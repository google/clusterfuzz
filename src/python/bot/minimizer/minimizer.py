# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Base classes for other minimizers."""

from metrics import logs
import copy
import functools
import os
import tempfile
import threading
import time

from . import errors

DEFAULT_CLEANUP_INTERVAL = 20
DEFAULT_THREAD_COUNT = 8
DEFAULT_TESTS_PER_THREAD = 4

MAX_MERGE_BATCH_SIZE = 32
PROGRESS_REPORT_INTERVAL = 300


class DummyLock(object):
  """Dummy to replace threading.Lock for single-threaded tests."""

  def __enter__(self):
    pass

  def __exit__(self, exec_type, value, traceback):
    pass

  def __bool__(self):
    return False


class TestQueue(object):
  """Queue to store commands that should be executed to test hypotheses."""

  def __init__(self,
               thread_count,
               deadline_check=None,
               progress_report_function=None,
               per_thread_cleanup_function=None):
    self.thread_count = thread_count
    self.deadline_check = deadline_check
    self.progress_report_function = progress_report_function
    self.per_thread_cleanup_function = per_thread_cleanup_function

    self.lock = threading.Lock()
    self.queue = []

  def _pop(self):
    """Pull a single hypothesis to process from the queue."""
    with self.lock:
      if not self.queue:
        return None
      return self.queue.pop(0)

  def _work(self):
    """Process items from the queue until it is empty."""
    while not self.deadline_check or not self.deadline_check(soft_check=True):
      current_item = self._pop()
      if not current_item:
        break

      test, test_function, completion_callback, should_run = current_item  # pylint: disable=unpacking-non-sequence
      if not should_run():
        continue

      result = test_function(test)
      completion_callback(result)

      if self.per_thread_cleanup_function:
        self.per_thread_cleanup_function()

      # Abort if we have exceeded the deadline for this operation.
      if self.deadline_check and self.deadline_check(soft_check=True):
        break

  def _cleanup(self):
    """Clean up the queue to be sure that no more tasks will be executed."""
    with self.lock:
      self.queue = []

  def push(self,
           test,
           test_function,
           completion_callback,
           should_run=lambda: True):
    """Add a test to the queue and a callback to run on completion."""
    with self.lock:
      self.queue.append((test, test_function, completion_callback, should_run))

  def force(self,
            test,
            test_function,
            completion_callback,
            should_run=lambda: True):
    """Force a test to the front of the queue."""
    entry = (test, test_function, completion_callback, should_run)
    with self.lock:
      self.queue.insert(0, entry)

  def size(self):
    """Return the number of unprocessed tasks in the queue."""
    return len(self.queue)

  def process(self):
    """Process all tests in the queue and block until completion."""
    while self.queue:
      threads = [
          threading.Thread(target=self._work) for _ in range(self.thread_count)
      ]
      for thread in threads:
        thread.start()

      while any([thread.is_alive() for thread in threads]):
        if self.deadline_check:
          self.deadline_check(cleanup_function=self._cleanup)

        if self.progress_report_function:
          self.progress_report_function()

        time.sleep(1)


class Testcase(object):
  """Single test case to be minimized."""

  def __init__(self, data, minimizer):
    self.minimizer = minimizer
    if minimizer.tokenize:
      try:
        self.tokens = minimizer.tokenizer(data)
      except UnicodeDecodeError:
        raise errors.AntlrDecodeError
    else:
      self.tokens = data

    self.required_tokens = [True] * len(self.tokens)
    self.tested_hypotheses = set()
    self.unmerged_failing_hypotheses = []
    self.tests_to_queue = []
    self.currently_processing = False
    self.last_progress_report_time = 0
    self.runs_since_last_cleanup = 0
    self.runs_executed = 0

    if minimizer.max_threads > 1:
      self.test_queue = TestQueue(
          minimizer.max_threads,
          deadline_check=self._deadline_exceeded,
          progress_report_function=self._report_progress)
      self.merge_preparation_lock = threading.Lock()
      self.merge_lock = threading.Lock()
      self.cache_lock = threading.Lock()
      self.tests_to_queue_lock = threading.Lock()
    else:
      self.test_queue = None
      self.merge_preparation_lock = DummyLock()
      self.merge_lock = DummyLock()
      self.cache_lock = DummyLock()
      self.tests_to_queue_lock = DummyLock()

  def get_current_testcase_data(self):
    """Return the current test case data."""
    return self.minimizer.token_combiner(self.get_required_tokens())

  # Helper functions based on minimizer configuration.
  def _deadline_exceeded(self, cleanup_function=None, soft_check=False):
    """Check to see if we have exceeded the deadline for execution."""
    if self.minimizer.deadline and time.time() > self.minimizer.deadline:
      if soft_check:
        return True

      # If we are here, we have exceeded the deadline on a hard check. Clean up.
      if cleanup_function:
        cleanup_function()

      if self.minimizer.cleanup_function:
        self.minimizer.cleanup_function()

      # Raise an exception if this is not a soft deadline check.
      raise errors.MinimizationDeadlineExceededError(self)

    return False

  def _delete_file_if_needed(self, input_file):
    """Deletes a temporary file if necessary."""
    # If we are not running in a mode where we need to delete files, do nothing.
    if not self.minimizer.tokenize or not self.minimizer.delete_temp_files:
      return

    try:
      os.remove(input_file)
    except OSError:
      pass

  def _report_progress(self, is_final_progress_report=False):
    """Call a function to report progress if the minimizer uses one."""
    if not self.minimizer.progress_report_function:
      return

    if (time.time() - self.last_progress_report_time < PROGRESS_REPORT_INTERVAL
        and not is_final_progress_report):
      return

    self.last_progress_report_time = time.time()
    message = '%d/%d tokens remaining. %d runs executed so far.' % (len(
        self.get_required_tokens()), len(
            self.required_tokens), self.runs_executed)
    if is_final_progress_report:
      message = "Done with this round of minimization. " + message
    self.minimizer.progress_report_function(message)

  # Functions used when preparing tests.
  def _range_complement(self, current_range):
    """Return required tokens in the complement of the specified range."""
    result = list(range(len(self.tokens)))
    to_remove = set(current_range)
    return [i for i in result if i not in to_remove and self.required_tokens[i]]

  def _prepare_test_input(self, tokens, tested_tokens):
    """Write the tokens currently being tested to a temporary file."""
    tested_tokens = set(tested_tokens)
    current_tokens = [t for i, t in enumerate(tokens) if i in tested_tokens]
    if not self.minimizer.tokenize:
      return current_tokens

    data = self.minimizer.token_combiner(current_tokens)

    handle = self.minimizer.get_temp_file()
    destination = handle.name
    try:
      handle.write(data)
    except IOError:
      # We may have filled the disk. Try processing tests and writing again.
      self._do_single_pass_process()
      handle.write(data)

    handle.close()
    return destination

  def _get_test_file(self, hypothesis):
    """Return a test file for a hypothesis."""
    complement = self._range_complement(hypothesis)
    return self._prepare_test_input(self.tokens, complement)

  def _push_test_to_queue(self, hypothesis):
    """Add a test for a hypothesis to a queue for processing."""
    test_file = self._get_test_file(hypothesis)
    callback = functools.partial(
        self._handle_completed_test,
        hypothesis=hypothesis,
        input_file=test_file)
    should_run = functools.partial(self._contains_required_tokens, hypothesis,
                                   test_file)

    self.test_queue.push(
        test_file,
        self.minimizer.test_function,
        callback,
        should_run=should_run)

    # Make sure that we do not let too many unprocessed tests build up.
    if self.test_queue.size() >= self.minimizer.batch_size:
      self._do_single_pass_process()

  def prepare_test(self, hypothesis):
    """Prepare the test based on the mode we are running in."""
    # Check the cache to make sure we have not tested this before.
    if self._has_tested(hypothesis):
      return

    self.runs_executed += 1
    # If we are single-threaded, just run and process results immediately.
    if not self.test_queue:
      # In the threaded case, we call the cleanup function before each pass
      # over the queue. It needs to be tracked here for the single-thread case.
      self.runs_since_last_cleanup += 1
      if (self.runs_since_last_cleanup >=
          self.minimizer.single_thread_cleanup_interval and
          self.minimizer.cleanup_function):
        self.minimizer.cleanup_function()

      test_file = self._get_test_file(hypothesis)
      if self._contains_required_tokens(hypothesis, test_file):
        self._handle_completed_test(
            self.minimizer.test_function(test_file), hypothesis, test_file)

      # Check to see if we have exceeded the deadline and report progress.
      self._report_progress()
      self._deadline_exceeded()
      return

    if self.currently_processing:
      # If we are processing, we cannot write more tests or add to the queue.
      with self.tests_to_queue_lock:
        self.tests_to_queue.append(hypothesis)
    else:
      self._push_test_to_queue(hypothesis)

  # Functions used when processing test results.
  def _handle_completed_test(self, test_passed, hypothesis, input_file):
    """Update state based on the test result and hypothesis."""
    # If the test failed, handle the result.
    if not test_passed:
      self._handle_failing_hypothesis(hypothesis)

    # Delete leftover files if necessary.
    self._delete_file_if_needed(input_file)

    # Minimizers may need to do something with the test result.
    self._process_test_result(test_passed, hypothesis)

  def _process_test_result(self, test_passed, hypothesis):
    """Additional processing of the result. Minimizers may override this."""

  def _handle_failing_hypothesis(self, hypothesis):
    """Update the token list for a failing hypothesis."""
    if not self.test_queue:
      # We aren't multithreaded, so just update the list directly.
      for token in hypothesis:
        self.required_tokens[token] = False
      return

    with self.merge_preparation_lock:
      self.unmerged_failing_hypotheses.append(hypothesis)
      if len(self.unmerged_failing_hypotheses) < MAX_MERGE_BATCH_SIZE:
        return

      hypotheses_to_merge = self.unmerged_failing_hypotheses
      self.unmerged_failing_hypotheses = []

    # We may need to block while the previous batch is merging. If not, the
    # results from this batch could conflict with the results from the previous.
    with self.merge_lock:
      self._attempt_merge(hypotheses_to_merge)

  def _attempt_merge(self, hypotheses):
    """Update the required token list if the queued changes don't conflict."""
    # If there's nothing to merge, we're done.
    if not hypotheses:
      return

    aggregate_tokens = set()
    for hypothesis in hypotheses:
      for token in hypothesis:
        aggregate_tokens.add(token)
    aggregate_hypothesis = list(aggregate_tokens)

    complement = self._range_complement(aggregate_hypothesis)
    test_file = self._prepare_test_input(self.tokens, complement)
    test_passed = self.minimizer.test_function(test_file)
    self._delete_file_if_needed(test_file)

    # Failed (crashed), so there was no conflict here.
    if not test_passed:
      for token in aggregate_hypothesis:
        self.required_tokens[token] = False
      return

    # Passed (no crash). We need to try a bit harder to resolve this conflict.
    if len(hypotheses) == 1:
      # We really cannot remove this token. No additional work to be done.
      return

    middle = len(hypotheses) // 2
    front = hypotheses[:middle]
    back = hypotheses[middle:]

    # This could potentially be optimized to assume that if one test fails the
    # other would pass, but because of flaky tests it's safer to run the test
    # unconditionally.
    self._attempt_merge(front)
    self._attempt_merge(back)

  def _do_single_pass_process(self):
    """Process through a single pass of our test queue."""
    self.currently_processing = True
    self.test_queue.process()

    # If a cleanup function is provided, call it. This is usually used to
    # ensure that all processes are terminated or perform additional cleanup.
    if self.minimizer.cleanup_function:
      self.minimizer.cleanup_function()

    # Push any results generated while this test was running to the queue.
    self.currently_processing = False
    while self.tests_to_queue:
      with self.tests_to_queue_lock:
        hypothesis = self.tests_to_queue.pop(0)

      # This may trigger another round of processing, so don't hold the lock.
      self._push_test_to_queue(hypothesis)

  def process(self):
    """Start a test."""
    if not self.test_queue:
      return

    while self.test_queue.size():
      self._do_single_pass_process()

    with self.merge_preparation_lock:
      hypotheses_to_merge = self.unmerged_failing_hypotheses
      self.unmerged_failing_hypotheses = []

    with self.merge_lock:
      self._attempt_merge(hypotheses_to_merge)

  # Cache functions.
  def _contains_required_tokens(self, hypothesis, test_file):
    """Check to see if this hypothesis contains untested tokens."""
    # It is possible that we could copy this while it is being updated. We do
    # not block in this case because the worst case scenario is that we run an
    # irrelevant test, and blocking is potentially expensive.
    working_required_tokens = copy.copy(self.required_tokens)
    with self.merge_preparation_lock:
      # A deep copy is not required. Hypotheses are not modified after being
      # added to the list for processing.
      unprocessed_hypotheses = copy.copy(self.unmerged_failing_hypotheses)

    for unprocessed_hypothesis in unprocessed_hypotheses:
      for token in unprocessed_hypothesis:
        # For this check, we do not care if the merge would succeed or not since
        # the best case is that we would add the token to the queue as well.
        working_required_tokens[token] = False

    for token in hypothesis:
      if working_required_tokens[token]:
        return True

    # If we aren't going to run this test, this will not have a completion
    # callback. If that happens, we need to clean up now.
    self._delete_file_if_needed(test_file)
    return False

  def _has_tested(self, hypothesis):
    """Check to see if this hypothesis has been tested before."""
    hypothesis_tuple = tuple(hypothesis)
    with self.cache_lock:
      if hypothesis_tuple in self.tested_hypotheses:
        return True

      self.tested_hypotheses.add(hypothesis_tuple)

    return False

  # Result checking functions.
  def get_result(self):
    """Get the result of minimization."""
    # Done with minimization, output log one more time
    self._report_progress(is_final_progress_report=True)

    if not self.minimizer.tokenize:
      return self.get_required_tokens()
    return self.get_current_testcase_data()

  def get_required_tokens(self):
    """Return all required tokens for this test case."""
    return [t for i, t in enumerate(self.tokens) if self.required_tokens[i]]

  def get_required_token_indices(self):
    """Get the indices of all remaining required tokens."""
    return [i for i, v in enumerate(self.required_tokens) if v]


def _default_tokenizer(s):
  """Default string tokenizer which splits on newlines."""
  return s.split(b'\n')


def _default_combiner(tokens):
  """Default token combiner which assumes each token is a line."""
  return b'\n'.join(tokens)


class Minimizer(object):
  """Base class for minimizers."""

  def __init__(self,
               test_function,
               max_threads=1,
               tokenizer=_default_tokenizer,
               token_combiner=_default_combiner,
               tokenize=True,
               cleanup_function=None,
               single_thread_cleanup_interval=DEFAULT_CLEANUP_INTERVAL,
               deadline=None,
               get_temp_file=None,
               delete_temp_files=True,
               batch_size=None,
               progress_report_function=None,
               file_extension=''):
    """Initialize a minimizer. A minimizer object can be used multiple times."""
    self.test_function = test_function
    self.max_threads = max_threads
    self.tokenizer = tokenizer
    self.token_combiner = token_combiner
    self.tokenize = tokenize
    self.cleanup_function = cleanup_function
    self.single_thread_cleanup_interval = single_thread_cleanup_interval
    self.deadline = deadline
    self.get_temp_file = get_temp_file
    self.delete_temp_files = delete_temp_files
    self.progress_report_function = progress_report_function

    if batch_size:
      self.batch_size = batch_size
    else:
      self.batch_size = DEFAULT_TESTS_PER_THREAD * max_threads

    if not get_temp_file:
      self.get_temp_file = functools.partial(
          tempfile.NamedTemporaryFile,
          mode='wb',
          delete=False,
          prefix='min_',
          suffix=file_extension)
    else:
      self.get_temp_file = get_temp_file

  @staticmethod
  def _handle_constructor_argument(key, kwargs, default=None):
    """Cleanup a keyword argument specific to a subclass and get the value."""
    result = default
    try:
      result = kwargs[key]
      del kwargs[key]
    except KeyError:
      pass

    return result

  def _execute(self, data):
    """Perform minimization on a test case."""
    raise NotImplementedError

  def minimize(self, data):
    """Wrapper to perform common tasks and call |_execute|."""
    try:
      testcase = self._execute(data)
    except errors.MinimizationDeadlineExceededError as error:
      # When a MinimizationDeadlineExceededError is raised, the partially
      # minimized test case is stored with it so that we can recover the work
      # that had been done up to that point.
      testcase = error.testcase
    except errors.TokenizationFailureError:
      logs.log('Tokenized data did not match original data. Defaulting to line'
               'minimization.')
      # In situation where the tokenizer does not work, we still want to use
      # the token combiner. This will not change the data unless
      # token combiner changes the data such as appending extra data to the
      # start or end. If this is the case, that change will be expected
      # in the return.
      return self.token_combiner([data])

    return testcase.get_result()

  def validate_tokenizer(self, data, testcase):
    """Validate that the tokenizer correctly tokenized the data. This is
    necessary because if the tokenizer does not recognize a character, it will
    skip it."""
    # If data is a list, it means we're not minimizing a test case but another
    # feature such as files or command line arguments. In these cases, we don't
    # rely on a tokenizer.
    if isinstance(data, list):
      return True

    # For most token_combiners, using the combiner on data like below will do
    # nothing, but in situations where data is changed in the token combiner
    # such as data being appended to the start or end of data we want to make
    # sure the same change happens to both before comparison.
    data = self.token_combiner([data])
    return testcase.get_current_testcase_data() == data

  @staticmethod
  def run(data, thread_count=DEFAULT_THREAD_COUNT, file_extension=''):
    """Minimize |data| using this minimizer's default configuration."""
    raise NotImplementedError

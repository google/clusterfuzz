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
"""Fuzz task for handling fuzzing."""

import collections
import datetime
import itertools
import os
import random
import re
import sys
import time

from base import dates
from base import retry
from base import utils
from bot.fuzzers import builtin_fuzzers
from bot.fuzzers.libFuzzer import stats as libfuzzer_stats
from bot.tasks import setup
from bot.tasks import task_creation
from bot.tasks import trials
from build_management import build_manager
from chrome import crash_uploader
from crash_analysis import crash_analyzer
from crash_analysis.stack_parsing import stack_analyzer
from datastore import data_handler
from datastore import data_types
from datastore import ndb
from fuzzing import corpus_manager
from fuzzing import coverage_uploader
from fuzzing import gesture_handler
from fuzzing import leak_blacklist
from fuzzing import tests
from google_cloud_utils import big_query
from google_cloud_utils import blobs
from google_cloud_utils import storage
from metrics import fuzzer_logs
from metrics import fuzzer_stats
from metrics import logs
from metrics import monitoring_metrics
from platforms import android
from system import environment
from system import process_handler
from system import shell

FUZZ_TARGET_UPDATE_FAIL_RETRIES = 5
FUZZ_TARGET_UPDATE_FAIL_DELAY = 2
DEFAULT_CHOOSE_PROBABILITY = 9  # 10%
FUZZER_METADATA_REGEX = re.compile(r'metadata::(\w+):\s*(.*)')
FUZZER_FAILURE_THRESHOLD = 0.33
MAX_GESTURES = 30
MAX_NEW_CORPUS_FILES = 500


class FuzzTaskException(Exception):
  """Fuzz task exception."""


class FuzzErrorCode(object):
  FUZZER_TIMEOUT = -1
  FUZZER_SETUP_FAILED = -2
  FUZZER_EXECUTION_FAILED = -3
  DATA_BUNDLE_SETUP_FAILED = -4
  BUILD_SETUP_FAILED = -5


Context = collections.namedtuple('Context', [
    'project_name', 'bot_name', 'job_type', 'fuzz_target', 'redzone',
    'platform_id', 'crash_revision', 'fuzzer_name', 'window_argument',
    'fuzzer_metadata', 'testcases_metadata', 'timeout_multiplier',
    'test_timeout', 'thread_wait_timeout', 'data_directory'
])
Redzone = collections.namedtuple('Redzone', ['size', 'weight'])


def get_unsymbolized_crash_stacktrace(stack_file_path):
  try:
    with open(stack_file_path, 'rb') as f:
      return (utils.decode_to_unicode(f.read()), None)
  except:
    logs.log_error('Unable to read stacktrace from file %s.' % stack_file_path)
    return (None, sys.exc_info()[1])


class Crash(object):
  """Represents a crash (before creating a testcase)."""

  def __init__(self, crash):
    """Initialize

    Args:
      crash: An instance of fuzzing.tests.Crash.
    """
    self.file_path = crash.file_path
    self.crash_time = crash.crash_time
    self.return_code = crash.return_code
    self.resource_list = crash.resource_list
    self.gestures = crash.gestures
    self.stack_file_path = crash.stack_file_path

    self.error = None
    self.security_flag = False
    self.should_be_ignored = False

    orig_unsymbolized_crash_stacktrace, self.error = (
        get_unsymbolized_crash_stacktrace(self.stack_file_path))

    if self.error:
      return

    self.filename = os.path.basename(self.file_path)
    self.http_flag = '-http-' in self.filename
    self.application_command_line = tests.get_command_line_for_application(
        self.file_path, needs_http=self.http_flag)
    self.unsymbolized_crash_stacktrace = orig_unsymbolized_crash_stacktrace
    state = stack_analyzer.get_crash_data(self.unsymbolized_crash_stacktrace)
    self.crash_type = state.crash_type
    self.crash_address = state.crash_address
    self.crash_state = state.crash_state
    self.crash_stacktrace = utils.get_crash_stacktrace_output(
        self.application_command_line, state.crash_stacktrace,
        self.unsymbolized_crash_stacktrace)
    self.security_flag = crash_analyzer.is_security_issue(
        self.unsymbolized_crash_stacktrace, self.crash_type, self.crash_address)
    self.key = '%s,%s,%s' % (self.crash_type, self.crash_state,
                             self.security_flag)
    self.should_be_ignored = crash_analyzer.ignore_stacktrace(
        self.crash_state, self.crash_stacktrace)

    # self.crash_info gets populated in create_testcase; save what we need.
    self.crash_frames = state.frames
    self.crash_info = None

  def is_archived(self):
    """Return true if archive_testcase_in_blobstore(..) was
      performed."""
    return hasattr(self, 'fuzzed_key')

  def archive_testcase_in_blobstore(self):
    """Calling setup.archive_testcase_and_dependencies_in_gcs(..)
      and hydrate certain attributes. We single out this method because it's
      expensive and we want to do it at the very last minute."""
    if self.is_archived():
      return

    (self.fuzzed_key, self.archived, self.absolute_path,
     self.archive_filename) = (
         setup.archive_testcase_and_dependencies_in_gcs(self.resource_list,
                                                        self.file_path))

  def is_valid(self):
    """Return true if the crash is valid for processing."""
    return self.get_error() is None

  def get_error(self):
    """Return the reason why the crash is invalid."""
    if self.error:
      return 'Unable to read the stack file: %s' % self.error

    filter_functional_bugs = environment.get_value('FILTER_FUNCTIONAL_BUGS')
    if filter_functional_bugs and not self.security_flag:
      return 'Functional crash is ignored: %s' % self.crash_state

    if self.should_be_ignored:
      return ('False crash: %s\n\n---%s\n\n---%s' %
              (self.crash_state, self.unsymbolized_crash_stacktrace,
               self.crash_stacktrace))

    if self.is_archived() and not self.fuzzed_key:
      return 'Unable to store testcase in blobstore: %s' % self.crash_state

    return None


def find_main_crash(crashes, test_timeout):
  """Find the first reproducible crash or the first valid crash.
    And return the crash and the one_time_crasher_flag."""
  for crash in crashes:
    # Archiving testcase to blobstore when we need to because it's expensive.
    crash.archive_testcase_in_blobstore()

    # We need to check again if the crash is valid. In other words, we check
    # if archiving to blobstore succeeded.
    if not crash.is_valid():
      continue

    # We pass an empty expected crash state since our initial stack from fuzzing
    # can be incomplete. So, make a judgement on reproducibility based on passed
    # security flag and crash state generated from re-running testcase in
    # test_for_reproducibility. Minimize task will later update the new crash
    # type and crash state paramaters.
    if tests.test_for_reproducibility(crash.file_path, None,
                                      crash.security_flag, test_timeout,
                                      crash.http_flag, crash.gestures):
      return crash, False

  # All crashes are non-reproducible. Therefore, we get the first valid one.
  for crash in crashes:
    if crash.is_valid():
      return crash, True

  return None, None


class CrashGroup(object):
  """Represent a group of identical crashes. The key is
      (crash_type, crash_state, security_flag)."""

  def __init__(self, crashes, context):
    for c in crashes:
      assert crashes[0].crash_type == c.crash_type
      assert crashes[0].crash_state == c.crash_state
      assert crashes[0].security_flag == c.security_flag

    self.crashes = crashes
    self.main_crash, self.one_time_crasher_flag = find_main_crash(
        crashes, context.test_timeout)

    self.newly_created_testcase = None

    # Getting existing_testcase after finding the main crash is important.
    # Because finding the main crash can take a long time; it tests
    # reproducibility on every crash.
    #
    # Getting existing testcase at the last possible moment helps avoid race
    # condition among different machines. One machine might finish first and
    # prevent other machines from creating identical testcases.
    self.existing_testcase = data_handler.find_testcase(
        context.project_name, crashes[0].crash_type, crashes[0].crash_state,
        crashes[0].security_flag)

  def is_new(self):
    """Return true if there's no existing testcase."""
    return not self.existing_testcase

  def should_create_testcase(self):
    """Return true if this crash should create a testcase."""
    if not self.existing_testcase:
      # No existing testcase, should create a new one.
      return True

    if not self.existing_testcase.one_time_crasher_flag:
      # Existing testcase is reproducible, don't need to create another one.
      return False

    if not self.one_time_crasher_flag:
      # Current testcase is reproducible, where existing one is not. Should
      # create a new one.
      return True

    # Both current and existing testcases are unreproducible, shouldn't create
    # a new testcase.
    # TODO(aarya): We should probably update last tested stacktrace in existing
    # testcase without any race conditions.
    return False

  def has_existing_reproducible_testcase(self):
    """Return true if this crash has a reproducible testcase."""
    return (self.existing_testcase and
            not self.existing_testcase.one_time_crasher_flag)


class _TrackFuzzTime(object):
  """Track the actual fuzzing time (e.g. excluding preparing binary)."""

  def __init__(self, fuzzer_name, job_type, time_module=time):
    self.fuzzer_name = fuzzer_name
    self.job_type = job_type
    self.time = time_module

  def __enter__(self):
    self.start_time = self.time.time()
    self.timeout = False
    return self

  def __exit__(self, exc_type, value, traceback):
    duration = self.time.time() - self.start_time
    monitoring_metrics.FUZZER_FUZZ_TIME.add(duration, {
        'fuzzer': self.fuzzer_name,
        'timeout': self.timeout
    })
    monitoring_metrics.JOB_FUZZ_TIME.add(duration, {
        'job': self.job_type,
        'timeout': self.timeout
    })
    monitoring_metrics.FUZZER_TOTAL_FUZZ_TIME.increment_by(
        int(duration), {
            'fuzzer': self.fuzzer_name,
            'timeout': self.timeout
        })
    monitoring_metrics.JOB_TOTAL_FUZZ_TIME.increment_by(
        int(duration), {
            'job': self.job_type,
            'timeout': self.timeout
        })


def _track_fuzzer_run_result(fuzzer_name, generated_testcase_count,
                             expected_testcase_count, return_code):
  """Track fuzzer run result"""
  if expected_testcase_count > 0:
    ratio = float(generated_testcase_count) / expected_testcase_count
    monitoring_metrics.FUZZER_TESTCASE_COUNT_RATIO.add(ratio,
                                                       {'fuzzer': fuzzer_name})

  def clamp(val, minimum, maximum):
    return max(minimum, min(maximum, val))

  # Clamp return code to max, min int 32-bit, otherwise it can get detected as
  # type long and we will exception out in infra_libs parsing pipeline.
  min_int32 = -(2**31)
  max_int32 = 2**31 - 1

  return_code = int(clamp(return_code, min_int32, max_int32))

  monitoring_metrics.FUZZER_RETURN_CODE_COUNT.increment({
      'fuzzer': fuzzer_name,
      'return_code': return_code,
  })


def _track_build_run_result(job_type, _, is_bad_build):
  """Track build run result."""
  # FIXME: Add support for |crash_revision| as part of state.
  monitoring_metrics.JOB_BAD_BUILD_COUNT.increment({
      'job': job_type,
      'bad_build': is_bad_build
  })


def _track_testcase_run_result(fuzzer, job_type, new_crash_count,
                               known_crash_count):
  """Track testcase run result."""
  monitoring_metrics.FUZZER_KNOWN_CRASH_COUNT.increment_by(
      known_crash_count, {
          'fuzzer': fuzzer,
      })
  monitoring_metrics.FUZZER_NEW_CRASH_COUNT.increment_by(
      new_crash_count, {
          'fuzzer': fuzzer,
      })
  monitoring_metrics.JOB_KNOWN_CRASH_COUNT.increment_by(known_crash_count, {
      'job': job_type,
  })
  monitoring_metrics.JOB_NEW_CRASH_COUNT.increment_by(new_crash_count, {
      'job': job_type,
  })


class GcsCorpus(object):
  """Sync state for a corpus."""

  def __init__(self, engine, project_qualified_target_name, corpus_directory,
               data_directory):
    if environment.is_trusted_host():
      from bot.untrusted_runner import corpus_manager as remote_corpus_manager
      self.gcs_corpus = remote_corpus_manager.RemoteFuzzTargetCorpus(
          engine, project_qualified_target_name)
    else:
      self.gcs_corpus = corpus_manager.FuzzTargetCorpus(
          engine, project_qualified_target_name, log_results=False)

    self._corpus_directory = corpus_directory
    self._data_directory = data_directory
    self._project_qualified_target_name = project_qualified_target_name
    self._synced_files = set()

  def _walk(self):
    if environment.is_trusted_host():
      from bot.untrusted_runner import file_host
      for file_path in file_host.list_files(
          self._corpus_directory, recursive=True):
        yield file_path
    else:
      for root, _, files in os.walk(self._corpus_directory):
        for filename in files:
          yield os.path.join(root, filename)

  def sync_from_gcs(self):
    """Update sync state after a sync from GCS."""
    already_synced = False
    last_sync_time = None
    sync_file_path = os.path.join(
        self._data_directory, '.%s_sync' % self._project_qualified_target_name)

    # Get last time we synced corpus.
    if environment.is_trusted_host():
      from bot.untrusted_runner import file_host
      worker_sync_file_path = file_host.rebase_to_worker_root(sync_file_path)
      shell.remove_file(sync_file_path)
      file_host.copy_file_from_worker(worker_sync_file_path, sync_file_path)
    if os.path.exists(sync_file_path):
      last_sync_time = datetime.datetime.utcfromtimestamp(
          utils.read_data_from_file(sync_file_path))

    # Check if the corpus was recently synced. If yes, set a flag so that we
    # don't sync it again and save some time.
    if last_sync_time:
      last_update_time = storage.last_updated(self.gcs_corpus.get_gcs_url())
      if last_update_time and last_sync_time > last_update_time:
        logs.log('Corpus for target %s has no new updates, skipping rsync.' %
                 self._project_qualified_target_name)
        already_synced = True

    time_before_sync_start = time.time()
    result = already_synced or self.gcs_corpus.rsync_to_disk(
        self._corpus_directory)
    self._synced_files.clear()
    self._synced_files.update(self._walk())

    logs.log('%d corpus files for target %s synced to disk.' % (len(
        self._synced_files), self._project_qualified_target_name))

    # On success of rsync, update the last sync file with current timestamp.
    if result and self._synced_files and not already_synced:
      utils.write_data_to_file(time_before_sync_start, sync_file_path)

      if environment.is_trusted_host():
        from bot.untrusted_runner import file_host
        worker_sync_file_path = file_host.rebase_to_worker_root(sync_file_path)
        file_host.copy_file_to_worker(sync_file_path, worker_sync_file_path)

    return result

  def upload_files(self, new_files):
    """Update state after files are uploaded."""
    result = self.gcs_corpus.upload_files(new_files)
    self._synced_files.update(new_files)

    return result

  def get_new_files(self):
    """Return list of new files in the directory that were generated by the
    fuzzer."""
    new_files = []
    for file_path in self._walk():
      if file_path not in self._synced_files:
        new_files.append(file_path)

    return new_files


def upload_testcase_run_stats(fuzzer_name, fully_qualified_fuzzer_name,
                              job_type, revision, testcase_file_paths):
  """Upload per-testcase stats."""
  if fuzzer_name not in builtin_fuzzers.BUILTIN_FUZZERS:
    # Testcase run stats are only applicable to builtin fuzzers (libFuzzer,AFL).
    return

  testcase_runs = []
  for testcase_file_path in testcase_file_paths:
    testcase_run = fuzzer_stats.TestcaseRun.read_from_disk(
        testcase_file_path, delete=True)
    if testcase_run:
      testcase_run['fuzzer'] = fully_qualified_fuzzer_name
      testcase_run['job'] = job_type
      testcase_run['build_revision'] = revision
      testcase_runs.append(testcase_run)

  fuzzer_stats.upload_stats(testcase_runs)


def get_fuzzer_metadata_from_output(fuzzer_output):
  """Extract metadata from fuzzer output."""
  metadata = {}
  for line in fuzzer_output.splitlines():
    match = FUZZER_METADATA_REGEX.match(line)
    if match:
      metadata[match.group(1)] = match.group(2)

  return metadata


def get_testcase_directories(testcase_directory, data_directory):
  """Return the list of directories containing fuzz testcases."""
  testcase_directories = [testcase_directory]

  # Cloud storage data bundle directory is on NFS. It is a slow file system
  # and browsing through hundreds of files can overload the server if every
  # bot starts doing that. Since, we don't create testcases there anyway, skip
  # adding the directory to the browse list.
  if not setup.is_directory_on_nfs(data_directory):
    testcase_directories.append(data_directory)

  return testcase_directories


def get_testcases(testcase_count, testcase_directory, data_directory):
  """Return fuzzed testcases from the data directories."""
  logs.log('Locating generated test cases.')

  # Get the list of testcase files.
  testcase_directories = get_testcase_directories(testcase_directory,
                                                  data_directory)
  testcase_file_paths = tests.get_testcases_from_directories(
      testcase_directories)

  # If the fuzzer created a bot-specific files list, add those now.
  bot_testcases_file_path = utils.get_bot_testcases_file_path(data_directory)
  if os.path.exists(bot_testcases_file_path):
    bot_testcases_file_content = utils.read_data_from_file(
        bot_testcases_file_path, eval_data=False)
    shell.remove_file(bot_testcases_file_path)
    if bot_testcases_file_content:
      bot_file_paths = bot_testcases_file_content.splitlines()
      testcase_file_paths += [
          utils.normalize_path(path) for path in bot_file_paths
      ]

  generated_testcase_count = len(testcase_file_paths)

  # Create output strings.
  generated_testcase_string = (
      'Generated %d/%d testcases.' % (generated_testcase_count, testcase_count))

  # Log the number of testcases generated.
  logs.log(generated_testcase_string)

  # If we are running the same command (again and again) on this bot,
  # we want to be careful of scenarios when the fuzzer starts failing
  # or has nothing to do, causing no testcases to be generated. This
  # will put lot of burden on appengine remote api.
  if (environment.get_value('COMMAND_OVERRIDE') and
      generated_testcase_count == 0):
    logs.log('No testcases generated. Sleeping for ~30 minutes.')
    time.sleep(random.uniform(1800, 2100))

  return (testcase_file_paths, generated_testcase_count,
          generated_testcase_string)


def pick_gestures(test_timeout):
  """Return a list of random gestures."""
  if not environment.get_value('ENABLE_GESTURES', True):
    # Gestures disabled.
    return []

  # Probability of choosing gestures.
  if utils.random_number(0, DEFAULT_CHOOSE_PROBABILITY):
    return []

  gesture_count = utils.random_number(1, MAX_GESTURES)
  gestures = gesture_handler.get_gestures(gesture_count)
  if not gestures:
    return []

  # Pick a random trigger time to run the gesture at.
  min_gesture_time = int(
      utils.random_element_from_list([0.25, 0.50, 0.50, 0.50]) * test_timeout)
  max_gesture_time = test_timeout - 1
  gesture_time = utils.random_number(min_gesture_time, max_gesture_time)

  gestures.append('Trigger:%d' % gesture_time)
  return gestures


def pick_redzone():
  """Return a random size for redzone."""
  thread_multiplier = environment.get_value('THREAD_MULTIPLIER', 1)

  if thread_multiplier == 1:
    redzone_list = [
        Redzone(16, 1.0),
        Redzone(32, 1.0),
        Redzone(64, 0.5),
        Redzone(128, 0.5),
        Redzone(256, 0.25),
        Redzone(512, 0.25),
    ]
  else:
    # For beefier boxes, prioritize using bigger redzones.
    redzone_list = [
        Redzone(16, 0.25),
        Redzone(32, 0.25),
        Redzone(64, 0.50),
        Redzone(128, 0.50),
        Redzone(256, 1.0),
        Redzone(512, 1.0),
    ]

  return utils.random_weighted_choice(redzone_list).size


def pick_timeout_multiplier():
  """Return a random testcase timeout multiplier and adjust timeout."""
  fuzz_test_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')
  custom_timeout_multipliers = environment.get_value(
      'CUSTOM_TIMEOUT_MULTIPLIERS')
  timeout_multiplier = 1.0

  use_multiplier = not utils.random_number(0, DEFAULT_CHOOSE_PROBABILITY)
  if (use_multiplier and not fuzz_test_timeout and
      not custom_timeout_multipliers):
    timeout_multiplier = utils.random_element_from_list([0.5, 1.5, 2.0, 3.0])
  elif use_multiplier and custom_timeout_multipliers:
    # Since they are explicitly set in the job definition, it is fine to use
    # custom timeout multipliers even in the case where FUZZ_TEST_TIMEOUT is
    # set.
    timeout_multiplier = utils.random_element_from_list(
        custom_timeout_multipliers)

  environment.set_value('TIMEOUT_MULTIPLIER', timeout_multiplier)
  return timeout_multiplier


def set_test_timeout(timeout, multipler):
  """Set the test timeout based on a timeout value and multiplier."""
  test_timeout = int(timeout * multipler)
  environment.set_value('TEST_TIMEOUT', test_timeout)
  return test_timeout


def pick_window_argument():
  """Return a window argument with random size and x,y position."""
  default_window_argument = environment.get_value('WINDOW_ARG', '')
  window_argument_change_chance = not utils.random_number(
      0, DEFAULT_CHOOSE_PROBABILITY)

  window_argument = ''
  if window_argument_change_chance:
    window_argument = default_window_argument
    if window_argument:
      width = utils.random_number(
          100, utils.random_element_from_list([256, 1280, 2048]))
      height = utils.random_number(
          100, utils.random_element_from_list([256, 1024, 1536]))
      left = utils.random_number(0, width)
      top = utils.random_number(0, height)

      window_argument = window_argument.replace('$WIDTH', str(width))
      window_argument = window_argument.replace('$HEIGHT', str(height))
      window_argument = window_argument.replace('$LEFT', str(left))
      window_argument = window_argument.replace('$TOP', str(top))

  # FIXME: Random seed is currently passed along to the next job
  # via WINDOW_ARG. Rename it without breaking existing tests.
  random_seed_argument = environment.get_value('RANDOM_SEED')
  if random_seed_argument:
    if window_argument:
      window_argument += ' '
    seed = utils.random_number(-2147483648, 2147483647)
    window_argument += '%s=%d' % (random_seed_argument.strip(), seed)

  environment.set_value('WINDOW_ARG', window_argument)
  return window_argument


@retry.wrap(
    retries=FUZZ_TARGET_UPDATE_FAIL_RETRIES,
    delay=FUZZ_TARGET_UPDATE_FAIL_DELAY,
    function='tasks.fuzz_task.record_fuzz_target')
def record_fuzz_target(engine, binary_name, job_type):
  """Record existence of fuzz target."""
  if not binary_name:
    logs.log_error('Expected binary_name.')
    return None

  project = data_handler.get_project_name(job_type)
  key_name = data_types.fuzz_target_fully_qualified_name(
      engine, project, binary_name)

  fuzz_target = ndb.Key(data_types.FuzzTarget, key_name).get()
  if not fuzz_target:
    fuzz_target = data_types.FuzzTarget(
        engine=engine, project=project, binary=binary_name)
    fuzz_target.put()

  job_mapping_key = data_types.fuzz_target_job_key(key_name, job_type)
  job_mapping = ndb.Key(data_types.FuzzTargetJob, job_mapping_key).get()
  if job_mapping:
    job_mapping.last_run = utils.utcnow()
  else:
    job_mapping = data_types.FuzzTargetJob(
        fuzz_target_name=key_name,
        job=job_type,
        engine=engine,
        last_run=utils.utcnow())
  job_mapping.put()

  logs.log(
      'Recorded use of fuzz target %s.' % key_name,
      project=project,
      engine=engine,
      binary_name=binary_name,
      job_type=job_type)
  return fuzz_target


def truncate_fuzzer_output(output, limit):
  """Truncate output in the middle according to limit."""
  if len(output) < limit:
    return output

  separator = '\n...truncated...\n'
  reduced_limit = limit - len(separator)
  left = reduced_limit / 2 + reduced_limit % 2
  right = reduced_limit / 2

  assert reduced_limit > 0

  return ''.join([output[:left], separator, output[-right:]])


def run_fuzzer(fuzzer, fuzzer_directory, testcase_directory, data_directory,
               testcase_count):
  """Run the fuzzer and generate testcases."""
  # Helper variables.
  error_occurred = False
  fuzzer_revision = fuzzer.revision
  fuzzer_name = fuzzer.name
  sync_corpus_directory = None

  # Clear existing testcases (only if past task failed).
  testcase_directories = get_testcase_directories(testcase_directory,
                                                  data_directory)
  tests.remove_testcases_from_directories(testcase_directories)

  # Set an environment variable for fuzzer name.
  environment.set_value('FUZZER_NAME', fuzzer_name)

  # Set minimum redzone size, do not detect leaks and zero out the
  # quarantine size before running the fuzzer.
  environment.reset_current_memory_tool_options(
      redzone_size=16, leaks=False, quarantine_size_mb=0)

  if fuzzer.builtin:
    fuzzer_command = 'builtin'
    builtin_fuzzer = builtin_fuzzers.get(fuzzer.name)

    builtin_result = builtin_fuzzer.run(data_directory, testcase_directory,
                                        testcase_count)

    fuzzer_output = builtin_result.output
    sync_corpus_directory = builtin_result.corpus_directory

    fuzzer_return_code = 0
  else:
    # Make sure we have a file to execute for the fuzzer.
    if not fuzzer.executable_path:
      logs.log_error(
          'Fuzzer %s does not have an executable path.' % fuzzer_name)
      error_occurred = True
      return error_occurred, None, None, None, None

    # Get the fuzzer executable and chdir to its base directory. This helps to
    # prevent referencing every file using __file__.
    fuzzer_executable = os.path.join(fuzzer_directory, fuzzer.executable_path)
    fuzzer_executable_directory = os.path.dirname(fuzzer_executable)

    # Make sure the fuzzer executable exists on disk.
    if not os.path.exists(fuzzer_executable):
      logs.log_error(
          'File %s does not exist. Cannot generate testcases for fuzzer %s.' %
          (fuzzer_executable, fuzzer_name))
      error_occurred = True
      return error_occurred, None, None, None, None

    # Build the fuzzer command execution string.
    command = shell.get_interpreter_for_command(fuzzer.executable_path)
    command += ' '
    command += fuzzer_executable.replace('.class', '')

    # NodeJS and shell script expect space seperator for arguments.
    if command.startswith('node ') or command.startswith('sh '):
      argument_seperator = ' '
    else:
      argument_seperator = '='

    command_format = ('%s --input_dir%s%s --output_dir%s%s --no_of_files%s%d')
    fuzzer_command = str(
        command_format % (command, argument_seperator, data_directory,
                          argument_seperator, testcase_directory,
                          argument_seperator, testcase_count))
    fuzzer_timeout = environment.get_value('FUZZER_TIMEOUT')

    # Run the fuzzer.
    logs.log('Running fuzzer - %s.' % fuzzer_command)
    fuzzer_return_code, fuzzer_duration, fuzzer_output = (
        process_handler.run_process(
            fuzzer_command,
            current_working_directory=fuzzer_executable_directory,
            timeout=fuzzer_timeout,
            testcase_run=False,
            ignore_children=False))

    # Use the custom return code for timeouts if needed.
    if fuzzer_return_code is None:
      fuzzer_return_code = FuzzErrorCode.FUZZER_TIMEOUT

    # Use the custom return code for execution failures if needed.
    if fuzzer_duration is None:
      fuzzer_return_code = FuzzErrorCode.FUZZER_EXECUTION_FAILED

  # Force GC to save some memory before processing fuzzer output.
  utils.python_gc()

  # For Android, we need to sync our local testcases directory with the one on
  # the device.
  if environment.platform() == 'ANDROID':
    android.device.push_testcases_to_device()

  if environment.is_trusted_host():
    from bot.untrusted_runner import file_host
    file_host.push_testcases_to_worker()

  fuzzer_metadata = get_fuzzer_metadata_from_output(fuzzer_output)

  # Filter fuzzer output, set to default value if empty.
  if fuzzer_output:
    fuzzer_output = utils.decode_to_unicode(fuzzer_output)
  else:
    fuzzer_output = u'No output!'

  # Get the list of generated testcases.
  testcase_file_paths, generated_testcase_count, generated_testcase_string = (
      get_testcases(testcase_count, testcase_directory, data_directory))

  # Check for process return code to identify abnormal termination.
  if fuzzer_return_code:
    if float(
        generated_testcase_count) / testcase_count < FUZZER_FAILURE_THRESHOLD:
      logs.log_error(
          'Fuzzer %s returned %d. Testcase generation failed.' %
          (fuzzer_name, fuzzer_return_code),
          output=fuzzer_output)
    else:
      logs.log_warn(
          'Fuzzer %s returned %d. Less than expected testcases generated.' %
          (fuzzer_name, fuzzer_return_code),
          output=fuzzer_output)

  # Store fuzzer run results.
  store_fuzzer_run_results(testcase_file_paths, fuzzer, fuzzer_command,
                           fuzzer_output, fuzzer_return_code, fuzzer_revision,
                           generated_testcase_count, testcase_count,
                           generated_testcase_string)

  # Upload blackbox fuzzer test cases to GCS on a small number of runs.
  coverage_uploader.upload_testcases_if_needed(fuzzer.name, testcase_file_paths,
                                               testcase_directory)

  # Make sure that there are testcases generated. If not, set the error flag.
  error_occurred = not testcase_file_paths

  _track_fuzzer_run_result(fuzzer_name, generated_testcase_count,
                           testcase_count, fuzzer_return_code)

  return (error_occurred, testcase_file_paths, generated_testcase_count,
          sync_corpus_directory, fuzzer_metadata)


def convert_groups_to_crashes(groups):
  """Convert groups to crashes (in an array of dicts) for JobRun."""
  crashes = []
  for group in groups:
    crashes.append({
        'is_new': group.is_new(),
        'count': len(group.crashes),
        'crash_type': group.main_crash.crash_type,
        'crash_state': group.main_crash.crash_state,
        'security_flag': group.main_crash.security_flag,
    })
  return crashes


def upload_job_run_stats(fuzzer_name, job_type, revision, timestamp,
                         new_crash_count, known_crash_count, testcases_executed,
                         groups):
  """Upload job run stats."""
  # New format.
  job_run = fuzzer_stats.JobRun(fuzzer_name, job_type, revision, timestamp,
                                testcases_executed, new_crash_count,
                                known_crash_count,
                                convert_groups_to_crashes(groups))
  fuzzer_stats.upload_stats([job_run])

  _track_testcase_run_result(fuzzer_name, job_type, new_crash_count,
                             known_crash_count)


def store_fuzzer_run_results(testcase_file_paths, fuzzer, fuzzer_command,
                             fuzzer_output, fuzzer_return_code, fuzzer_revision,
                             generated_testcase_count, expected_testcase_count,
                             generated_testcase_string):
  """Store fuzzer run results in database."""
  # Upload fuzzer script output to bucket.
  fuzzer_logs.upload_script_log(fuzzer_output)

  # Save the test results for the following cases.
  # 1. There is no result yet.
  # 2. There is no timestamp associated with the result.
  # 3. Last update timestamp is more than a day old.
  # 4. Return code is non-zero and was not found before.
  # 5. Testcases generated were fewer than expected in this run and zero return
  #    code did occur before and zero generated testcases didn't occur before.
  save_test_results = (
      not fuzzer.result or not fuzzer.result_timestamp or
      dates.time_has_expired(fuzzer.result_timestamp, days=1) or
      (fuzzer_return_code != 0 and fuzzer_return_code != fuzzer.return_code) or
      (generated_testcase_count != expected_testcase_count and
       fuzzer.return_code == 0 and ' 0/' not in fuzzer.result))
  if not save_test_results:
    return

  logs.log('Started storing results from fuzzer run.')

  # Store the sample testcase in blobstore first. This can take some time, so
  # do this operation before refreshing fuzzer object.
  sample_testcase = None
  if testcase_file_paths:
    with open(testcase_file_paths[0], 'rb') as sample_testcase_file_handle:
      sample_testcase = blobs.write_blob(sample_testcase_file_handle)

    if not sample_testcase:
      logs.log_error('Could not save testcase from fuzzer run.')

  # Store fuzzer console output.
  bot_name = environment.get_value('BOT_NAME')
  if fuzzer_return_code is not None:
    fuzzer_return_code_string = 'Return code (%d).' % fuzzer_return_code
  else:
    fuzzer_return_code_string = 'Fuzzer timed out.'
  truncated_fuzzer_output = truncate_fuzzer_output(fuzzer_output,
                                                   data_types.ENTITY_SIZE_LIMIT)
  console_output = u'%s: %s\n%s\n%s' % (bot_name, fuzzer_return_code_string,
                                        fuzzer_command, truncated_fuzzer_output)

  # Refresh the fuzzer object.
  fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer.name).get()

  # Make sure fuzzer is same as the latest revision.
  if not fuzzer:
    logs.log_fatal_and_exit('Fuzzer does not exist, exiting.')
  if fuzzer.revision != fuzzer_revision:
    logs.log('Fuzzer was recently updated, skipping results from old version.')
    return

  fuzzer.sample_testcase = sample_testcase
  fuzzer.console_output = console_output
  fuzzer.result = generated_testcase_string
  fuzzer.result_timestamp = datetime.datetime.utcnow()
  fuzzer.return_code = fuzzer_return_code
  fuzzer.put()

  logs.log('Finished storing results from fuzzer run.')


def get_regression(one_time_crasher_flag):
  """Get the right regression value."""
  if one_time_crasher_flag or build_manager.is_custom_binary():
    return 'NA'
  return ''


def get_fixed_or_minimized_key(one_time_crasher_flag):
  """Get the right fixed value."""
  return 'NA' if one_time_crasher_flag else ''


def get_minidump_keys(crash_info):
  """Get minidump_keys."""
  # This is a new crash, so add its minidump to blobstore first and get the
  # blob key information.
  if crash_info:
    return crash_info.store_minidump()
  return ''


def get_full_args(absolute_path):
  """Get full arguments for running testcase."""
  # If there are per-testcase additional flags, we need to store them.
  additional_args = tests.get_additional_command_line_flags(absolute_path) or ''
  app_args = environment.get_value('APP_ARGS') or ''
  return (app_args + ' ' + additional_args).strip()


def get_testcase_timeout_multiplier(timeout_multiplier, crash, test_timeout,
                                    thread_wait_timeout):
  """Get testcase timeout multiplier."""
  testcase_timeout_multiplier = timeout_multiplier
  if timeout_multiplier > 1 and (crash.crash_time + thread_wait_timeout) < (
      test_timeout / timeout_multiplier):
    testcase_timeout_multiplier = 1.0

  return testcase_timeout_multiplier


def create_testcase(group, context):
  """Create a testcase based on crash."""
  crash = group.main_crash
  fully_qualified_fuzzer_name = get_fully_qualified_fuzzer_name(context)
  testcase_id = data_handler.store_testcase(
      crash=crash,
      fuzzed_keys=crash.fuzzed_key,
      minimized_keys=get_fixed_or_minimized_key(group.one_time_crasher_flag),
      regression=get_regression(group.one_time_crasher_flag),
      fixed=get_fixed_or_minimized_key(group.one_time_crasher_flag),
      one_time_crasher_flag=group.one_time_crasher_flag,
      crash_revision=context.crash_revision,
      comment='Fuzzer %s generated testcase crashed in %d seconds (r%d)' %
      (fully_qualified_fuzzer_name, crash.crash_time, context.crash_revision),
      absolute_path=crash.absolute_path,
      fuzzer_name=context.fuzzer_name,
      fully_qualified_fuzzer_name=fully_qualified_fuzzer_name,
      job_type=context.job_type,
      archived=crash.archived,
      archive_filename=crash.archive_filename,
      binary_flag=utils.is_binary_file(crash.file_path),
      http_flag=crash.http_flag,
      gestures=crash.gestures,
      redzone=context.redzone,
      minidump_keys=get_minidump_keys(crash.crash_info),
      window_argument=context.window_argument,
      timeout_multiplier=get_testcase_timeout_multiplier(
          context.timeout_multiplier, crash, context.test_timeout,
          context.thread_wait_timeout),
      minimized_arguments=get_full_args(crash.absolute_path))
  testcase = data_handler.get_testcase_by_id(testcase_id)

  if context.fuzzer_metadata:
    for key, value in context.fuzzer_metadata.iteritems():
      testcase.set_metadata(key, value, update_testcase=False)

    testcase.put()

  fuzzing_strategies = (
      libfuzzer_stats.LIBFUZZER_FUZZING_STRATEGIES.search(
          crash.crash_stacktrace))

  if fuzzing_strategies:
    assert len(fuzzing_strategies.groups()) == 1
    fuzzing_strategies_string = fuzzing_strategies.groups()[0]
    fuzzing_strategies = [
        strategy.strip() for strategy in fuzzing_strategies_string.split(',')
    ]
    testcase.set_metadata(
        'fuzzing_strategies', fuzzing_strategies, update_testcase=True)

  # If there is one, record the original file this testcase was mutated from.
  if (crash.file_path in context.testcases_metadata and
      'original_file_path' in context.testcases_metadata[crash.file_path] and
      context.testcases_metadata[crash.file_path]['original_file_path']):
    testcase_relative_path = utils.get_normalized_relative_path(
        context.testcases_metadata[crash.file_path]['original_file_path'],
        context.data_directory)
    testcase.set_metadata('original_file_path', testcase_relative_path)

  # Track that app args appended by trials are required.
  trial_app_args = environment.get_value('TRIAL_APP_ARGS')
  if trial_app_args:
    testcase.set_metadata('additional_required_app_args', trial_app_args)

  # Create tasks to
  # 1. Minimize testcase (minimize).
  # 2. Find regression range (regression).
  # 3. Find testcase impact on production branches (impact).
  # 4. Check whether testcase is fixed (progression).
  # 5. Get second stacktrace from another job in case of
  #    one-time crashers (stack).
  task_creation.create_tasks(testcase)

  # If this is a new reproducible crash, annotate for upload to Chromecrash.
  if (not (group.one_time_crasher_flag or
           group.has_existing_reproducible_testcase())):
    crash.crash_info = crash_uploader.save_crash_info_if_needed(
        testcase_id, context.crash_revision, context.job_type, crash.crash_type,
        crash.crash_address, crash.crash_frames)

  return testcase


def filter_crashes(crashes):
  """Fitler crashes based on is_valid()."""
  filtered = []

  for crash in crashes:
    if not crash.is_valid():
      logs.log('Ignore crash (reason=%s, state=%s).' % (crash.get_error(),
                                                        crash.crash_state))
      continue

    filtered.append(crash)

  return filtered


def get_engine(context):
  """Get the fuzzing engine."""
  if context.fuzz_target:
    return context.fuzz_target.engine

  return ''


def get_fully_qualified_fuzzer_name(context):
  """Get the fully qualified fuzzer name."""
  if context.fuzz_target:
    return context.fuzz_target.fully_qualified_name()

  return context.fuzzer_name


def write_crashes_to_big_query(group, context):
  """Write a group of crashes to BigQuery."""
  created_at = int(time.time())

  # Many of ChromeOS fuzz targets run on Linux bots, so we incorrectly set the
  # linux platform for this. We cannot change platform_id in testcase as
  # otherwise linux bots can no longer lease those testcase. So, just change
  # this value in crash stats. This helps cleanup task put correct OS label.
  if environment.is_chromeos_job(context.job_type):
    actual_platform = 'chrome'
  else:
    actual_platform = context.platform_id

  # Write to a specific partition.
  table_id = ('crashes$%s' % (
      datetime.datetime.utcfromtimestamp(created_at).strftime('%Y%m%d')))

  client = big_query.Client(dataset_id='main', table_id=table_id)

  insert_id_prefix = ':'.join(
      [group.crashes[0].key, context.bot_name,
       str(created_at)])

  rows = []
  for index, crash in enumerate(group.crashes):
    created_testcase_id = None
    if crash == group.main_crash and group.newly_created_testcase:
      created_testcase_id = str(group.newly_created_testcase.key.id())

    rows.append(
        big_query.Insert(
            row={
                'crash_type': crash.crash_type,
                'crash_state': crash.crash_state,
                'created_at': created_at,
                'platform': actual_platform,
                'crash_time_in_ms': int(crash.crash_time * 1000),
                'parent_fuzzer_name': get_engine(context),
                'fuzzer_name': get_fully_qualified_fuzzer_name(context),
                'job_type': context.job_type,
                'security_flag': crash.security_flag,
                'project': context.project_name,
                'reproducible_flag': not group.one_time_crasher_flag,
                'revision': str(context.crash_revision),
                'new_flag': group.is_new() and crash == group.main_crash,
                'testcase_id': created_testcase_id
            },
            insert_id='%s:%s' % (insert_id_prefix, index)))

  row_count = len(rows)

  try:
    result = client.insert(rows)
    if result is None:
      # Happens in case the big query function is disabled (local development).
      return

    errors = result.get('insertErrors', [])
    failed_count = len(errors)

    monitoring_metrics.BIG_QUERY_WRITE_COUNT.increment_by(
        row_count - failed_count, {'success': True})
    monitoring_metrics.BIG_QUERY_WRITE_COUNT.increment_by(
        failed_count, {'success': False})

    for error in errors:
      logs.log_error(
          ('Ignoring error writing the crash (%s) to BigQuery.' %
           group.crashes[error['index']].crash_type),
          exception=Exception(error))
  except Exception:
    logs.log_error('Ignoring error writing a group of crashes to BigQuery')
    monitoring_metrics.BIG_QUERY_WRITE_COUNT.increment_by(
        row_count, {'success': False})


def process_crashes(crashes, context):
  """Process a list of crashes."""
  processed_groups = []
  new_crash_count = 0
  known_crash_count = 0

  def key_fn(crash):
    return crash.key

  # Filter invalid crashes.
  crashes = filter_crashes(crashes)
  group_of_crashes = itertools.groupby(sorted(crashes, key=key_fn), key_fn)

  for _, grouped_crashes in group_of_crashes:
    group = CrashGroup(list(grouped_crashes), context)

    # Archiving testcase to blobstore might fail for all crashes within this
    # group.
    if not group.main_crash:
      logs.log('Unable to store testcase in blobstore: %s' %
               group.crashes[0].crash_state)
      continue

    logs.log(
        'Process the crash group (file=%s, '
        'fuzzed_key=%s, '
        'return code=%s, '
        'crash time=%d, '
        'crash type=%s, '
        'crash state=%s, '
        'security flag=%s, '
        'crash stacktrace=%s)' %
        (group.main_crash.filename, group.main_crash.fuzzed_key,
         group.main_crash.return_code, group.main_crash.crash_time,
         group.main_crash.crash_type, group.main_crash.crash_state,
         group.main_crash.security_flag, group.main_crash.crash_stacktrace))

    if group.should_create_testcase():
      group.newly_created_testcase = create_testcase(
          group=group, context=context)

    write_crashes_to_big_query(group, context)

    if group.is_new():
      new_crash_count += 1
      known_crash_count += len(group.crashes) - 1
    else:
      known_crash_count += len(group.crashes)
    processed_groups.append(group)

    # Artificial delay to throttle appengine updates.
    time.sleep(1)

  logs.log('Finished processing crashes.')
  return new_crash_count, known_crash_count, processed_groups


def execute_task(fuzzer_name, job_type):
  """Runs the given fuzzer for one round."""
  failure_wait_interval = environment.get_value('FAIL_WAIT')

  # Update LSAN local blacklist with global blacklist.
  is_lsan_enabled = environment.get_value('LSAN')
  if is_lsan_enabled:
    leak_blacklist.copy_global_to_local_blacklist()

  # For some binaries, we specify trials, which are sets of flags that we only
  # apply some of the time. Adjust APP_ARGS for them if needed.
  trials.setup_additional_args_for_app()

  # Ensure that that the fuzzer still exists.
  logs.log('Setting up fuzzer and data bundles.')
  fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer_name).get()
  if not fuzzer or not setup.update_fuzzer_and_data_bundles(fuzzer_name):
    _track_fuzzer_run_result(fuzzer_name, 0, 0,
                             FuzzErrorCode.FUZZER_SETUP_FAILED)
    logs.log_error('Unable to setup fuzzer %s.' % fuzzer_name)

    # Artifical sleep to slow down continuous failed fuzzer runs if the bot is
    # using command override for task execution.
    time.sleep(failure_wait_interval)
    return

  # Set up a custom or regular build based on revision. By default, fuzzing
  # is done on trunk build (using revision=None). Otherwise, a job definition
  # can provide a revision to use via |APP_REVISION|.
  build_manager.setup_build(revision=environment.get_value('APP_REVISION'))

  # Check if we have an application path. If not, our build failed
  # to setup correctly.
  app_path = environment.get_value('APP_PATH')
  if not app_path:
    _track_fuzzer_run_result(fuzzer_name, 0, 0,
                             FuzzErrorCode.BUILD_SETUP_FAILED)
    return

  # Check if we have a bad build, i.e. one that crashes on startup.
  # If yes, bail out.
  logs.log('Checking for bad build.')
  crash_revision = environment.get_value('APP_REVISION')
  is_bad_build = tests.check_for_bad_build(job_type, crash_revision)
  _track_build_run_result(job_type, crash_revision, is_bad_build)
  if is_bad_build:
    return

  # Helper variables.
  bot_name = environment.get_value('BOT_NAME')
  data_bundle_name = fuzzer.data_bundle_name
  platform = environment.platform()
  platform_id = environment.get_platform_id()

  # Get the fuzzer directory.
  fuzzer_directory = setup.get_fuzzer_directory(fuzzer_name)

  # Get the testcase directories |testcase_directory| and |data_directory|.
  # Data bundle directories can also have testcases which are kept in-place
  # because of dependencies.
  testcase_directory = environment.get_value('FUZZ_INPUTS')
  data_directory = setup.get_data_bundle_directory(fuzzer_name)
  if not data_directory:
    _track_fuzzer_run_result(fuzzer_name, 0, 0,
                             FuzzErrorCode.DATA_BUNDLE_SETUP_FAILED)
    logs.log_error('Unable to setup data bundle %s.' % data_bundle_name)
    return

  # Pick up a timeout multiplier.
  timeout_multiplier = pick_timeout_multiplier()

  # Set the thread timeout values.
  fuzz_test_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')
  old_test_timeout = environment.get_value('TEST_TIMEOUT')
  if fuzz_test_timeout:
    base_test_timeout = fuzz_test_timeout
  else:
    base_test_timeout = old_test_timeout

  test_timeout = set_test_timeout(base_test_timeout, timeout_multiplier)
  thread_timeout = test_timeout

  # Determine number of testcases to process.
  testcase_count = environment.get_value('MAX_TESTCASES')

  # For timeout multipler greater than 1, we need to decrease testcase count to
  # prevent exceeding task lease time.
  if timeout_multiplier > 1:
    testcase_count /= timeout_multiplier

  # Run the fuzzer to generate testcases. If error occurred while trying
  # to run the fuzzer, bail out.
  (error_occurred, testcase_file_paths, generated_testcase_count,
   sync_corpus_directory,
   fuzzer_metadata) = run_fuzzer(fuzzer, fuzzer_directory, testcase_directory,
                                 data_directory, testcase_count)
  if error_occurred:
    return

  fuzzer_binary_name = fuzzer_metadata.get('fuzzer_binary_name')
  fuzz_target = None
  if fuzzer_binary_name:
    fuzz_target = record_fuzz_target(fuzzer_name, fuzzer_binary_name, job_type)
    fully_qualified_fuzzer_name = fuzz_target.fully_qualified_name()
    environment.set_value('FUZZER_NAME', fully_qualified_fuzzer_name)
  else:
    fully_qualified_fuzzer_name = fuzzer_name

  # Synchronize corpus files with GCS
  if sync_corpus_directory:
    gcs_corpus = GcsCorpus(fuzzer_name, fuzz_target.project_qualified_name(),
                           sync_corpus_directory, data_directory)

    if not gcs_corpus.sync_from_gcs():
      raise FuzzTaskException('Failed to sync corpus for fuzzer %s (job %s).' %
                              (fuzz_target.project_qualified_name(), job_type))

    environment.set_value('FUZZ_CORPUS_DIR', sync_corpus_directory)

  # Initialize a list of crashes.
  crashes = []

  # Pick up a random redzone.
  redzone = pick_redzone()

  # Pick up a random window size and position.
  window_argument = pick_window_argument()

  # Helper variables.
  max_threads = utils.maximum_parallel_processes_allowed()
  needs_stale_process_cleanup = False
  project_name = data_handler.get_project_name(job_type)
  test_number = 0
  testcases_before_stale_process_cleanup = environment.get_value(
      'TESTCASES_BEFORE_STALE_PROCESS_CLEANUP', 1)
  thread_delay = environment.get_value('THREAD_DELAY')
  thread_error_occurred = False

  # Reset memory tool options.
  environment.reset_current_memory_tool_options(redzone_size=redzone)

  thread_wait_timeout = 1

  # Create a dict to store metadata specific to each testcase.
  testcases_metadata = {}
  for testcase_file_path in testcase_file_paths:
    testcases_metadata[testcase_file_path] = {}

    # Pick up a gesture to run on the testcase.
    testcases_metadata[testcase_file_path]['gestures'] = pick_gestures(
        test_timeout)

  logs.log('Starting to process testcases.')
  logs.log('Redzone is %d bytes.' % redzone)
  logs.log('Timeout multiplier is %s.' % str(timeout_multiplier))
  logs.log(
      'App launch command is %s.' % tests.get_command_line_for_application())

  # Start processing the testcases.
  while test_number < len(testcase_file_paths):
    thread_index = 0
    threads = []

    temp_queue = process_handler.get_queue()
    if not temp_queue:
      process_handler.terminate_stale_application_instances()
      logs.log_error('Unable to create temporary crash queue.')
      break

    while thread_index < max_threads and test_number < len(testcase_file_paths):
      testcase_file_path = testcase_file_paths[test_number]
      gestures = testcases_metadata[testcase_file_path]['gestures']

      env_copy = environment.copy()
      thread = process_handler.get_process()(
          target=tests.run_testcase_and_return_result_in_queue,
          args=(temp_queue, thread_index, testcase_file_path, gestures,
                env_copy, True))

      try:
        thread.start()
      except:
        process_handler.terminate_stale_application_instances()
        thread_error_occurred = True
        logs.log_error('Unable to start new thread.')
        break

      threads.append(thread)
      thread_index += 1
      test_number += 1

      if test_number % testcases_before_stale_process_cleanup == 0:
        needs_stale_process_cleanup = True

      time.sleep(thread_delay)

    with _TrackFuzzTime(fully_qualified_fuzzer_name, job_type) as tracker:
      tracker.timeout = utils.wait_until_timeout(threads, thread_timeout)

    # Allow for some time to finish processing before terminating the processes.
    process_handler.terminate_hung_threads(threads)

    # It is not necessary to clean up stale instances on every batch, but
    # should be done at regular intervals to ensure we are in a good state.
    if needs_stale_process_cleanup:
      process_handler.terminate_stale_application_instances()
      needs_stale_process_cleanup = False

    while not temp_queue.empty():
      crashes.append(temp_queue.get())

    process_handler.close_queue(temp_queue)

    logs.log('Upto %d' % test_number)

    if thread_error_occurred:
      break

  # Pull testcase directory to host. The testcase file contents could have been
  # changed (by e.g. libFuzzer) and stats files could have been written.
  if environment.is_trusted_host():
    from bot.untrusted_runner import file_host
    file_host.pull_testcases_from_worker()

  # Synchronize corpus files with GCS after fuzzing
  if sync_corpus_directory:
    new_files = gcs_corpus.get_new_files()
    new_files_count = len(new_files)
    logs.log('%d new corpus files generated by fuzzer %s (job %s).' %
             (new_files_count, fuzz_target.project_qualified_name(), job_type))

    if new_files_count > MAX_NEW_CORPUS_FILES:
      # Throttle corpus uploads so they don't explode in size.
      logs.log(('Only uploading %d out of %d new corpus files '
                'generated by fuzzer %s (job %s).') %
               (MAX_NEW_CORPUS_FILES, new_files_count,
                fuzz_target.project_qualified_name(), job_type))
      new_files = random.sample(new_files, MAX_NEW_CORPUS_FILES)

    gcs_corpus.upload_files(new_files)

  logs.log('Finished processing test cases.')

  # Currently, the decision to do fuzzing or running the testcase is based on
  # the value of |FUZZ_CORPUS_DIR|. Reset it to None, so that later runs of
  # testForReproducibility run the testcase.
  # FIXME: Change to environment.remove_key call when it supports removing
  # the environment variable on untrusted bot (as part of
  # bot.untrusted_runner import environment).
  environment.set_value('FUZZ_CORPUS_DIR', None)

  # Restore old values before attempting to test for reproducibility.
  test_timeout = set_test_timeout(old_test_timeout, timeout_multiplier)

  # For Android, bring back device to a good state before analyzing crashes.
  # TODO(unassigned): Need to find a way to this efficiently before every
  # testcase is analyzed.
  if platform == 'ANDROID' and crashes:
    android.device.initialize_device()

  # Transform tests.Crash into fuzz_task.Crash.
  # And filter the crashes (e.g. removing errorneous crashes).
  crashes = [Crash(crash) for crash in crashes]

  # Process and save crashes to datastore.
  new_crash_count, known_crash_count, processed_groups = process_crashes(
      crashes=crashes,
      context=Context(
          project_name=project_name,
          bot_name=bot_name,
          job_type=job_type,
          fuzz_target=fuzz_target,
          redzone=redzone,
          platform_id=platform_id,
          crash_revision=crash_revision,
          fuzzer_name=fuzzer_name,
          window_argument=window_argument,
          fuzzer_metadata=fuzzer_metadata,
          testcases_metadata=testcases_metadata,
          timeout_multiplier=timeout_multiplier,
          test_timeout=test_timeout,
          thread_wait_timeout=thread_wait_timeout,
          data_directory=data_directory))

  upload_testcase_run_stats(fuzzer_name, fully_qualified_fuzzer_name, job_type,
                            crash_revision, testcase_file_paths)
  upload_job_run_stats(fully_qualified_fuzzer_name, job_type, crash_revision,
                       time.time(), new_crash_count, known_crash_count,
                       generated_testcase_count, processed_groups)

  # Delete the fuzzed testcases. This is explicitly needed since
  # some testcases might reside on NFS and would otherwise be
  # left forever.
  for testcase_file_path in testcase_file_paths:
    shell.remove_file(testcase_file_path)

  # Explicit cleanup for large vars.
  del testcase_file_paths
  del testcases_metadata
  utils.python_gc()

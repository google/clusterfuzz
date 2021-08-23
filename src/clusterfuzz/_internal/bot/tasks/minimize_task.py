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
"""Minimize task for handling testcase minimization."""

import binascii
import functools
import os
import threading
import time
import zipfile

import six

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.libFuzzer.engine import LibFuzzerEngine
from clusterfuzz._internal.bot.minimizer import basic_minimizers
from clusterfuzz._internal.bot.minimizer import delta_minimizer
from clusterfuzz._internal.bot.minimizer import errors as minimizer_errors
from clusterfuzz._internal.bot.minimizer import html_minimizer
from clusterfuzz._internal.bot.minimizer import js_minimizer
from clusterfuzz._internal.bot.minimizer import minimizer
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.bot.tokenizer.antlr_tokenizer import AntlrTokenizer
from clusterfuzz._internal.bot.tokenizer.grammars.JavaScriptLexer import \
    JavaScriptLexer
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.crash_analysis import severity_analyzer
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.system import shell
from clusterfuzz.fuzz import engine

IPCDUMP_TIMEOUT = 60
COMBINED_IPCDUMP_TIMEOUT = 60 * 3
MAX_DEADLINE_EXCEEDED_ATTEMPTS = 3
MAX_TEMPORARY_FILE_BASENAME_LENGTH = 32
MINIMIZE_SANITIZER_OPTIONS_RETRIES = 3
TOKENS_PER_IPCDUMP = 2000

IPC_MESSAGE_UTIL_EXECUTABLE_FOR_PLATFORM = {
    'LINUX': 'ipc_message_util',
    'WINDOWS': 'ipc_message_util.exe',
}

# These options should not ever be removed during minimization. They might seem
# unneeded when reproducing a given crash, but after the bug is fixed, the lack
# of these options might prevent ClusterFuzz from verifying the fix and closing
# the bug. See https://github.com/google/oss-fuzz/issues/3227 for example.
MANDATORY_OSS_FUZZ_OPTIONS = [
    'silence_unsigned_overflow',
]


class MinimizationPhase(object):
  """Effectively an enum to represent the current phase of minimization."""
  GESTURES = 0
  MAIN_FILE = 1
  FILE_LIST = 2
  RESOURCES = 3
  ARGUMENTS = 4


class TestRunner(object):
  """Helper class for running the same test multiple times."""

  def __init__(self, testcase, file_path, files, input_directory, arguments,
               required_arguments, threads, deadline):
    self.testcase = testcase
    self.file_path = file_path
    self.files = files
    self.input_directory = input_directory
    self.gestures = testcase.gestures
    self.arguments = arguments
    self.threads = threads
    self.deadline = deadline

    self.cleanup_interval = environment.get_value(
        'TESTCASES_BEFORE_STALE_PROCESS_CLEANUP', 1)
    self.timeout = environment.get_value('TEST_TIMEOUT', 10)
    self.full_timeout = self.timeout
    self.last_failing_result = None
    self.required_arguments = set(required_arguments.split())

    self.expected_security_flag = False
    self.is_flaky = False
    self.expected_state = None

    self._profile_lock = threading.Lock()
    self._available_profiles = [True] * threads

    self._result_lock = threading.Lock()
    self._results = []

    self._previous_arguments = None

  def _get_profile_index(self):
    """Get the first available profile directory index."""
    with self._profile_lock:
      for index, is_available in enumerate(self._available_profiles):
        if is_available:
          self._available_profiles[index] = False
          return index

    # Raise an exception rather than running in a bad state.
    raise errors.BadStateError('No profile directories available.')

  def _release_profile(self, index):
    """Mark the specified profile as available."""
    with self._profile_lock:
      self._available_profiles[index] = True

  def _handle_test_result(self, result):
    """Handle a test result, return True on pass (no crash), False on fail."""
    if not result.is_crash():
      return True

    # If we have no crash state, we should not consider this a crash.
    state = result.get_state(symbolized=False)
    if not state:
      return True

    # Even though this was a crash, we want to ignore it if the stack does not
    # have the expected security flag (e.g. expected UAF but got NULL deref).
    if result.is_security_issue() != self.expected_security_flag:
      return True

    # Ignore failures that do not appear to be caused by this issue.
    if not self.is_flaky and state != self.expected_state:
      return True

    self.last_failing_result = result
    return False

  def _repopulate_required_arguments(self, arguments):
    """Add required arguments back to the argument list."""
    fixed_arguments = []
    original_arguments = self.arguments.split()

    original_argument_index = 0
    argument_index = 0

    while original_argument_index < len(original_arguments):
      original_argument = original_arguments[original_argument_index]
      if (argument_index < len(arguments) and
          original_argument == arguments[argument_index]):
        argument_index += 1
        fixed_arguments.append(original_argument)
      elif (original_argument in self.required_arguments or
            original_argument.split('=')[0] in self.required_arguments or
            '"' in original_argument or "'" in original_argument):
        fixed_arguments.append(original_argument)

      original_argument_index += 1

    return fixed_arguments

  def get_argument_string(self, arguments):
    """Convert a list of argument tokens to a usable value."""
    fixed_arguments = self._repopulate_required_arguments(arguments)
    return ' '.join(fixed_arguments)

  def test_with_defaults(self, _):
    """Run a test with all default values."""
    result = self.run()
    return self._handle_test_result(result)

  def test_with_files(self, files):
    """Run the test with the specified file list."""
    files_to_rename = list(set(self.files) - set(files))
    files_to_skip = []

    # Generate a unique suffix to append to files we want to ignore.
    index = 0
    file_rename_suffix = '___%d' % index
    while any([f.endswith(file_rename_suffix) for f in files_to_rename]):
      index += 1
      file_rename_suffix = '___%d' % index

    # Rename all files in the test case's file list but not the specified one.
    for file_to_rename in files_to_rename:
      absolute_file_to_rename = os.path.join(self.input_directory,
                                             file_to_rename)
      try:
        os.rename(absolute_file_to_rename,
                  '%s%s' % (absolute_file_to_rename, file_rename_suffix))
      except OSError:
        # This can happen if we have already renamed a directory with files
        # under it. In this case, make sure we don't try to change the name
        # back later.
        files_to_skip.append(file_to_rename)

    # Clean up any issues with modifications of resources in subdirectories.
    for file_to_skip in files_to_skip:
      files_to_rename.remove(file_to_skip)
    files_to_rename.reverse()

    result = self.run()

    # Restore previously renamed files to their original locations.
    for file_to_rename in files_to_rename:
      absolute_file_to_rename = os.path.join(self.input_directory,
                                             file_to_rename)
      os.rename('%s%s' % (absolute_file_to_rename, file_rename_suffix),
                absolute_file_to_rename)

    return self._handle_test_result(result)

  def test_with_file(self, file_path):
    """Run the test with the specified contents for a particular file."""
    result = self.run(file_path=file_path)
    return self._handle_test_result(result)

  def test_with_gestures(self, gestures):
    """Run the test with the specified gesture list."""
    result = self.run(gestures=gestures)
    return self._handle_test_result(result)

  def test_with_command_line_arguments(self, arguments):
    """Run the test with the specified command line."""
    fixed_arguments = self.get_argument_string(arguments)
    result = self.run(
        arguments=fixed_arguments,
        timeout=self.full_timeout,
        use_fresh_profile=True)
    return self._handle_test_result(result)

  def set_test_expectations(self, security_flag, is_flaky,
                            unsymbolized_crash_state):
    """Set expectations when using this runner for tests."""
    self.expected_security_flag = security_flag
    self.is_flaky = is_flaky
    self.expected_state = unsymbolized_crash_state

  def run(self,
          file_path=None,
          gestures=None,
          arguments=None,
          timeout=None,
          log_command=False,
          use_fresh_profile=False):
    """Run the test."""
    if file_path is None:
      file_path = self.file_path

    if gestures is None:
      gestures = self.gestures

    if arguments is None:
      arguments = self.arguments

    # TODO(mbarbella): Dynamic timeout adjustment.
    if timeout is None:
      timeout = self.timeout

    needs_http = self.testcase.http_flag
    profile_index = self._get_profile_index()

    if use_fresh_profile and environment.get_value('USER_PROFILE_ARG'):
      shell.remove_directory(
          testcase_manager.get_user_profile_directory(profile_index))

    # For Android, we need to sync our local testcases directory with the one on
    # the device.
    if environment.is_android():
      android.device.push_testcases_to_device()
    elif environment.is_trusted_host():
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      file_host.push_testcases_to_worker()

    # If we need to write a command line file, only do so if the arguments have
    # changed.
    arguments_changed = arguments != self._previous_arguments
    self._previous_arguments = arguments

    command = testcase_manager.get_command_line_for_application(
        file_to_run=file_path,
        app_args=arguments,
        needs_http=needs_http,
        user_profile_index=profile_index,
        write_command_line_file=arguments_changed)
    if log_command:
      logs.log('Executing command: %s' % command)

    return_code, crash_time, output = process_handler.run_process(
        command, timeout=timeout, gestures=gestures)

    self._release_profile(profile_index)
    return CrashResult(return_code, crash_time, output)

  def store_result_from_run(self, result):
    """Run and store the result for later processing."""
    with self._result_lock:
      self._results.append(result)

    # A race here isn't problematic. Better not to hold the lock during an
    # is_crash call.
    if not self.last_failing_result and result.is_crash():
      self.last_failing_result = result

  def execute_parallel_runs(self, runs, instances=None):
    """Run multiple instances of this test in parallel."""
    if not instances:
      instances = self.threads

    # TODO(mbarbella): Hack for Android. If we are running single-threaded, it
    # is safe to call a cleanup function on each thread. Ideally, the minimizer
    # would like to assume that when it finishes running a process it cleans
    # itself up properly.
    cleanup_function = None
    if self.threads == 1:
      cleanup_function = process_handler.cleanup_stale_processes

    run_queue = minimizer.TestQueue(
        instances, per_thread_cleanup_function=cleanup_function)
    for _ in range(runs):
      run_queue.push(self.file_path, self.run, self.store_result_from_run)

    run_queue.process()

    # At timeout, we send SIGTERM. Wait for 2 seconds before sending SIGKILL.
    time.sleep(2)
    process_handler.cleanup_stale_processes()

    with self._result_lock:
      results = self._results
      self._results = []

    return results


def execute_task(testcase_id, job_type):
  """Attempt to minimize a given testcase."""
  # Get deadline to finish this task.
  deadline = tasks.get_task_completion_deadline()

  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if not testcase:
    return

  # Update comments to reflect bot information.
  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  # Setup testcase and its dependencies. Also, allow setting up a different
  # fuzzer.
  minimize_fuzzer_override = environment.get_value('MINIMIZE_FUZZER_OVERRIDE')
  file_list, input_directory, testcase_file_path = setup.setup_testcase(
      testcase, job_type, fuzzer_override=minimize_fuzzer_override)
  if not file_list:
    return

  # Initialize variables.
  max_timeout = environment.get_value('TEST_TIMEOUT', 10)
  app_arguments = environment.get_value('APP_ARGS')

  # Set up a custom or regular build based on revision.
  last_tested_crash_revision = testcase.get_metadata(
      'last_tested_crash_revision')

  crash_revision = last_tested_crash_revision or testcase.crash_revision
  build_manager.setup_build(crash_revision)

  # Check if we have an application path. If not, our build failed
  # to setup correctly.
  if not build_manager.check_app_path():
    logs.log_error('Unable to setup build for minimization.')
    build_fail_wait = environment.get_value('FAIL_WAIT')

    if environment.get_value('ORIGINAL_JOB_NAME'):
      _skip_minimization(testcase, 'Failed to setup build for overridden job.')
    else:
      # Only recreate task if this isn't an overriden job. It's possible that a
      # revision exists for the original job, but doesn't exist for the
      # overriden job.
      tasks.add_task(
          'minimize', testcase_id, job_type, wait_time=build_fail_wait)

    return

  if environment.is_libfuzzer_job():
    do_libfuzzer_minimization(testcase, testcase_file_path)
    return

  if environment.is_engine_fuzzer_job():
    # TODO(ochang): More robust check for engine minimization support.
    _skip_minimization(testcase, 'Engine does not support minimization.')
    return

  max_threads = utils.maximum_parallel_processes_allowed()

  # Prepare the test case runner.
  crash_retries = environment.get_value('CRASH_RETRIES')
  warmup_timeout = environment.get_value('WARMUP_TIMEOUT')
  required_arguments = environment.get_value('REQUIRED_APP_ARGS', '')

  # Add any testcase-specific required arguments if needed.
  additional_required_arguments = testcase.get_metadata(
      'additional_required_app_args')
  if additional_required_arguments:
    required_arguments = '%s %s' % (required_arguments,
                                    additional_required_arguments)

  test_runner = TestRunner(testcase, testcase_file_path, file_list,
                           input_directory, app_arguments, required_arguments,
                           max_threads, deadline)

  # Verify the crash with a long timeout.
  warmup_crash_occurred = False
  result = test_runner.run(timeout=warmup_timeout, log_command=True)
  if result.is_crash():
    warmup_crash_occurred = True
    logs.log('Warmup crash occurred in %d seconds.' % result.crash_time)

  saved_unsymbolized_crash_state, flaky_stack, crash_times = (
      check_for_initial_crash(test_runner, crash_retries, testcase))

  # If the warmup crash occurred but we couldn't reproduce this in with
  # multiple processes running in parallel, try to minimize single threaded.
  reproducible_crash_count = (
      testcase_manager.REPRODUCIBILITY_FACTOR * crash_retries)
  if (len(crash_times) < reproducible_crash_count and warmup_crash_occurred and
      max_threads > 1):
    logs.log('Attempting to continue single-threaded.')

    max_threads = 1
    test_runner = TestRunner(testcase, testcase_file_path, file_list,
                             input_directory, app_arguments, required_arguments,
                             max_threads, deadline)

    saved_unsymbolized_crash_state, flaky_stack, crash_times = (
        check_for_initial_crash(test_runner, crash_retries, testcase))

  if not crash_times:
    # We didn't crash at all. This might be a legitimately unreproducible
    # test case, so it will get marked as such after being retried on other
    # bots.
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Unable to reproduce crash')
    task_creation.mark_unreproducible_if_flaky(testcase, True)
    return

  if flaky_stack:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    testcase.flaky_stack = flaky_stack
    testcase.put()

  is_redo = testcase.get_metadata('redo_minimize')
  if not is_redo and len(crash_times) < reproducible_crash_count:
    # We reproduced this crash at least once. It's too flaky to minimize, but
    # maybe we'll have more luck in the other jobs.
    testcase = data_handler.get_testcase_by_id(testcase_id)
    testcase.minimized_keys = 'NA'
    error_message = (
        'Crash occurs, but not too consistently. Skipping minimization '
        '(crashed %d/%d)' % (len(crash_times), crash_retries))
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         error_message)
    create_additional_tasks(testcase)
    return

  # If we've made it this far, the test case appears to be reproducible. Clear
  # metadata from previous runs had it been marked as potentially flaky.
  task_creation.mark_unreproducible_if_flaky(testcase, False)

  test_runner.set_test_expectations(testcase.security_flag, flaky_stack,
                                    saved_unsymbolized_crash_state)

  # Use the max crash time unless this would be greater than the max timeout.
  test_timeout = min(max(crash_times), max_timeout) + 1
  logs.log('Using timeout %d (was %d)' % (test_timeout, max_timeout))
  test_runner.timeout = test_timeout

  logs.log('Starting minimization.')

  if should_attempt_phase(testcase, MinimizationPhase.GESTURES):
    gestures = minimize_gestures(test_runner, testcase)

    # We can't call check_deadline_exceeded_and_store_partial_minimized_testcase
    # at this point because we do not have a test case to store.
    testcase = data_handler.get_testcase_by_id(testcase.key.id())

    if testcase.security_flag and len(testcase.gestures) != len(gestures):
      # Re-run security severity analysis since gestures affect the severity.
      testcase.security_severity = severity_analyzer.get_security_severity(
          testcase.crash_type, data_handler.get_stacktrace(testcase), job_type,
          bool(gestures))

    testcase.gestures = gestures
    testcase.set_metadata('minimization_phase', MinimizationPhase.MAIN_FILE)

    if time.time() > test_runner.deadline:
      tasks.add_task('minimize', testcase.key.id(), job_type)
      return

  # Minimize the main file.
  data = utils.get_file_contents_with_fatal_error_on_failure(testcase_file_path)
  if should_attempt_phase(testcase, MinimizationPhase.MAIN_FILE):
    data = minimize_main_file(test_runner, testcase_file_path, data)

    if check_deadline_exceeded_and_store_partial_minimized_testcase(
        deadline, testcase_id, job_type, input_directory, file_list, data,
        testcase_file_path):
      return

    testcase.set_metadata('minimization_phase', MinimizationPhase.FILE_LIST)

  # Minimize the file list.
  if should_attempt_phase(testcase, MinimizationPhase.FILE_LIST):
    if environment.get_value('MINIMIZE_FILE_LIST', True):
      file_list = minimize_file_list(test_runner, file_list, input_directory,
                                     testcase_file_path)

      if check_deadline_exceeded_and_store_partial_minimized_testcase(
          deadline, testcase_id, job_type, input_directory, file_list, data,
          testcase_file_path):
        return
    else:
      logs.log('Skipping minimization of file list.')

    testcase.set_metadata('minimization_phase', MinimizationPhase.RESOURCES)

  # Minimize any files remaining in the file list.
  if should_attempt_phase(testcase, MinimizationPhase.RESOURCES):
    if environment.get_value('MINIMIZE_RESOURCES', True):
      for dependency in file_list:
        minimize_resource(test_runner, dependency, input_directory,
                          testcase_file_path)

        if check_deadline_exceeded_and_store_partial_minimized_testcase(
            deadline, testcase_id, job_type, input_directory, file_list, data,
            testcase_file_path):
          return
    else:
      logs.log('Skipping minimization of resources.')

    testcase.set_metadata('minimization_phase', MinimizationPhase.ARGUMENTS)

  if should_attempt_phase(testcase, MinimizationPhase.ARGUMENTS):
    app_arguments = minimize_arguments(test_runner, app_arguments)

    # Arguments must be stored here in case we time out below.
    testcase.minimized_arguments = app_arguments
    testcase.put()

    if check_deadline_exceeded_and_store_partial_minimized_testcase(
        deadline, testcase_id, job_type, input_directory, file_list, data,
        testcase_file_path):
      return

  command = testcase_manager.get_command_line_for_application(
      testcase_file_path, app_args=app_arguments, needs_http=testcase.http_flag)
  last_crash_result = test_runner.last_failing_result

  store_minimized_testcase(testcase, input_directory, file_list, data,
                           testcase_file_path)
  finalize_testcase(
      testcase_id, command, last_crash_result, flaky_stack=flaky_stack)


def finalize_testcase(testcase_id,
                      command,
                      last_crash_result,
                      flaky_stack=False):
  """Perform final updates on a test case and prepare it for other tasks."""
  # Symbolize crash output if we have it.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if last_crash_result:
    _update_crash_result(testcase, last_crash_result, command)
  testcase.delete_metadata('redo_minimize', update_testcase=False)

  # Update remaining test case information.
  testcase.flaky_stack = flaky_stack
  if build_manager.is_custom_binary():
    testcase.set_impacts_as_na()
    testcase.regression = 'NA'
  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED)

  # We might have updated the crash state. See if we need to marked as duplicate
  # based on other testcases.
  data_handler.handle_duplicate_entry(testcase)

  create_additional_tasks(testcase)


def create_additional_tasks(testcase):
  """Create post-minimization tasks for this reproducible testcase such as
  impact, regression, progression, variant and symbolize."""
  # No need to create progression task. It is automatically created by the cron
  # handler.
  task_creation.create_impact_task_if_needed(testcase)
  task_creation.create_regression_task_if_needed(testcase)
  task_creation.create_symbolize_task_if_needed(testcase)
  task_creation.create_variant_tasks_if_needed(testcase)


def should_attempt_phase(testcase, phase):
  """Return true if we should we attempt a minimization phase."""
  if (phase == MinimizationPhase.ARGUMENTS and
      environment.is_engine_fuzzer_job()):
    # Should not minimize arguments list for engine based fuzzer jobs.
    return False

  current_phase = testcase.get_metadata(
      'minimization_phase', default=MinimizationPhase.GESTURES)
  return phase >= current_phase


def minimize_gestures(test_runner, testcase):
  """Minimize the gesture list for a test case."""
  gestures = testcase.gestures
  if gestures:
    gesture_minimizer = delta_minimizer.DeltaMinimizer(
        test_runner.test_with_gestures,
        max_threads=test_runner.threads,
        tokenize=False,
        deadline=test_runner.deadline,
        cleanup_function=process_handler.cleanup_stale_processes,
        single_thread_cleanup_interval=test_runner.cleanup_interval,
        progress_report_function=functools.partial(logs.log))
    gestures = gesture_minimizer.minimize(gestures)

  logs.log('Minimized gestures: %s' % str(gestures))
  return gestures


def minimize_main_file(test_runner, testcase_file_path, data):
  """Minimize the main test case file."""
  if not can_minimize_file(testcase_file_path):
    return data

  get_random_file = functools.partial(get_temporary_file, testcase_file_path)
  data = (
      minimize_file(testcase_file_path, test_runner.test_with_file,
                    get_random_file, data, test_runner.deadline,
                    test_runner.threads, test_runner.cleanup_interval))

  logs.log('Minimized main test file.')
  return data


def minimize_file_list(test_runner, file_list, input_directory, main_file):
  """Minimize the test case files."""
  if len(file_list) <= 1:
    return file_list

  # TODO(mbarbella): Simplify this with refactoring of setup_testcase.
  offset = len(input_directory) + len(os.path.sep)
  fixed_testcase_file_path = main_file[offset:]

  # As of now, this must be single-threaded.
  file_list_minimizer = basic_minimizers.SinglePassMinimizer(
      test_runner.test_with_files,
      tokenize=False,
      deadline=test_runner.deadline,
      cleanup_function=process_handler.cleanup_stale_processes,
      single_thread_cleanup_interval=test_runner.cleanup_interval,
      progress_report_function=functools.partial(logs.log))
  file_list = file_list_minimizer.minimize(file_list)

  if fixed_testcase_file_path not in file_list:
    file_list.append(fixed_testcase_file_path)

  logs.log('Minimized file list: %s' % str(file_list))
  return file_list


def minimize_resource(test_runner, dependency, input_directory, main_file):
  """Minimize a resource for the test case."""
  # TODO(mbarbella): Simplify this with refactoring of setup_testcase.
  offset = len(input_directory) + len(os.path.sep)
  fixed_testcase_file_path = main_file[offset:]

  dependency_absolute_path = os.path.join(input_directory, dependency)

  if (dependency == fixed_testcase_file_path or dependency == main_file or
      not can_minimize_file(dependency_absolute_path)):
    return

  get_temp_file = functools.partial(
      get_temporary_file, dependency_absolute_path, no_modifications=True)
  original_data = utils.get_file_contents_with_fatal_error_on_failure(
      dependency_absolute_path)
  dependency_data = (
      minimize_file(
          dependency,
          test_runner.test_with_defaults,
          get_temp_file,
          original_data,
          test_runner.deadline,
          1,
          test_runner.cleanup_interval,
          delete_temp_files=False))
  utils.write_data_to_file(dependency_data, dependency_absolute_path)

  logs.log('Minimized dependency file: %s' % dependency)


def minimize_arguments(test_runner, app_arguments):
  """Minimize the argument list for a test case."""
  argument_minimizer = delta_minimizer.DeltaMinimizer(
      test_runner.test_with_command_line_arguments,
      max_threads=test_runner.threads,
      tokenize=False,
      deadline=test_runner.deadline,
      cleanup_function=process_handler.cleanup_stale_processes,
      single_thread_cleanup_interval=test_runner.cleanup_interval,
      progress_report_function=functools.partial(logs.log))
  reduced_args = argument_minimizer.minimize(app_arguments.split())
  reduced_arg_string = test_runner.get_argument_string(reduced_args)

  return reduced_arg_string


def store_minimized_testcase(testcase, base_directory, file_list,
                             file_to_run_data, file_to_run):
  """Store all files that make up this testcase."""
  # Write the main file data.
  utils.write_data_to_file(file_to_run_data, file_to_run)

  # Prepare the file.
  zip_path = None
  if testcase.archive_state:
    if len(file_list) > 1:
      testcase.archive_state |= data_types.ArchiveStatus.MINIMIZED
      zip_path = os.path.join(
          environment.get_value('INPUT_DIR'), '%d.zip' % testcase.key.id())
      zip_file = zipfile.ZipFile(zip_path, 'w')
      count = 0
      filtered_file_list = []
      for file_name in file_list:
        absolute_filename = os.path.join(base_directory, file_name)
        is_file = os.path.isfile(absolute_filename)
        if file_to_run_data and is_file and os.path.getsize(
            absolute_filename) == 0 and (os.path.basename(
                absolute_filename).encode('utf-8') not in file_to_run_data):
          continue
        if not os.path.exists(absolute_filename):
          continue
        zip_file.write(absolute_filename, file_name, zipfile.ZIP_DEFLATED)
        if is_file:
          count += 1
          filtered_file_list.append(absolute_filename)

      zip_file.close()
      try:
        if count > 1:
          file_handle = open(zip_path, 'rb')
        else:
          if not filtered_file_list:
            # We minimized everything. The only thing needed to reproduce is the
            # interaction gesture.
            file_path = file_list[0]
            file_handle = open(file_path, 'wb')
            file_handle.close()
          else:
            file_path = filtered_file_list[0]
          file_handle = open(file_path, 'rb')
          testcase.absolute_path = os.path.join(base_directory,
                                                os.path.basename(file_path))
          testcase.archive_state &= ~data_types.ArchiveStatus.MINIMIZED
      except IOError:
        testcase.put()  # Preserve what we can.
        logs.log_error('Unable to open archive for blobstore write.')
        return
    else:
      absolute_filename = os.path.join(base_directory, file_list[0])
      file_handle = open(absolute_filename, 'rb')
      testcase.archive_state &= ~data_types.ArchiveStatus.MINIMIZED
  else:
    file_handle = open(file_list[0], 'rb')
    testcase.archive_state &= ~data_types.ArchiveStatus.MINIMIZED

  # Store the testcase.
  minimized_keys = blobs.write_blob(file_handle)
  file_handle.close()

  testcase.minimized_keys = minimized_keys
  testcase.put()

  if zip_path:
    shell.remove_file(zip_path)


def check_deadline_exceeded_and_store_partial_minimized_testcase(
    deadline, testcase_id, job_type, input_directory, file_list,
    file_to_run_data, main_file_path):
  """Store the partially minimized test and check the deadline."""
  testcase = data_handler.get_testcase_by_id(testcase_id)
  store_minimized_testcase(testcase, input_directory, file_list,
                           file_to_run_data, main_file_path)

  deadline_exceeded = time.time() > deadline
  if deadline_exceeded:
    attempts = testcase.get_metadata(
        'minimization_deadline_exceeded_attempts', default=0)
    if attempts >= MAX_DEADLINE_EXCEEDED_ATTEMPTS:
      _skip_minimization(testcase,
                         'Exceeded minimization deadline too many times.')
    else:
      testcase.set_metadata('minimization_deadline_exceeded_attempts',
                            attempts + 1)
      tasks.add_task('minimize', testcase_id, job_type)

  return deadline_exceeded


def check_for_initial_crash(test_runner, crash_retries, testcase):
  """Initial check to see how long it takes to reproduce a crash."""
  crash_times = []
  flaky_stack = False
  saved_crash_state = None
  saved_security_flag = None
  saved_unsymbolized_crash_state = None

  results = test_runner.execute_parallel_runs(crash_retries)

  for result in results:
    if not result.is_crash():
      continue

    if result.should_ignore():
      continue

    crash_state = result.get_state(symbolized=True)
    security_flag = result.is_security_issue()
    unsymbolized_crash_state = result.get_state(symbolized=False)

    if not unsymbolized_crash_state:
      continue

    if security_flag != testcase.security_flag:
      continue

    crash_times.append(result.crash_time)

    if not saved_crash_state:
      saved_crash_state = crash_state
      saved_security_flag = security_flag
      saved_unsymbolized_crash_state = unsymbolized_crash_state
      continue

    crash_comparer = CrashComparer(crash_state, saved_crash_state)
    if not crash_comparer.is_similar():
      flaky_stack = True

  logs.log('Total crash count: %d/%d. Flaky: %s. Security: %s. State:\n%s' %
           (len(crash_times), crash_retries, flaky_stack, saved_security_flag,
            saved_crash_state))

  return saved_unsymbolized_crash_state, flaky_stack, crash_times


def get_temporary_file_name(original_file):
  """Generate a temporary file name in the same directory as |original_file|."""
  directory, basename = os.path.split(original_file)
  basename = basename[-MAX_TEMPORARY_FILE_BASENAME_LENGTH:]

  random_hex = binascii.b2a_hex(os.urandom(16)).decode('utf-8')
  new_file_path = os.path.join(directory, '%s%s' % (random_hex, basename))

  return new_file_path


def get_temporary_file(original_file, no_modifications=False):
  """Get a temporary file handle with a name based on an original file name."""
  if no_modifications:
    handle = open(original_file, 'wb')
    return handle

  handle = open(get_temporary_file_name(original_file), 'wb')
  return handle


def get_ipc_message_util_executable():
  """Return the ipc_message_util executable path for the current build."""
  app_directory = environment.get_value('APP_DIR')
  platform = environment.platform()

  try:
    executable = IPC_MESSAGE_UTIL_EXECUTABLE_FOR_PLATFORM[platform]
  except KeyError:
    # Current platform is not supported.
    return None

  return os.path.join(app_directory, executable)


def create_partial_ipc_dump(tokens, original_file_path):
  """Use the ipc_message_util utility to create a file for up to
     |TOKENS_PER_IPCDUMP| tokens."""
  assert len(tokens) <= TOKENS_PER_IPCDUMP

  token_list = ','.join([str(token) for token in tokens])
  temp_file_path = get_temporary_file_name(original_file_path)

  executable = get_ipc_message_util_executable()
  command_line = shell.get_command_line_from_argument_list(
      [executable,
       '--in=%s' % token_list, original_file_path, temp_file_path])
  return_code, _, output = process_handler.run_process(
      command_line, testcase_run=False, timeout=IPCDUMP_TIMEOUT)
  if return_code or not os.path.exists(temp_file_path):
    # For some reason, generating the new file failed.
    logs.log_error('Failed to create ipc dump file %s.' % output)
    return None

  return temp_file_path


def combine_ipc_dumps(ipcdumps, original_file_path):
  """Combines a list of ipcdump files into a single dump."""
  input_file_string = ','.join(ipcdumps)
  executable = get_ipc_message_util_executable()
  output_file_path = get_temporary_file_name(original_file_path)
  command_line = shell.get_command_line_from_argument_list(
      [executable, input_file_string, output_file_path])
  return_code, _, output = process_handler.run_process(
      command_line, testcase_run=False, timeout=COMBINED_IPCDUMP_TIMEOUT)

  for ipcdump in ipcdumps:
    shell.remove_file(ipcdump)

  if return_code or not os.path.exists(output_file_path):
    logs.log_error('Failed to create ipc dump file %s.' % output)
    return None

  return output_file_path


def supports_ipc_minimization(file_path):
  """Check to see if IPC minimization is supported for the current build."""
  executable = get_ipc_message_util_executable()
  if not executable:
    # IPC fuzzer minimization is not supported on this platform.
    return False

  command_line = shell.get_command_line_from_argument_list(
      [executable, '--dump', '--in=0', file_path])
  return_code, _, output = process_handler.run_process(
      command_line, testcase_run=False, timeout=IPCDUMP_TIMEOUT)

  # If --in is not supported by this version of the ipc_message_util binary,
  # it will exit with a nonzero exit status. Also ensure that the first message
  # is printed in case the build is bad for some other reason.
  # Example output: 0. AutofillHostMsg_DidFillAutofillFormData
  if return_code or not output.startswith('0.'):
    return False

  supports_ipc_minimization.is_supported = True
  return True


def can_minimize_file(file_path):
  """Check to see if we support minimization for this file."""
  # If this is not a binary file, we should be able to minimize it in some way.
  if not utils.is_binary_file(file_path):
    return True

  # Attempt to minimize IPC dumps.
  if file_path.endswith(testcase_manager.IPCDUMP_EXTENSION):
    return supports_ipc_minimization(file_path)

  # Other binary file formats are not supported.
  return False


def do_ipc_dump_minimization(test_function, get_temp_file, file_path, deadline,
                             threads, cleanup_interval, delete_temp_files):
  """IPC dump minimization strategy."""

  def tokenize(current_file_path):
    """Generate a token list for an IPC fuzzer test case."""
    command_line = shell.get_command_line_from_argument_list(
        [get_ipc_message_util_executable(), '--dump', current_file_path])
    _, _, output = process_handler.run_process(
        command_line, testcase_run=False, timeout=IPCDUMP_TIMEOUT)
    output_lines = output.splitlines()
    if not output_lines:
      return []

    # Each output line starts with the message index followed by a ".", but
    # we are only interested in the total number of messages in the file. To
    # find this, we add one to the index of the final message.
    try:
      last_index = int(output_lines[-1].split('.')[0])
    except ValueError:
      return []

    return list(range(last_index + 1))

  def combine_tokens(tokens):
    """Use the ipc_message_util utility to create a file for these tokens."""
    partial_ipcdumps = []
    for start_index in range(0, len(tokens), TOKENS_PER_IPCDUMP):
      end_index = min(start_index + TOKENS_PER_IPCDUMP, len(tokens))
      current_tokens = tokens[start_index:end_index]
      partial_ipcdumps.append(
          create_partial_ipc_dump(current_tokens, file_path))

    combined_file_path = None
    if len(partial_ipcdumps) > 1:
      combined_file_path = combine_ipc_dumps(partial_ipcdumps, file_path)
    elif len(partial_ipcdumps) == 1:
      combined_file_path = partial_ipcdumps[0]

    if not combined_file_path:
      # This can happen in the case of a timeout or other error. The actual
      # error should already be logged, so no need to do it again here.
      return b''

    # TODO(mbarbella): Allow token combining functions to write files directly.
    handle = open(combined_file_path, 'rb')
    result = handle.read()
    handle.close()

    shell.remove_file(combined_file_path)
    return result

  current_minimizer = delta_minimizer.DeltaMinimizer(
      test_function,
      max_threads=threads,
      deadline=deadline,
      cleanup_function=process_handler.cleanup_stale_processes,
      single_thread_cleanup_interval=cleanup_interval,
      get_temp_file=get_temp_file,
      delete_temp_files=delete_temp_files,
      tokenizer=tokenize,
      token_combiner=combine_tokens,
      progress_report_function=functools.partial(logs.log))
  return current_minimizer.minimize(file_path)


def do_js_minimization(test_function, get_temp_file, data, deadline, threads,
                       cleanup_interval, delete_temp_files):
  """Javascript minimization strategy."""
  # Start by using a generic line minimizer on the test.
  # Do two line minimizations to make up for the fact that minimzations on bots
  # don't always minimize as much as they can.
  for _ in range(2):
    data = do_line_minimization(test_function, get_temp_file, data, deadline,
                                threads, cleanup_interval, delete_temp_files)

  tokenizer = AntlrTokenizer(JavaScriptLexer)

  current_minimizer = js_minimizer.JSMinimizer(
      test_function,
      max_threads=threads,
      deadline=deadline,
      cleanup_function=process_handler.cleanup_stale_processes,
      single_thread_cleanup_interval=cleanup_interval,
      get_temp_file=get_temp_file,
      delete_temp_files=delete_temp_files,
      tokenizer=tokenizer.tokenize,
      token_combiner=tokenizer.combine,
      progress_report_function=functools.partial(logs.log))

  # Some tokens can't be removed until other have, so do 2 passes.
  try:
    for _ in range(2):
      data = current_minimizer.minimize(data)
  except minimizer_errors.AntlrDecodeError:
    data = do_line_minimization(test_function, get_temp_file, data, deadline,
                                threads, cleanup_interval, delete_temp_files)

  # FIXME(mbarbella): Improve the JS minimizer so that this is not necessary.
  # Sometimes, lines that could not have been removed on their own can now be
  # removed since they have already been partially cleaned up.
  return do_line_minimization(test_function, get_temp_file, data, deadline,
                              threads, cleanup_interval, delete_temp_files)


def _run_libfuzzer_testcase(testcase, testcase_file_path, crash_retries=1):
  """Run libFuzzer testcase, and return the CrashResult."""
  # Cleanup any existing application instances and temp directories.
  process_handler.cleanup_stale_processes()
  shell.clear_temp_directory()

  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    file_host.copy_file_to_worker(
        testcase_file_path, file_host.rebase_to_worker_root(testcase_file_path))

  test_timeout = environment.get_value('TEST_TIMEOUT',
                                       process_handler.DEFAULT_TEST_TIMEOUT)
  return testcase_manager.test_for_crash_with_retries(
      testcase,
      testcase_file_path,
      test_timeout,
      compare_crash=False,
      crash_retries=crash_retries)


def run_libfuzzer_engine(tool_name, target_name, arguments, testcase_path,
                         output_path, timeout):
  """Run the libFuzzer engine."""
  arguments = list(arguments)
  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import tasks_host

    # TODO(ochang): Remove hardcode.
    return tasks_host.process_testcase('libFuzzer', tool_name, target_name,
                                       arguments, testcase_path, output_path,
                                       timeout)

  target_path = engine_common.find_fuzzer_path(
      environment.get_value('BUILD_DIR'), target_name)
  if not target_path:
    return engine.ReproduceResult([], 0, 0, '')

  engine_impl = LibFuzzerEngine()
  if tool_name == 'minimize':
    func = engine_impl.minimize_testcase
  else:
    assert tool_name == 'cleanse'
    func = engine_impl.cleanse

  return func(target_path, arguments, testcase_path, output_path, timeout)


def _run_libfuzzer_tool(tool_name,
                        testcase,
                        testcase_file_path,
                        timeout,
                        expected_crash_state,
                        set_dedup_flags=False):
  """Run libFuzzer tool to either minimize or cleanse."""
  memory_tool_options_var = environment.get_current_memory_tool_var()
  saved_memory_tool_options = environment.get_value(memory_tool_options_var)

  def _set_dedup_flags():
    """Allow libFuzzer to do its own crash comparison during minimization."""
    memory_tool_options = environment.get_memory_tool_options(
        memory_tool_options_var, default_value={})

    memory_tool_options['symbolize'] = 1
    memory_tool_options['dedup_token_length'] = 3

    environment.set_memory_tool_options(memory_tool_options_var,
                                        memory_tool_options)

  def _unset_dedup_flags():
    """Reset memory tool options."""
    # This is needed so that when we re-run, we can symbolize ourselves
    # (ignoring inline frames).
    if saved_memory_tool_options is not None:
      environment.set_value(memory_tool_options_var, saved_memory_tool_options)

  output_file_path = get_temporary_file_name(testcase_file_path)

  arguments = data_handler.get_arguments(testcase).split()
  fuzzer_display = data_handler.get_fuzzer_display(testcase)

  if set_dedup_flags:
    _set_dedup_flags()

  try:
    result = run_libfuzzer_engine(tool_name, fuzzer_display.target, arguments,
                                  testcase_file_path, output_file_path, timeout)
  except TimeoutError:
    logs.log_warn('LibFuzzer timed out.')
    return None, None

  if set_dedup_flags:
    _unset_dedup_flags()

  if not os.path.exists(output_file_path):
    logs.log_warn('LibFuzzer %s run failed.' % tool_name, output=result.output)
    return None, None

  # Ensure that the crash parameters match. It's possible that we will
  # minimize/cleanse to an unrelated bug, such as a timeout.
  crash_result = _run_libfuzzer_testcase(testcase, output_file_path)
  state = crash_result.get_symbolized_data()
  security_flag = crash_result.is_security_issue()
  if (security_flag != testcase.security_flag or
      state.crash_state != expected_crash_state):
    logs.log_warn('Ignoring unrelated crash.\n'
                  'State: %s (expected %s)\n'
                  'Security: %s (expected %s)\n'
                  'Output: %s\n' %
                  (state.crash_state, expected_crash_state, security_flag,
                   testcase.security_flag, state.crash_stacktrace))
    return None, None

  with open(output_file_path, 'rb') as file_handle:
    minimized_keys = blobs.write_blob(file_handle)

  testcase.minimized_keys = minimized_keys
  testcase.put()

  return output_file_path, crash_result


def _update_crash_result(testcase, crash_result, command):
  """Update testcase with crash result."""
  min_state = crash_result.get_symbolized_data()
  min_unsymbolized_crash_stacktrace = crash_result.get_stacktrace(
      symbolized=False)
  min_crash_stacktrace = utils.get_crash_stacktrace_output(
      command, min_state.crash_stacktrace, min_unsymbolized_crash_stacktrace)
  testcase.crash_type = min_state.crash_type
  testcase.crash_address = min_state.crash_address
  testcase.crash_state = min_state.crash_state
  testcase.crash_stacktrace = data_handler.filter_stacktrace(
      min_crash_stacktrace)


def _skip_minimization(testcase, message, crash_result=None, command=None):
  """Skip minimization for a testcase."""
  testcase = data_handler.get_testcase_by_id(testcase.key.id())
  testcase.minimized_keys = testcase.fuzzed_keys

  if crash_result:
    _update_crash_result(testcase, crash_result, command)

  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       message)
  create_additional_tasks(testcase)


def do_libfuzzer_minimization(testcase, testcase_file_path):
  """Use libFuzzer's built-in minimizer where appropriate."""
  is_overriden_job = bool(environment.get_value('ORIGINAL_JOB_NAME'))

  def handle_unreproducible():
    # Be more lenient with marking testcases as unreproducible when this is a
    # job override.
    if is_overriden_job:
      _skip_minimization(testcase, 'Unreproducible on overridden job')
    else:
      task_creation.mark_unreproducible_if_flaky(testcase, True)

  timeout = environment.get_value('LIBFUZZER_MINIMIZATION_TIMEOUT', 600)
  rounds = environment.get_value('LIBFUZZER_MINIMIZATION_ROUNDS', 5)
  current_testcase_path = testcase_file_path
  last_crash_result = None

  # Get initial crash state.
  initial_crash_result = _run_libfuzzer_testcase(
      testcase, testcase_file_path, crash_retries=None)  # Use default retries.
  if not initial_crash_result.is_crash():
    logs.log_warn('Did not crash. Output:\n' +
                  initial_crash_result.get_stacktrace(symbolized=True))
    handle_unreproducible()
    return

  if testcase.security_flag != initial_crash_result.is_security_issue():
    logs.log_warn('Security flag does not match.')
    handle_unreproducible()
    return

  task_creation.mark_unreproducible_if_flaky(testcase, False)

  expected_state = initial_crash_result.get_symbolized_data()
  logs.log('Initial crash state: %s\n' % expected_state.crash_state)

  # Minimize *_OPTIONS env variable first.
  env = {}
  for tool in environment.SUPPORTED_MEMORY_TOOLS_FOR_OPTIONS:
    options_env_var = tool + '_OPTIONS'
    options = environment.get_memory_tool_options(options_env_var)
    if not options:
      continue

    minimized_options = options.copy()
    for options_name, options_value in six.iteritems(options):
      if utils.is_oss_fuzz() and options_name in MANDATORY_OSS_FUZZ_OPTIONS:
        continue

      minimized_options.pop(options_name)
      environment.set_memory_tool_options(options_env_var, minimized_options)

      reproduced = False
      for _ in range(MINIMIZE_SANITIZER_OPTIONS_RETRIES):
        crash_result = _run_libfuzzer_testcase(testcase, testcase_file_path)
        if (crash_result.is_crash() and crash_result.is_security_issue() ==
            initial_crash_result.is_security_issue() and
            crash_result.get_type() == initial_crash_result.get_type() and
            crash_result.get_state() == initial_crash_result.get_state()):
          reproduced = True
          break

      if reproduced:
        logs.log(
            'Removed unneeded {options_env_var} option: {options_name}'.format(
                options_env_var=options_env_var, options_name=options_name))
      else:
        minimized_options[options_name] = options_value
        logs.log(
            'Skipped needed {options_env_var} option: {options_name}'.format(
                options_env_var=options_env_var, options_name=options_name),
            crash_type=crash_result.get_type(),
            crash_state=crash_result.get_state(),
            security_flag=crash_result.is_security_issue())

    environment.set_memory_tool_options(options_env_var, minimized_options)
    env[options_env_var] = environment.get_memory_tool_options(options_env_var)
  if env:
    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    testcase.set_metadata('env', env)

  # We attempt minimization multiple times in case one round results in an
  # incorrect state, or runs into another issue such as a slow unit.
  for round_number in range(1, rounds + 1):
    logs.log('Minimizing round %d.' % round_number)
    output_file_path, crash_result = _run_libfuzzer_tool(
        'minimize',
        testcase,
        current_testcase_path,
        timeout,
        expected_state.crash_state,
        set_dedup_flags=True)
    if output_file_path:
      last_crash_result = crash_result
      current_testcase_path = output_file_path

  if not last_crash_result:
    repro_command = testcase_manager.get_command_line_for_application(
        file_to_run=testcase_file_path, needs_http=testcase.http_flag)
    _skip_minimization(
        testcase,
        'LibFuzzer minimization failed',
        crash_result=initial_crash_result,
        command=repro_command)
    return

  logs.log('LibFuzzer minimization succeeded.')

  if utils.is_oss_fuzz():
    # Scrub the testcase of non-essential data.
    cleansed_testcase_path = do_libfuzzer_cleanse(
        testcase, current_testcase_path, expected_state.crash_state)
    if cleansed_testcase_path:
      current_testcase_path = cleansed_testcase_path

  # Finalize the test case if we were able to reproduce it.
  repro_command = testcase_manager.get_command_line_for_application(
      file_to_run=current_testcase_path, needs_http=testcase.http_flag)
  finalize_testcase(
      testcase.key.id(), repro_command, last_crash_result, flaky_stack=False)

  # Clean up after we're done.
  shell.clear_testcase_directories()


def do_libfuzzer_cleanse(testcase, testcase_file_path, expected_crash_state):
  """Cleanse testcase using libFuzzer."""
  timeout = environment.get_value('LIBFUZZER_CLEANSE_TIMEOUT', 180)
  output_file_path, _ = _run_libfuzzer_tool(
      'cleanse', testcase, testcase_file_path, timeout, expected_crash_state)

  if output_file_path:
    logs.log('LibFuzzer cleanse succeeded.')

  return output_file_path


def do_line_minimization(test_function, get_temp_file, data, deadline, threads,
                         cleanup_interval, delete_temp_files):
  """Line-by-line minimization strategy."""
  current_minimizer = delta_minimizer.DeltaMinimizer(
      test_function,
      max_threads=threads,
      deadline=deadline,
      cleanup_function=process_handler.cleanup_stale_processes,
      single_thread_cleanup_interval=cleanup_interval,
      get_temp_file=get_temp_file,
      delete_temp_files=delete_temp_files,
      progress_report_function=functools.partial(logs.log))
  return current_minimizer.minimize(data)


def do_html_minimization(test_function, get_temp_file, data, deadline, threads,
                         cleanup_interval, delete_temp_files):
  """HTML minimization strategy."""
  current_minimizer = html_minimizer.HTMLMinimizer(
      test_function,
      max_threads=threads,
      deadline=deadline,
      cleanup_function=process_handler.cleanup_stale_processes,
      single_thread_cleanup_interval=cleanup_interval,
      get_temp_file=get_temp_file,
      delete_temp_files=delete_temp_files,
      progress_report_function=functools.partial(logs.log))
  try:
    return current_minimizer.minimize(data)
  except minimizer_errors.AntlrDecodeError:
    return do_line_minimization(test_function, get_temp_file, data, deadline,
                                threads, cleanup_interval, delete_temp_files)


def minimize_file(file_path,
                  test_function,
                  get_temp_file,
                  data,
                  deadline,
                  threads,
                  cleanup_interval,
                  delete_temp_files=True):
  """Attempt to minimize a single file."""
  # Specialized minimization strategy for IPC dumps.
  if file_path.endswith(testcase_manager.IPCDUMP_EXTENSION):
    return do_ipc_dump_minimization(test_function, get_temp_file, file_path,
                                    deadline, threads, cleanup_interval,
                                    delete_temp_files)

  # Specialized minimization strategy for javascript.
  if file_path.endswith('.js'):
    return do_js_minimization(test_function, get_temp_file, data, deadline,
                              threads, cleanup_interval, delete_temp_files)

  if file_path.endswith('.html'):
    return do_html_minimization(test_function, get_temp_file, data, deadline,
                                threads, cleanup_interval, delete_temp_files)

  # We could not identify another strategy for this file, so use the default.
  return do_line_minimization(test_function, get_temp_file, data, deadline,
                              threads, cleanup_interval, delete_temp_files)

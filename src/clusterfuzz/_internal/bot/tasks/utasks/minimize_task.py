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
from typing import Dict
from typing import List
from typing import Optional
import zipfile

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.libFuzzer import \
    engine as libfuzzer_engine
from clusterfuzz._internal.bot.minimizer import basic_minimizers
from clusterfuzz._internal.bot.minimizer import delta_minimizer
from clusterfuzz._internal.bot.minimizer import errors as minimizer_errors
from clusterfuzz._internal.bot.minimizer import html_minimizer
from clusterfuzz._internal.bot.minimizer import js_minimizer
from clusterfuzz._internal.bot.minimizer import minimizer
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.bot.tasks.utasks import uworker_handle_errors
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.bot.tokenizer.antlr_tokenizer import AntlrTokenizer
from clusterfuzz._internal.bot.tokenizer.grammars.JavaScriptLexer import \
    JavaScriptLexer
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.common import testcase_utils
from clusterfuzz._internal.crash_analysis import severity_analyzer
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.protos import uworker_msg_pb2
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


class MinimizationPhase:
  """Effectively an enum to represent the current phase of minimization."""
  GESTURES = 0
  MAIN_FILE = 1
  FILE_LIST = 2
  RESOURCES = 3
  ARGUMENTS = 4


class TestRunner:
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
    while any(f.endswith(file_rename_suffix) for f in files_to_rename):
      index += 1
      file_rename_suffix = '___%d' % index

    # Rename all files in the test case's file list but not the specified one.
    for file_to_rename in files_to_rename:
      absolute_file_to_rename = os.path.join(self.input_directory,
                                             file_to_rename)
      try:
        os.rename(absolute_file_to_rename,
                  f'{absolute_file_to_rename}{file_rename_suffix}')
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
      os.rename(f'{absolute_file_to_rename}{file_rename_suffix}',
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
      logs.info(f'Executing command: {command}')

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


def _get_minimize_task_input(testcase):
  testcase_blob_name, testcase_upload_url = blobs.get_blob_signed_upload_url()
  (stacktrace_blob_name,
   stacktrace_upload_url) = blobs.get_blob_signed_upload_url()

  arguments = data_handler.get_arguments(testcase).split()
  return uworker_msg_pb2.MinimizeTaskInput(  # pylint: disable=no-member
      testcase_upload_url=testcase_upload_url,
      testcase_blob_name=testcase_blob_name,
      stacktrace_blob_name=stacktrace_blob_name,
      stacktrace_upload_url=stacktrace_upload_url,
      arguments=arguments)


def utask_preprocess(testcase_id, job_type, uworker_env):
  """Preprocess in a trusted bot."""
  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  with logs.testcase_log_context(testcase, testcase.get_fuzz_target()):
    # Allow setting up a different fuzzer.
    minimize_fuzzer_override = environment.get_value('MINIMIZE_FUZZER_OVERRIDE')
    setup_input = setup.preprocess_setup_testcase(
        testcase, uworker_env, fuzzer_override=minimize_fuzzer_override)

    # TODO(metzman): This should be removed.
    if not environment.is_minimization_supported():
      # TODO(ochang): More robust check for engine minimization support.
      _skip_minimization(testcase, 'Engine does not support minimization.')
      return None

    # Update comments to reflect bot information.
    data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

    uworker_input = uworker_msg_pb2.Input(  # pylint: disable=no-member
        job_type=job_type,
        testcase_id=str(testcase_id),
        testcase=uworker_io.entity_to_protobuf(testcase),
        setup_input=setup_input,
        minimize_task_input=_get_minimize_task_input(testcase),
        uworker_env=uworker_env)
    testcase_manager.preprocess_testcase_manager(testcase, uworker_input)
    return uworker_input


def utask_main(uworker_input: uworker_msg_pb2.Input):  # pylint: disable=no-member
  """Attempt to minimize a given testcase."""
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  with logs.testcase_log_context(
      testcase, testcase_manager.get_fuzz_target_from_input(uworker_input)):
    uworker_io.check_handling_testcase_safe(testcase)
    minimize_task_input = uworker_input.minimize_task_input
    # Setup testcase and its dependencies.
    file_list, testcase_file_path, uworker_error_output = setup.setup_testcase(
        testcase, uworker_input.job_type, uworker_input.setup_input)
    if uworker_error_output:
      return uworker_error_output

    # Initialize variables.
    max_timeout = environment.get_value('TEST_TIMEOUT', 10)
    app_arguments = environment.get_value('APP_ARGS')

    # Set up a custom or regular build based on revision.
    last_tested_crash_revision = testcase.get_metadata(
        'last_tested_crash_revision')

    crash_revision = last_tested_crash_revision or testcase.crash_revision
    fuzz_target = testcase_manager.get_fuzz_target_from_input(uworker_input)
    fuzz_target = fuzz_target.binary if fuzz_target else None
    build_setup_result = build_manager.setup_build(crash_revision, fuzz_target)

    # Check if we have an application path. If not, our build failed
    # to setup correctly.
    if not build_setup_result or not build_manager.check_app_path():
      logs.error('Unable to setup build for minimization.')
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.ErrorType.MINIMIZE_SETUP)  # pylint: disable=no-member

    if environment.is_libfuzzer_job():
      fuzz_target = testcase_manager.get_fuzz_target_from_input(uworker_input)
      return do_libfuzzer_minimization(fuzz_target, minimize_task_input,
                                       testcase, testcase_file_path)

    if environment.is_engine_fuzzer_job():
      logs.error(
          'Engine does not support minimization. Something went wrong as this'
          ' should have been detected in preprocess.')
      return None

    # TODO(alhijazi): re-install multithreaded runs
    # max_threads = utils.maximum_parallel_processes_allowed()
    # Temporarily run minimization single threaded.
    max_threads = 1

    # Prepare the test case runner.
    crash_retries = environment.get_value('CRASH_RETRIES')
    warmup_timeout = environment.get_value('WARMUP_TIMEOUT')
    required_arguments = environment.get_value('REQUIRED_APP_ARGS', '')

    logs.info('Warming up for minimization, checking for crashes ' +
              f'(thread count: {max_threads}).')

    # Add any testcase-specific required arguments if needed.
    additional_required_arguments = testcase.get_metadata(
        'additional_required_app_args')
    if additional_required_arguments:
      required_arguments = (f'{required_arguments} '
                            f'{additional_required_arguments}')

    input_directory = environment.get_value('FUZZ_INPUTS')
    # Get deadline to finish this task.
    deadline = tasks.get_task_completion_deadline()
    test_runner = TestRunner(testcase, testcase_file_path, file_list,
                             input_directory, app_arguments, required_arguments,
                             max_threads, deadline)

    # Verify the crash with a long timeout.
    warmup_crash_occurred = False
    result = test_runner.run(timeout=warmup_timeout, log_command=True)
    if result.is_crash():
      warmup_crash_occurred = True
      logs.info(f'Warmup crash occurred in {result.crash_time} seconds.')

    saved_unsymbolized_crash_state, flaky_stack, crash_times = (
        check_for_initial_crash(test_runner, crash_retries, testcase))
    logs.info(f'Warmup crashed {crash_times}/{crash_retries} times.')

    # If the warmup crash occurred but we couldn't reproduce this in with
    # multiple processes running in parallel, try to minimize single threaded.
    reproducible_crash_count = (
        testcase_manager.REPRODUCIBILITY_FACTOR * crash_retries)
    if (len(crash_times) < reproducible_crash_count and
        warmup_crash_occurred and max_threads > 1):
      logs.info('Attempting to continue single-threaded.')

      max_threads = 1
      test_runner = TestRunner(testcase, testcase_file_path, file_list,
                               input_directory, app_arguments,
                               required_arguments, max_threads, deadline)

      saved_unsymbolized_crash_state, flaky_stack, crash_times = (
          check_for_initial_crash(test_runner, crash_retries, testcase))
      logs.info(f'Single-threaded warmup crashed {crash_times} times.')

    if not crash_times:
      # We didn't crash at all. This might be a legitimately unreproducible
      # test case, so it will get marked as such after being retried on other
      # bots.
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.ErrorType.MINIMIZE_UNREPRODUCIBLE_CRASH)  # pylint: disable=no-member

    minimize_task_output = uworker_msg_pb2.MinimizeTaskOutput()  # pylint: disable=no-member

    if flaky_stack:
      testcase.flaky_stack = flaky_stack
      minimize_task_output.flaky_stack = flaky_stack

    is_redo = testcase.get_metadata('redo_minimize')
    if not is_redo and len(crash_times) < reproducible_crash_count:
      error_message = (
          'Crash occurs, but not too consistently. Skipping minimization '
          f'(crashed {len(crash_times)}/{crash_retries})')
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_message=error_message,
          minimize_task_output=minimize_task_output,
          error_type=uworker_msg_pb2.ErrorType.MINIMIZE_CRASH_TOO_FLAKY)  # pylint: disable=no-member

    test_runner.set_test_expectations(testcase.security_flag, flaky_stack,
                                      saved_unsymbolized_crash_state)

    # Use the max crash time unless this would be greater than the max timeout.
    test_timeout = min(max(crash_times), max_timeout) + 1
    logs.info(f'Using per-test timeout {test_timeout} (was {max_timeout})')
    test_runner.timeout = test_timeout

    logs.info(f'Starting minimization with overall {deadline}s timeout.')

    if should_attempt_phase(testcase, MinimizationPhase.GESTURES):
      logs.info('Starting gesture minimization phase.')
      gestures = minimize_gestures(test_runner, testcase)

      # At this point, we do not have a test case to store, so we can't call
      # check_deadline_exceeded_and_store_partial_minimized_testcase.

      if testcase.security_flag and len(testcase.gestures) != len(gestures):
        # Re-run security severity analysis since gestures affect the severity.
        testcase.security_severity = severity_analyzer.get_security_severity(
            testcase.crash_type, data_handler.get_stacktrace(testcase),
            uworker_input.job_type, bool(gestures))
        minimize_task_output.security_severity_updated = True
        if testcase.security_severity is not None:
          minimize_task_output.security_severity = testcase.security_severity

      testcase.gestures = gestures
      del minimize_task_output.gestures[:]
      minimize_task_output.gestures.extend(gestures)
      testcase.set_metadata('minimization_phase', MinimizationPhase.MAIN_FILE,
                            False)
      minimize_task_output.minimization_phase = MinimizationPhase.MAIN_FILE

      if time.time() > test_runner.deadline:
        logs.info('Timed out during gesture minimization.')
        return uworker_msg_pb2.Output(  # pylint: disable=no-member
            minimize_task_output=minimize_task_output,
            error_type=uworker_msg_pb2.ErrorType.  # pylint: disable=no-member
            MINIMIZE_DEADLINE_EXCEEDED_IN_MAIN_FILE_PHASE,
            error_message='Timed out during gesture minimization.')

      logs.info('Minimized gestures.')

    # Minimize the main file.
    data = utils.get_file_contents_with_fatal_error_on_failure(
        testcase_file_path)
    if should_attempt_phase(testcase, MinimizationPhase.MAIN_FILE):
      logs.info('Starting main file minimization phase.')
      data = minimize_main_file(test_runner, testcase_file_path, data)

      if check_deadline_exceeded_and_store_partial_minimized_testcase(
          deadline, testcase, input_directory, file_list, data,
          testcase_file_path, minimize_task_input, minimize_task_output):
        logs.info('Timed out during main file minimization.')
        return uworker_msg_pb2.Output(  # pylint: disable=no-member
            error_type=uworker_msg_pb2.ErrorType.MINIMIZE_DEADLINE_EXCEEDED,  # pylint: disable=no-member
            error_message='Timed out during main file minimization.',
            minimize_task_output=minimize_task_output)

      logs.info('Minimized main file.')
      testcase.set_metadata('minimization_phase', MinimizationPhase.FILE_LIST,
                            False)
      minimize_task_output.minimization_phase = MinimizationPhase.FILE_LIST

    # Minimize the file list.
    if should_attempt_phase(testcase, MinimizationPhase.FILE_LIST):
      if environment.get_value('MINIMIZE_FILE_LIST', True):
        logs.info('Starting file list minimization phase.')
        file_list = minimize_file_list(test_runner, file_list, input_directory,
                                       testcase_file_path)

        if check_deadline_exceeded_and_store_partial_minimized_testcase(
            deadline, testcase, input_directory, file_list, data,
            testcase_file_path, minimize_task_input, minimize_task_output):
          logs.info('Timed out during file list minimization.')
          return uworker_msg_pb2.Output(  # pylint: disable=no-member
              error_type=uworker_msg_pb2.ErrorType.MINIMIZE_DEADLINE_EXCEEDED,  # pylint: disable=no-member
              error_message='Timed out during file list minimization.',
              minimize_task_output=minimize_task_output)
        logs.info('Minimized file list.')
      else:
        logs.info('Skipping minimization of file list.')

      testcase.set_metadata('minimization_phase', MinimizationPhase.RESOURCES,
                            False)
      minimize_task_output.minimization_phase = MinimizationPhase.RESOURCES

    # Minimize any files remaining in the file list.
    if should_attempt_phase(testcase, MinimizationPhase.RESOURCES):
      if environment.get_value('MINIMIZE_RESOURCES', True):
        logs.info('Starting resources minimization phase.')
        for dependency in file_list:
          minimize_resource(test_runner, dependency, input_directory,
                            testcase_file_path)

          if check_deadline_exceeded_and_store_partial_minimized_testcase(
              deadline, testcase, input_directory, file_list, data,
              testcase_file_path, minimize_task_input, minimize_task_output):
            logs.info('Timed out during resources minimization.')
            return uworker_msg_pb2.Output(  # pylint: disable=no-member
                error_type=uworker_msg_pb2.ErrorType.MINIMIZE_DEADLINE_EXCEEDED,  # pylint: disable=no-member
                error_message='Timed out during resources minimization.',
                minimize_task_output=minimize_task_output)

        logs.info('Minimized resources.')
      else:
        logs.info('Skipping minimization of resources.')

      testcase.set_metadata('minimization_phase', MinimizationPhase.ARGUMENTS,
                            False)
      minimize_task_output.minimization_phase = MinimizationPhase.ARGUMENTS

    if should_attempt_phase(testcase, MinimizationPhase.ARGUMENTS):
      logs.info('Starting arguments minimization phase.')
      app_arguments = minimize_arguments(test_runner, app_arguments)

      # Arguments must be stored here in case we time out below.
      testcase.minimized_arguments = app_arguments
      minimize_task_output.minimized_arguments = app_arguments

      if check_deadline_exceeded_and_store_partial_minimized_testcase(
          deadline, testcase, input_directory, file_list, data,
          testcase_file_path, minimize_task_input, minimize_task_output):
        logs.info('Timed out during arguments minimization.')
        return uworker_msg_pb2.Output(  # pylint: disable=no-member
            error_type=uworker_msg_pb2.ErrorType.MINIMIZE_DEADLINE_EXCEEDED,  # pylint: disable=no-member
            error_message='Timed out during arguments minimization.',
            minimize_task_output=minimize_task_output)

      logs.info('Minimized arguments.')

    logs.info('Finished minization.')

    command = testcase_manager.get_command_line_for_application(
        testcase_file_path,
        app_args=app_arguments,
        needs_http=testcase.http_flag)
    last_crash_result = test_runner.last_failing_result

    store_minimized_testcase(testcase, input_directory, file_list, data,
                             testcase_file_path, minimize_task_input,
                             minimize_task_output)

    minimize_task_output.last_crash_result_dict.clear()
    minimize_task_output.last_crash_result_dict.update(
        _extract_crash_result(last_crash_result, command, minimize_task_input))

    return uworker_msg_pb2.Output(minimize_task_output=minimize_task_output)  # pylint: disable=no-member


def _cleanup_unused_blobs_from_storage(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Cleanup the blobs created in preprocess if they weren't used during
  utask_main."""
  delete_testcase_blob = True
  delete_stacktrace_blob = True

  if output.HasField('minimize_task_output'):
    # If minimized_keys was set, we should not cleanup the corresponding blob.
    if output.minimize_task_output.HasField("minimized_keys"):
      delete_testcase_blob = False

    stacktrace_blob_key = output.minimize_task_output.last_crash_result_dict[
        'crash_stacktrace']
    if stacktrace_blob_key.startswith(data_types.BLOBSTORE_STACK_PREFIX):
      delete_stacktrace_blob = False

  testcase_blob_name = (
      output.uworker_input.minimize_task_input.testcase_blob_name)
  stacktrace_blob_name = (
      output.uworker_input.minimize_task_input.stacktrace_blob_name)
  if delete_testcase_blob:
    blobs.delete_blob(testcase_blob_name)
  if delete_stacktrace_blob:
    blobs.delete_blob(stacktrace_blob_name)


def update_testcase(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Updates the tescase using the values passed from utask_main. This is done
  at the beginning of utask_postprocess and before error handling is called."""
  if not output.HasField('minimize_task_output'):
    return

  minimize_task_output = output.minimize_task_output
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)

  _update_testcase_memory_tool_options(testcase,
                                       minimize_task_output.memory_tool_options)

  if minimize_task_output.security_severity_updated:
    if minimize_task_output.HasField('security_severity'):
      testcase.security_severity = minimize_task_output.security_severity
    else:
      testcase.security_severity = None

  if minimize_task_output.HasField('minimization_phase'):
    testcase.set_metadata('minimization_phase',
                          minimize_task_output.minimization_phase)

  if minimize_task_output.flaky_stack:
    testcase.flaky_stack = minimize_task_output.flaky_stack

  if minimize_task_output.HasField('minimized_arguments'):
    testcase.minimized_arguments = minimize_task_output.minimized_arguments

  if minimize_task_output.HasField('archive_state'):
    testcase.archive_state = minimize_task_output.archive_state

  if minimize_task_output.HasField('absolute_path'):
    testcase.absolute_path = minimize_task_output.absolute_path

  if minimize_task_output.gestures:
    # One must convert repeated fields to lists in order to save them using ndb.
    testcase.gestures = list(minimize_task_output.gestures)

  if minimize_task_output.HasField('minimized_keys'):
    testcase.minimized_keys = minimize_task_output.minimized_keys

  testcase.put()


def handle_minimize_setup_error(output):
  """Handles errors occuring during setup."""
  build_fail_wait = environment.get_value('FAIL_WAIT')

  if environment.get_value('ORIGINAL_JOB_NAME'):
    testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
    _skip_minimization(testcase, 'Failed to setup build for overridden job.')
  else:
    # Only recreate task if this isn't an overriden job. It's possible that a
    # revision exists for the original job, but doesn't exist for the
    # overriden job.
    build_fail_wait = environment.get_value('FAIL_WAIT')
    tasks.add_task(
        'minimize',
        output.uworker_input.testcase_id,
        output.uworker_input.job_type,
        wait_time=build_fail_wait)


def handle_minimize_unreproducible_crash(output):
  """Handles unreproducible crashes."""
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       'Unable to reproduce crash')
  task_creation.mark_unreproducible_if_flaky(testcase, 'minimize', True)


def handle_minimize_crash_too_flaky(output):
  """Schedules postminimize tasks when the crash is too flaky."""
  # We reproduced this crash at least once. It's too flaky to minimize, but
  # maybe we'll have more luck in the other jobs.
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  testcase.minimized_keys = 'NA'

  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)
  task_creation.create_postminimize_tasks(testcase)


def handle_minimize_deadline_exceeded_in_main_file_phase(output):
  """Reschedules the minimize task when the deadline is exceeded just before
  starting the main file phase."""
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(
      testcase, data_types.TaskState.WIP,
      'Timed out before even minimizing the main file. Retrying.')
  tasks.add_task('minimize', output.uworker_input.testcase_id,
                 output.uworker_input.job_type)


def handle_minimize_deadline_exceeded(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Reschedules a minimize task when minimization deadline is exceeded or
  calls _skip_minimization when the number of reattempts is surpassed."""
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  attempts = testcase.get_metadata(
      'minimization_deadline_exceeded_attempts', default=0)
  if attempts >= MAX_DEADLINE_EXCEEDED_ATTEMPTS:
    _skip_minimization(testcase,
                       'Exceeded minimization deadline too many times.')
  else:
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.WIP,
        output.error_message + f' Retrying (attempt #{attempts + 1}).')
    testcase.set_metadata('minimization_deadline_exceeded_attempts',
                          attempts + 1)
    tasks.add_task('minimize', output.uworker_input.testcase_id,
                   output.uworker_input.job_type)


def handle_libfuzzer_minimization_unreproducible(
    output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Handles libfuzzer minimization task's failure to reproduce the issue."""
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  # Be more lenient with marking testcases as unreproducible when this is a
  # job override.
  is_overriden_job = bool(environment.get_value('ORIGINAL_JOB_NAME'))
  if is_overriden_job:
    _skip_minimization(testcase, 'Unreproducible on overridden job')
  else:
    task_creation.mark_unreproducible_if_flaky(testcase, 'minimize', True)


def handle_libfuzzer_minimization_failed(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Handles libfuzzer minimization task failure."""
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  _skip_minimization(
      testcase,
      'LibFuzzer minimization failed',
      crash_result_dict=output.minimize_task_output.last_crash_result_dict)


_ERROR_HANDLER = uworker_handle_errors.CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.LIBFUZZER_MINIMIZATION_FAILED:  # pylint: disable=no-member
        handle_libfuzzer_minimization_failed,
    uworker_msg_pb2.ErrorType.LIBFUZZER_MINIMIZATION_UNREPRODUCIBLE:  # pylint: disable=no-member
        handle_libfuzzer_minimization_unreproducible,
    uworker_msg_pb2.ErrorType.MINIMIZE_CRASH_TOO_FLAKY:  # pylint: disable=no-member
        handle_minimize_crash_too_flaky,
    uworker_msg_pb2.ErrorType.MINIMIZE_DEADLINE_EXCEEDED:  # pylint: disable=no-member
        handle_minimize_deadline_exceeded,
    uworker_msg_pb2.ErrorType.MINIMIZE_DEADLINE_EXCEEDED_IN_MAIN_FILE_PHASE:  # pylint: disable=no-member
        handle_minimize_deadline_exceeded_in_main_file_phase,
    uworker_msg_pb2.ErrorType.MINIMIZE_SETUP:  # pylint: disable=no-member
        handle_minimize_setup_error,
    uworker_msg_pb2.ErrorType.MINIMIZE_UNREPRODUCIBLE_CRASH:  # pylint: disable=no-member
        handle_minimize_unreproducible_crash,
}).compose_with(
    setup.ERROR_HANDLER,
    uworker_handle_errors.UNHANDLED_ERROR_HANDLER,
)


def finalize_testcase(testcase_id, last_crash_result_dict, flaky_stack=False):
  """Perform final updates on a test case and prepare it for other tasks."""
  # Symbolize crash output if we have it.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if last_crash_result_dict:
    _update_crash_result(testcase, last_crash_result_dict)
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

  task_creation.create_postminimize_tasks(testcase)


def utask_postprocess(output):
  """Postprocess in a trusted bot."""
  # Retrive the testcase early for logs context.
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  with logs.testcase_log_context(testcase, testcase.get_fuzz_target()):
    testcase_utils.emit_testcase_triage_duration_metric(
        int(output.uworker_input.testcase_id),
        testcase_utils.TESTCASE_TRIAGE_DURATION_MINIMIZE_COMPLETED_STEP)
    update_testcase(output)
    _cleanup_unused_blobs_from_storage(output)
    if output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
      _ERROR_HANDLER.handle(output)
      return

    finalize_testcase(
        output.uworker_input.testcase_id,
        output.minimize_task_output.last_crash_result_dict,
        flaky_stack=output.minimize_task_output.flaky_stack)


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
        progress_report_function=logs.info)
    gestures = gesture_minimizer.minimize(gestures)

  logs.info(f'Minimized gestures: {str(gestures)}')
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

  logs.info('Minimized main test file.')
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
      progress_report_function=logs.info)
  file_list = file_list_minimizer.minimize(file_list)

  if fixed_testcase_file_path not in file_list:
    file_list.append(fixed_testcase_file_path)

  logs.info(f'Minimized file list: {str(file_list)}')
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

  logs.info(f'Minimized dependency file: {dependency}')


def minimize_arguments(test_runner, app_arguments):
  """Minimize the argument list for a test case."""
  argument_minimizer = delta_minimizer.DeltaMinimizer(
      test_runner.test_with_command_line_arguments,
      max_threads=test_runner.threads,
      tokenize=False,
      deadline=test_runner.deadline,
      cleanup_function=process_handler.cleanup_stale_processes,
      single_thread_cleanup_interval=test_runner.cleanup_interval,
      progress_report_function=logs.info)
  reduced_args = argument_minimizer.minimize(app_arguments.split())
  reduced_arg_string = test_runner.get_argument_string(reduced_args)

  return reduced_arg_string


def store_minimized_testcase(
    testcase: data_types.Testcase,
    base_directory: str,
    file_list: List[str],
    file_to_run_data: str,
    file_to_run: str,
    minimize_task_input: uworker_msg_pb2.MinimizeTaskInput,  # pylint: disable=no-member
    minimize_task_output: uworker_msg_pb2.MinimizeTaskOutput):  # pylint: disable=no-member
  """Store all files that make up this testcase."""
  # Write the main file data.
  utils.write_data_to_file(file_to_run_data, file_to_run)

  # Prepare the file.
  zip_path = None
  if testcase.archive_state:
    if len(file_list) > 1:
      testcase.archive_state |= data_types.ArchiveStatus.MINIMIZED
      minimize_task_output.archive_state = testcase.archive_state
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
          minimize_task_output.absolute_path = testcase.absolute_path
          testcase.archive_state &= ~data_types.ArchiveStatus.MINIMIZED
          minimize_task_output.archive_state = testcase.archive_state
      except OSError:
        logs.error('Unable to open archive for blobstore write.')
        return
    else:
      absolute_filename = os.path.join(base_directory, file_list[0])
      file_handle = open(absolute_filename, 'rb')
      testcase.archive_state &= ~data_types.ArchiveStatus.MINIMIZED
      minimize_task_output.archive_state = testcase.archive_state
  else:
    file_handle = open(file_list[0], 'rb')
    testcase.archive_state &= ~data_types.ArchiveStatus.MINIMIZED
    minimize_task_output.archive_state = testcase.archive_state

  # Store the testcase.
  data = file_handle.read()
  storage.upload_signed_url(data, minimize_task_input.testcase_upload_url)
  minimized_keys = minimize_task_input.testcase_blob_name
  file_handle.close()

  testcase.minimized_keys = minimized_keys
  minimize_task_output.minimized_keys = minimized_keys

  if zip_path:
    shell.remove_file(zip_path)


def check_deadline_exceeded_and_store_partial_minimized_testcase(
    deadline,
    testcase: data_types.Testcase,
    input_directory: str,
    file_list,
    file_to_run_data,
    main_file_path: str,
    minimize_task_input: uworker_msg_pb2.MinimizeTaskInput,  # pylint: disable=no-member
    minimize_task_output: uworker_msg_pb2.MinimizeTaskOutput) -> bool:  # pylint: disable=no-member
  """Store the partially minimized test and check the deadline."""
  store_minimized_testcase(testcase, input_directory, file_list,
                           file_to_run_data, main_file_path,
                           minimize_task_input, minimize_task_output)

  return time.time() > deadline


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

  logs.info(f'Total crash count: {len(crash_times)}/{crash_retries}.'
            f'Flaky: {flaky_stack}. Security: {saved_security_flag}.'
            f'State:\n{saved_crash_state}')

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
    logs.error('Failed to create ipc dump file %s.' % output)
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
    logs.error('Failed to create ipc dump file %s.' % output)
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
      progress_report_function=logs.info)
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
      progress_report_function=logs.info)

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


def _run_libfuzzer_testcase(fuzz_target,
                            testcase: data_types.Testcase,
                            testcase_file_path: str,
                            crash_retries: int = 1) -> CrashResult:
  """Run libFuzzer testcase, and return the CrashResult."""
  # Cleanup any existing application instances and temp directories.
  process_handler.cleanup_stale_processes()
  shell.clear_temp_directory()

  test_timeout = environment.get_value('TEST_TIMEOUT',
                                       process_handler.DEFAULT_TEST_TIMEOUT)
  return testcase_manager.test_for_crash_with_retries(
      fuzz_target,
      testcase,
      testcase_file_path,
      test_timeout,
      compare_crash=False,
      crash_retries=crash_retries)


def run_libfuzzer_engine(tool_name, target_name, arguments, testcase_path,
                         output_path, timeout):
  """Run the libFuzzer engine."""
  target_path = engine_common.find_fuzzer_path(
      environment.get_value('BUILD_DIR'), target_name)
  if not target_path:
    return engine.ReproduceResult([], 0, 0, '')

  engine_impl = libfuzzer_engine.Engine()
  if tool_name == 'minimize':
    func = engine_impl.minimize_testcase
  else:
    assert tool_name == 'cleanse'
    func = engine_impl.cleanse

  return func(target_path, list(arguments), testcase_path, output_path, timeout)


def _run_libfuzzer_tool(
    tool_name: str,
    testcase: data_types.Testcase,
    testcase_file_path: str,
    timeout: int,
    expected_crash_state: str,
    minimize_task_input: uworker_msg_pb2.MinimizeTaskInput,  # pylint: disable=no-member
    fuzz_target: Optional[data_types.FuzzTarget],
    set_dedup_flags: bool = False
) -> tuple[str, CrashResult, str] | tuple[None, None, None]:
  """Run libFuzzer tool to either minimize or cleanse.

  Returns (None, None, None) in case of failure.
  Otherwise sets `testcase.minimized_keys` and returns:

    (testcase_file_path, crash_result, minimized_keys)

  """
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
  fuzzer_display = data_handler.get_fuzzer_display_unprivileged(
      testcase, fuzz_target)

  if set_dedup_flags:
    _set_dedup_flags()

  try:
    result = run_libfuzzer_engine(tool_name, fuzzer_display.target,
                                  minimize_task_input.arguments,
                                  testcase_file_path, output_file_path, timeout)
  except TimeoutError:
    logs.warning('LibFuzzer timed out.')
    return None, None, None

  if set_dedup_flags:
    _unset_dedup_flags()

  if not os.path.exists(output_file_path):
    logs.warning(f'LibFuzzer {tool_name} run failed.', output=result.output)
    return None, None, None

  # Ensure that the crash parameters match. It's possible that we will
  # minimize/cleanse to an unrelated bug, such as a timeout.
  crash_result = _run_libfuzzer_testcase(fuzz_target, testcase,
                                         output_file_path)
  state = crash_result.get_symbolized_data()
  security_flag = crash_result.is_security_issue()
  if (security_flag != testcase.security_flag or
      state.crash_state != expected_crash_state):
    logs.warning(
        'Ignoring unrelated crash.\n'
        f'State: {state.crash_state} (expected {expected_crash_state})\n'
        f'Security: {security_flag} (expected {testcase.security_flag})\n'
        f'Output: {state.crash_stacktrace}\n')
    return None, None, None

  with open(output_file_path, 'rb') as file_handle:
    data = file_handle.read()
    storage.upload_signed_url(data, minimize_task_input.testcase_upload_url)
    minimized_keys = minimize_task_input.testcase_blob_name

  testcase.minimized_keys = minimized_keys

  return output_file_path, crash_result, minimized_keys


def _extract_crash_result(crash_result, command, minimize_task_input):
  """Extract necessary data from CrashResult."""
  if not crash_result:
    raise errors.BadStateError(
        'No crash result was provided to _extract_crash_result')
  min_state = crash_result.get_symbolized_data()
  min_unsymbolized_crash_stacktrace = crash_result.get_stacktrace(
      symbolized=False)
  min_crash_stacktrace = utils.get_crash_stacktrace_output(
      command, min_state.crash_stacktrace, min_unsymbolized_crash_stacktrace)
  return {
      'crash_type':
          min_state.crash_type,
      'crash_address':
          min_state.crash_address,
      'crash_state':
          min_state.crash_state,
      'crash_stacktrace':
          data_handler.filter_stacktrace(
              min_crash_stacktrace, minimize_task_input.stacktrace_blob_name,
              minimize_task_input.stacktrace_upload_url),
  }


def _update_crash_result(testcase, crash_result_dict):
  """Update testcase with crash result."""
  testcase.crash_type = crash_result_dict['crash_type']
  testcase.crash_address = crash_result_dict['crash_address']
  testcase.crash_state = crash_result_dict['crash_state']
  testcase.crash_stacktrace = crash_result_dict['crash_stacktrace']


def _skip_minimization(testcase: data_types.Testcase,
                       message: str,
                       crash_result_dict: Dict[str, str] = None):
  """Skip minimization for a testcase, only called during postrocess."""
  testcase.minimized_keys = testcase.fuzzed_keys

  if crash_result_dict:
    _update_crash_result(testcase, crash_result_dict)

  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       message)
  task_creation.create_postminimize_tasks(testcase)


def _update_testcase_memory_tool_options(testcase: data_types.Testcase,
                                         memory_tool_options: Dict[str, str]):
  """Updates the testcase metadata env with the values set during utask_main."""
  env = {}
  for key, value in memory_tool_options.items():
    environment.set_value(key, value)
    env[key] = environment.get_memory_tool_options(key)

  if env:
    testcase.set_metadata('env', env, False)


def do_libfuzzer_minimization(
    fuzz_target: Optional[data_types.FuzzTarget],
    minimize_task_input: uworker_msg_pb2.MinimizeTaskInput,  # pylint: disable=no-member
    testcase: data_types.Testcase,
    testcase_file_path: str) -> uworker_msg_pb2.Output:  # pylint: disable=no-member
  """Use libFuzzer's built-in minimizer where appropriate."""
  timeout = environment.get_value('LIBFUZZER_MINIMIZATION_TIMEOUT', 600)
  rounds = environment.get_value('LIBFUZZER_MINIMIZATION_ROUNDS', 5)

  # Get initial crash state.
  initial_crash_result = _run_libfuzzer_testcase(
      fuzz_target, testcase, testcase_file_path,
      crash_retries=None)  # Use default retries.
  if not initial_crash_result.is_crash():
    logs.warning('Did not crash. Output:\n' +
                 initial_crash_result.get_stacktrace(symbolized=True))
    return uworker_msg_pb2.Output(error_type=uworker_msg_pb2.ErrorType.  # pylint: disable=no-member
                                  LIBFUZZER_MINIMIZATION_UNREPRODUCIBLE)

  if testcase.security_flag != initial_crash_result.is_security_issue():
    logs.warning('Security flag does not match.')
    return uworker_msg_pb2.Output(error_type=uworker_msg_pb2.ErrorType.  # pylint: disable=no-member
                                  LIBFUZZER_MINIMIZATION_UNREPRODUCIBLE)  # pylint: disable=no-member

  expected_state = initial_crash_result.get_symbolized_data()
  logs.info(f'Initial crash state: {expected_state.crash_state}\n')

  # Minimize *_OPTIONS env variable first.
  env = {}
  # A Dict[str, str] potentially containing options_env_var strings and the
  #  corresponding minimized_options_string to be parsed and set in testcase
  #  metadata during postprocess.
  memory_tool_options = {}
  for tool in environment.SUPPORTED_MEMORY_TOOLS_FOR_OPTIONS:
    options_env_var = tool + '_OPTIONS'
    options = environment.get_memory_tool_options(options_env_var)
    if not options:
      continue

    minimized_options = options.copy()
    for options_name, options_value in options.items():
      if utils.is_oss_fuzz() and options_name in MANDATORY_OSS_FUZZ_OPTIONS:
        continue

      minimized_options.pop(options_name)
      environment.set_memory_tool_options(options_env_var, minimized_options)

      reproduced = False
      for _ in range(MINIMIZE_SANITIZER_OPTIONS_RETRIES):
        crash_result = _run_libfuzzer_testcase(fuzz_target, testcase,
                                               testcase_file_path)
        if (crash_result.is_crash() and crash_result.is_security_issue() ==
            initial_crash_result.is_security_issue() and
            crash_result.get_type() == initial_crash_result.get_type() and
            crash_result.get_state() == initial_crash_result.get_state()):
          reproduced = True
          break

      if reproduced:
        logs.info(
            'Removed unneeded {options_env_var} option: {options_name}'.format(
                options_env_var=options_env_var, options_name=options_name))
      else:
        minimized_options[options_name] = options_value
        logs.info(
            'Skipped needed {options_env_var} option: {options_name}'.format(
                options_env_var=options_env_var, options_name=options_name),
            crash_type=crash_result.get_type(),
            crash_state=crash_result.get_state(),
            security_flag=crash_result.is_security_issue())

    environment.set_memory_tool_options(options_env_var, minimized_options)
    env[options_env_var] = environment.get_memory_tool_options(options_env_var)
    memory_tool_options[options_env_var] = environment.join_memory_tool_options(
        minimized_options)
  if env:
    testcase.set_metadata('env', env, False)

  current_testcase_path = testcase_file_path
  last_crash_result = None
  last_minimized_keys = None

  # We attempt minimization multiple times in case one round results in an
  # incorrect state, or runs into another issue such as a slow unit.
  for round_number in range(1, rounds + 1):
    logs.info(f'Minimizing round {round_number}.')
    output_file_path, crash_result, minimized_keys = _run_libfuzzer_tool(
        'minimize',
        testcase,
        current_testcase_path,
        timeout,
        expected_state.crash_state,
        minimize_task_input,
        fuzz_target,
        set_dedup_flags=True)
    if output_file_path:
      last_crash_result = crash_result
      last_minimized_keys = minimized_keys
      current_testcase_path = output_file_path

  if not last_crash_result:
    repro_command = testcase_manager.get_command_line_for_application(
        file_to_run=testcase_file_path, needs_http=testcase.http_flag)
    crash_result_dict = _extract_crash_result(
        initial_crash_result, repro_command, minimize_task_input)
    minimize_task_output = uworker_msg_pb2.MinimizeTaskOutput(  # pylint: disable=no-member
        last_crash_result_dict=crash_result_dict,
        memory_tool_options=memory_tool_options)
    if last_minimized_keys:
      minimize_task_output.minimized_keys = str(last_minimized_keys)
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_type=uworker_msg_pb2.ErrorType.LIBFUZZER_MINIMIZATION_FAILED,  # pylint: disable=no-member
        minimize_task_output=minimize_task_output)

  logs.info('LibFuzzer minimization succeeded.')

  if utils.is_oss_fuzz():
    # Scrub the testcase of non-essential data.
    cleansed_testcase_path, last_minimized_keys = do_libfuzzer_cleanse(
        fuzz_target, testcase, current_testcase_path,
        expected_state.crash_state, minimize_task_input)
    if cleansed_testcase_path:
      current_testcase_path = cleansed_testcase_path

  # Finalize the test case if we were able to reproduce it.
  repro_command = testcase_manager.get_command_line_for_application(
      file_to_run=current_testcase_path, needs_http=testcase.http_flag)
  last_crash_result_dict = _extract_crash_result(
      last_crash_result, repro_command, minimize_task_input)

  # Clean up after we're done.
  shell.clear_testcase_directories()
  minimize_task_output = uworker_msg_pb2.MinimizeTaskOutput(  # pylint: disable=no-member
      last_crash_result_dict=last_crash_result_dict,
      memory_tool_options=memory_tool_options)
  if last_minimized_keys:
    minimize_task_output.minimized_keys = str(last_minimized_keys)
  return uworker_msg_pb2.Output(minimize_task_output=minimize_task_output)  # pylint: disable=no-member


def do_libfuzzer_cleanse(fuzz_target: Optional[data_types.FuzzTarget], testcase,
                         testcase_file_path, expected_crash_state,
                         minimize_task_input):
  """Cleanse testcase using libFuzzer."""
  timeout = environment.get_value('LIBFUZZER_CLEANSE_TIMEOUT', 180)
  output_file_path, _, minimized_keys = _run_libfuzzer_tool(
      'cleanse', testcase, testcase_file_path, timeout, expected_crash_state,
      minimize_task_input, fuzz_target)

  if output_file_path:
    logs.info('LibFuzzer cleanse succeeded.')

  return output_file_path, minimized_keys


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
      progress_report_function=logs.info)
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
      progress_report_function=logs.info)
  try:
    logs.info('Launching html minimization.')
    return current_minimizer.minimize(data)
  except minimizer_errors.AntlrDecodeError:
    logs.info('Launching line minimization.')
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

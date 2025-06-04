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
"""Symbolize task.
   Add stack traces from non-optimized release and debug builds."""

import os

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.bot.tasks.utasks import uworker_handle_errors
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler

DEFAULT_REDZONE = 128
MAX_REDZONE = 1024
MIN_REDZONE = 16
STACK_FRAME_COUNT = 128


def handle_build_setup_error(output):
  testcase_id = output.uworker_input.testcase_id
  job_type = output.uworker_input.job_type
  testcase = data_handler.get_testcase_by_id(testcase_id)
  build_fail_wait = environment.get_value('FAIL_WAIT')
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       'Build setup failed')
  tasks.add_task('symbolize', testcase_id, job_type, wait_time=build_fail_wait)


def _utask_preprocess(testcase_id, job_type, uworker_env):
  """Run preprocessing for symbolize task."""
  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)

  # We should atleast have a symbolized debug or release build.
  if not build_manager.has_symbolized_builds():
    return None

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  # Setup testcase and its dependencies.
  setup_input = setup.preprocess_setup_testcase(testcase, uworker_env)

  old_crash_stacktrace = data_handler.get_stacktrace(testcase)
  return uworker_msg_pb2.Input(  # pylint: disable=no-member
      job_type=job_type,
      testcase_id=testcase_id,
      uworker_env=uworker_env,
      setup_input=setup_input,
      testcase=uworker_io.entity_to_protobuf(testcase),
      symbolize_task_input=uworker_msg_pb2.SymbolizeTaskInput(  # pylint: disable=no-member
          old_crash_stacktrace=old_crash_stacktrace))


def utask_preprocess(testcase_id, job_type, uworker_env):
  """Set logs context and run preprocessing for symbolize task."""
  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  with logs.testcase_log_context(testcase, testcase.get_fuzz_target()):
    return _utask_preprocess(testcase_id, job_type, uworker_env)


def _utask_main(uworker_input):
  """Execute the untrusted part of a symbolize command."""
  job_type = uworker_input.job_type
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  uworker_io.check_handling_testcase_safe(testcase)
  job_type = uworker_input.job_type
  setup_input = uworker_input.setup_input

  _, testcase_file_path, error = setup.setup_testcase(testcase, job_type,
                                                      setup_input)
  if error:
    return error

  # Initialize variables.
  old_crash_stacktrace = (
      uworker_input.symbolize_task_input.old_crash_stacktrace)
  sym_crash_address = testcase.crash_address
  sym_crash_state = testcase.crash_state
  sym_redzone = DEFAULT_REDZONE
  warmup_timeout = environment.get_value('WARMUP_TIMEOUT')

  # Decide which build revision to use.
  if testcase.crash_stacktrace == 'Pending':
    # This usually happen when someone clicked the 'Update stacktrace from
    # trunk' button on the testcase details page. In this case, we are forced
    # to use trunk. No revision -> trunk build.
    build_revision = None
  else:
    build_revision = testcase.crash_revision

  fuzz_target = testcase_manager.get_fuzz_target_from_input(uworker_input)
  fuzz_target = fuzz_target.binary if fuzz_target else None
  # Set up a custom or regular build based on revision.
  build = build_manager.setup_build(build_revision, fuzz_target)

  # Get crash revision used in setting up build.
  crash_revision = environment.get_value('APP_REVISION')

  if not build or not build_manager.check_app_path():
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_message='Build setup failed',
        error_type=uworker_msg_pb2.ErrorType.SYMBOLIZE_BUILD_SETUP_ERROR)  # pylint: disable=no-member

  # ASAN tool settings (if the tool is used).
  # See if we can get better stacks with higher redzone sizes.
  # A UAF might actually turn out to be OOB read/write with a bigger redzone.
  if environment.tool_matches('ASAN', job_type) and testcase.security_flag:
    redzone = MAX_REDZONE
    while redzone >= MIN_REDZONE:
      logs.info(f'Trying to reproduce crash with ASAN redzone size {redzone}.')

      environment.reset_current_memory_tool_options(
          redzone_size=testcase.redzone, disable_ubsan=testcase.disable_ubsan)

      process_handler.terminate_stale_application_instances()
      command = testcase_manager.get_command_line_for_application(
          testcase_file_path, needs_http=testcase.http_flag)
      return_code, crash_time, output = (
          process_handler.run_process(
              command, timeout=warmup_timeout, gestures=testcase.gestures))
      crash_result = CrashResult(return_code, crash_time, output)

      if crash_result.is_crash() and 'AddressSanitizer' in output:
        state = crash_result.get_symbolized_data()
        security_flag = crash_result.is_security_issue()

        if crash_analyzer.ignore_stacktrace(state.crash_stacktrace):
          logs.info(
              f'Skipping crash with ASAN redzone size {redzone}: ' +
              'stack trace should be ignored.',
              stacktrace=state.crash_stacktrace)
        elif security_flag != testcase.security_flag:
          logs.info(
              f'Skipping crash with ASAN redzone size {redzone}: ' +
              f'mismatched security flag: old = {testcase.security_flag}, '
              f'new = {security_flag}')
        elif state.crash_type != testcase.crash_type:
          logs.info(f'Skipping crash with ASAN redzone size {redzone}: ' +
                    f'mismatched crash type: old = {testcase.crash_type}, '
                    f'new = {state.crash_type}')
        elif state.crash_state == sym_crash_state:
          logs.info(f'Skipping crash with ASAN redzone size {redzone}: ' +
                    f'same crash state = {sym_crash_state}')
        else:
          logs.info(f'Using crash with larger ASAN redzone size {redzone}: ' +
                    f'old crash address = {sym_crash_address}, ' +
                    f'new crash address = {state.crash_address}, ' +
                    f'old crash state = {sym_crash_state}, ' +
                    f'new crash state = {state.crash_state}')

          sym_crash_address = state.crash_address
          sym_crash_state = state.crash_state
          sym_redzone = redzone
          old_crash_stacktrace = state.crash_stacktrace
          break

      redzone /= 2

  # We no longer need this build, delete it to save some disk space. We will
  # download a symbolized release build to perform the symbolization.
  build.delete()

  # We should have atleast a symbolized debug or a release build.
  symbolized_builds = build_manager.setup_symbolized_builds(crash_revision)
  if (not symbolized_builds or
      (not build_manager.check_app_path() and
       not build_manager.check_app_path('APP_PATH_DEBUG'))):
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_message='Build setup failed',
        error_type=uworker_msg_pb2.ErrorType.SYMBOLIZE_BUILD_SETUP_ERROR)  # pylint: disable=no-member

  # Increase malloc_context_size to get all stack frames. Default is 30.
  environment.reset_current_memory_tool_options(
      redzone_size=sym_redzone,
      malloc_context_size=STACK_FRAME_COUNT,
      symbolize_inline_frames=True,
      disable_ubsan=testcase.disable_ubsan)

  # TSAN tool settings (if the tool is used).
  if environment.tool_matches('TSAN', job_type):
    environment.set_tsan_max_history_size()

  # Do the symbolization if supported by this application.
  result, sym_crash_stacktrace = (
      get_symbolized_stacktraces(testcase_file_path, testcase,
                                 old_crash_stacktrace, sym_crash_state))

  symbolize_task_output = uworker_msg_pb2.SymbolizeTaskOutput(  # pylint: disable=no-member
      crash_type=testcase.crash_type,
      crash_address=sym_crash_address,
      crash_state=sym_crash_state,
      crash_stacktrace=(data_handler.filter_stacktrace(sym_crash_stacktrace)),
      symbolized=result,
      crash_revision=int(crash_revision))

  if result:
    build_url = environment.get_value('BUILD_URL')
    if build_url:
      symbolize_task_output.build_url = str(build_url)

  # Switch current directory before builds cleanup.
  root_directory = environment.get_value('ROOT_DIR')
  os.chdir(root_directory)

  # Cleanup symbolized builds which are space-heavy.
  symbolized_builds.delete()
  return uworker_msg_pb2.Output(symbolize_task_output=symbolize_task_output)  # pylint: disable=no-member


def utask_main(uworker_input):
  """Set logs context and run the untrusted part of a symbolize command."""
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  with logs.testcase_log_context(
      testcase, testcase_manager.get_fuzz_target_from_input(uworker_input)):
    return _utask_main(uworker_input)


def get_symbolized_stacktraces(testcase_file_path, testcase,
                               old_crash_stacktrace, expected_state):
  """Use the symbolized builds to generate an updated stacktrace."""
  # Initialize variables.
  app_path = environment.get_value('APP_PATH')
  app_path_debug = environment.get_value('APP_PATH_DEBUG')
  long_test_timeout = environment.get_value('WARMUP_TIMEOUT')
  retry_limit = environment.get_value('FAIL_RETRIES')
  symbolized = False

  debug_build_stacktrace = ''
  release_build_stacktrace = old_crash_stacktrace

  # Symbolize using the debug build first so that the debug build stacktrace
  # comes after the more important release build stacktrace.
  if app_path_debug:
    for _ in range(retry_limit):
      process_handler.terminate_stale_application_instances()
      command = testcase_manager.get_command_line_for_application(
          testcase_file_path,
          app_path=app_path_debug,
          needs_http=testcase.http_flag)
      return_code, crash_time, output = (
          process_handler.run_process(
              command, timeout=long_test_timeout, gestures=testcase.gestures))
      crash_result = CrashResult(return_code, crash_time, output)

      if crash_result.is_crash():
        state = crash_result.get_symbolized_data()

        if crash_analyzer.ignore_stacktrace(state.crash_stacktrace):
          continue

        unsymbolized_crash_stacktrace = crash_result.get_stacktrace(
            symbolized=False)
        debug_build_stacktrace = utils.get_crash_stacktrace_output(
            command,
            state.crash_stacktrace,
            unsymbolized_crash_stacktrace,
            build_type='debug')
        symbolized = True
        break

  # Symbolize using the release build.
  if app_path:
    for _ in range(retry_limit):
      process_handler.terminate_stale_application_instances()
      command = testcase_manager.get_command_line_for_application(
          testcase_file_path, app_path=app_path, needs_http=testcase.http_flag)
      return_code, crash_time, output = (
          process_handler.run_process(
              command, timeout=long_test_timeout, gestures=testcase.gestures))
      crash_result = CrashResult(return_code, crash_time, output)

      if crash_result.is_crash():
        state = crash_result.get_symbolized_data()

        if crash_analyzer.ignore_stacktrace(state.crash_stacktrace):
          continue

        if state.crash_state != expected_state:
          continue

        # Release stack's security flag has to match the symbolized release
        # stack's security flag.
        security_flag = crash_result.is_security_issue()
        if security_flag != testcase.security_flag:
          continue

        unsymbolized_crash_stacktrace = crash_result.get_stacktrace(
            symbolized=False)
        release_build_stacktrace = utils.get_crash_stacktrace_output(
            command,
            state.crash_stacktrace,
            unsymbolized_crash_stacktrace,
            build_type='release')
        symbolized = True
        break

  stacktrace = release_build_stacktrace
  if debug_build_stacktrace:
    stacktrace += '\n\n' + debug_build_stacktrace

  return symbolized, stacktrace


_ERROR_HANDLER = uworker_handle_errors.CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.SYMBOLIZE_BUILD_SETUP_ERROR:  # pylint: disable=no-member
        handle_build_setup_error,
}).compose_with(
    setup.ERROR_HANDLER,
    uworker_handle_errors.UNHANDLED_ERROR_HANDLER,
)


def _utask_postprocess(output):
  """Handle the output from utask_main."""
  if output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
    _ERROR_HANDLER.handle(output)
    return

  symbolize_task_output = output.symbolize_task_output

  # Update crash parameters.
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  testcase.crash_type = symbolize_task_output.crash_type
  testcase.crash_address = symbolize_task_output.crash_address
  testcase.crash_state = symbolize_task_output.crash_state
  testcase.crash_stacktrace = symbolize_task_output.crash_stacktrace

  if not symbolize_task_output.symbolized:
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.ERROR,
        'Unable to reproduce crash, skipping '
        'stacktrace update')
  else:
    # Switch build url to use the less-optimized symbolized build with better
    # stacktrace.
    if symbolize_task_output.build_url:
      testcase.set_metadata(
          'build_url', symbolize_task_output.build_url, update_testcase=False)

    data_handler.update_testcase_comment(testcase,
                                         data_types.TaskState.FINISHED)

  testcase.symbolized = True
  testcase.crash_revision = symbolize_task_output.crash_revision
  testcase.put()

  # We might have updated the crash state. See if we need to marked as duplicate
  # based on other testcases.
  data_handler.handle_duplicate_entry(testcase)

  task_creation.create_blame_task_if_needed(testcase)


def utask_postprocess(output):
  """Set logs context and handle the output from utask_main."""
  # Retrieve the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  with logs.testcase_log_context(testcase, testcase.get_fuzz_target()):
    return _utask_postprocess(output)

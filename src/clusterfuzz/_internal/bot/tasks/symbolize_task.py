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
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler

DEFAULT_REDZONE = 128
MAX_REDZONE = 1024
MIN_REDZONE = 16
STACK_FRAME_COUNT = 128


def execute_task(testcase_id, job_type):
  """Execute a symbolize command."""
  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)

  # We should atleast have a symbolized debug or release build.
  if not build_manager.has_symbolized_builds():
    return

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  # Setup testcase and its dependencies.
  file_list, _, testcase_file_path = setup.setup_testcase(testcase, job_type)
  if not file_list:
    return

  # Initialize variables.
  build_fail_wait = environment.get_value('FAIL_WAIT')

  old_crash_stacktrace = data_handler.get_stacktrace(testcase)
  sym_crash_type = testcase.crash_type
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

  # Set up a custom or regular build based on revision.
  build_manager.setup_build(build_revision)

  # Get crash revision used in setting up build.
  crash_revision = environment.get_value('APP_REVISION')

  if not build_manager.check_app_path():
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Build setup failed')
    tasks.add_task(
        'symbolize', testcase_id, job_type, wait_time=build_fail_wait)
    return

  # ASAN tool settings (if the tool is used).
  # See if we can get better stacks with higher redzone sizes.
  # A UAF might actually turn out to be OOB read/write with a bigger redzone.
  if environment.tool_matches('ASAN', job_type) and testcase.security_flag:
    redzone = MAX_REDZONE
    while redzone >= MIN_REDZONE:
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

        if (not crash_analyzer.ignore_stacktrace(state.crash_stacktrace) and
            security_flag == testcase.security_flag and
            state.crash_type == testcase.crash_type and
            (state.crash_type != sym_crash_type or
             state.crash_state != sym_crash_state)):
          logs.log('Changing crash parameters.\nOld : %s, %s, %s' %
                   (sym_crash_type, sym_crash_address, sym_crash_state))

          sym_crash_type = state.crash_type
          sym_crash_address = state.crash_address
          sym_crash_state = state.crash_state
          sym_redzone = redzone
          old_crash_stacktrace = state.crash_stacktrace

          logs.log('\nNew : %s, %s, %s' % (sym_crash_type, sym_crash_address,
                                           sym_crash_state))
          break

      redzone /= 2

  # We should have atleast a symbolized debug or a release build.
  symbolized_builds = build_manager.setup_symbolized_builds(crash_revision)
  if (not symbolized_builds or
      (not build_manager.check_app_path() and
       not build_manager.check_app_path('APP_PATH_DEBUG'))):
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Build setup failed')
    tasks.add_task(
        'symbolize', testcase_id, job_type, wait_time=build_fail_wait)
    return

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

  # Update crash parameters.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  testcase.crash_type = sym_crash_type
  testcase.crash_address = sym_crash_address
  testcase.crash_state = sym_crash_state
  testcase.crash_stacktrace = (
      data_handler.filter_stacktrace(sym_crash_stacktrace))

  if not result:
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.ERROR,
        'Unable to reproduce crash, skipping '
        'stacktrace update')
  else:
    # Switch build url to use the less-optimized symbolized build with better
    # stacktrace.
    build_url = environment.get_value('BUILD_URL')
    if build_url:
      testcase.set_metadata('build_url', build_url, update_testcase=False)

    data_handler.update_testcase_comment(testcase,
                                         data_types.TaskState.FINISHED)

  testcase.symbolized = True
  testcase.crash_revision = crash_revision
  testcase.put()

  # We might have updated the crash state. See if we need to marked as duplicate
  # based on other testcases.
  data_handler.handle_duplicate_entry(testcase)

  task_creation.create_blame_task_if_needed(testcase)

  # Switch current directory before builds cleanup.
  root_directory = environment.get_value('ROOT_DIR')
  os.chdir(root_directory)

  # Cleanup symbolized builds which are space-heavy.
  symbolized_builds.delete()


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

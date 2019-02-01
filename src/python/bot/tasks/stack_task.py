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
"""Stack task for generating additional stacktrace(s)."""

from base import utils
from bot.tasks import setup
from build_management import build_manager
from datastore import data_handler
from datastore import data_types
from fuzzing import tests
from system import environment


def execute_task(testcase_id, job_type):
  """Run a test case with a second job type to generate a second stack trace."""
  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  # Setup testcase and its dependencies.
  file_list, _, testcase_file_path = setup.setup_testcase(testcase)
  if not file_list:
    return

  # Initialize timeout values.
  test_timeout = environment.get_value('TEST_TIMEOUT', 10)

  # Set up a custom or regular build. We explicitly omit the crash revision
  # since we want to test against the latest build here.
  build_manager.setup_build()

  # Check if we have an application path. If not, our build failed to setup
  # correctly.
  app_path = environment.get_value('APP_PATH')
  if not app_path:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Build setup failed')
    return

  # TSAN tool settings (if the tool is used).
  if environment.tool_matches('TSAN', job_type):
    environment.set_tsan_max_history_size()

  command = tests.get_command_line_for_application(
      testcase_file_path, app_path=app_path, needs_http=testcase.http_flag)
  result = tests.test_for_crash_with_retries(
      testcase,
      testcase_file_path,
      test_timeout,
      http_flag=testcase.http_flag,
      compare_crash=False)

  # Get revision information.
  revision = environment.get_value('APP_REVISION')

  # If a crash occurs, then we add the second stacktrace information.
  if result.is_crash():
    state = result.get_symbolized_data()
    security_flag = result.is_security_issue()
    one_time_crasher_flag = not tests.test_for_reproducibility(
        testcase_file_path, state.crash_state, security_flag, test_timeout,
        testcase.http_flag, testcase.gestures)

    # Attach a header to indicate information on reproducibility flag.
    if one_time_crasher_flag:
      crash_stacktrace_header = 'Unreliable'
    else:
      crash_stacktrace_header = 'Fully reproducible'
    crash_stacktrace_header += (' crash found using %s job.\n\n' % job_type)

    unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
    stacktrace = utils.get_crash_stacktrace_output(
        command, state.crash_stacktrace, unsymbolized_crash_stacktrace)

    crash_stacktrace = data_handler.filter_stacktrace(
        '%s%s' % (crash_stacktrace_header, stacktrace))
  else:
    crash_stacktrace = 'No crash found using %s job.' % job_type

  # Decide which stacktrace to update this stacktrace with.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if testcase.last_tested_crash_stacktrace == 'Pending':
    # This case happens when someone clicks 'Update last tested stacktrace using
    # trunk build' button.
    testcase.last_tested_crash_stacktrace = crash_stacktrace
    testcase.set_metadata(
        'last_tested_crash_revision', revision, update_testcase=False)
  else:
    # Default case when someone defines |SECOND_STACK_JOB_TYPE| in the job
    # type. This helps to test the unreproducible crash with a different memory
    # debugging tool to get a second stacktrace (e.g. running TSAN on a flaky
    # crash found in ASAN build).
    testcase.second_crash_stacktrace = crash_stacktrace
    testcase.set_metadata(
        'second_crash_stacktrace_revision', revision, update_testcase=False)

  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED)

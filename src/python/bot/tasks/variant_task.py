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
"""Variant task for analyzing testcase variants with a different job."""

from base import utils
from bot.fuzzers import builtin_fuzzers
from bot.tasks import setup
from build_management import build_manager
from crash_analysis.crash_comparer import CrashComparer
from datastore import data_handler
from datastore import data_types
from fuzzing import testcase_manager
from system import environment


def execute_task(testcase_id, job_type):
  """Run a test case with a different job type to see if they reproduce."""
  testcase = data_handler.get_testcase_by_id(testcase_id)

  # Setup testcase and its dependencies.
  fuzzer_override = builtin_fuzzers.get_fuzzer_for_job(job_type)
  file_list, _, testcase_file_path = setup.setup_testcase(
      testcase, fuzzer_override=fuzzer_override)
  if not file_list:
    return

  # Initialize helper variables.
  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  revision = environment.get_value('APP_REVISION')

  # Set up a custom or regular build. We explicitly omit the crash revision
  # since we want to test against the latest build here.
  build_manager.setup_build()

  # Check if we have an application path. If not, our build failed to setup
  # correctly.
  app_path = environment.get_value('APP_PATH')
  if not app_path:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.ERROR,
        'Build setup failed with job: ' + job_type)
    return

  # Reproduce the crash.
  command = testcase_manager.get_command_line_for_application(
      testcase_file_path, app_path=app_path, needs_http=testcase.http_flag)
  result = testcase_manager.test_for_crash_with_retries(
      testcase,
      testcase_file_path,
      test_timeout,
      http_flag=testcase.http_flag,
      compare_crash=False)

  if result.is_crash():
    crash_state = result.get_state()
    crash_type = result.get_type()
    security_flag = result.is_security_issue()

    one_time_crasher_flag = not testcase_manager.test_for_reproducibility(
        testcase_file_path, crash_state, security_flag, test_timeout,
        testcase.http_flag, testcase.gestures)
    if one_time_crasher_flag:
      status = data_types.TestcaseVariantStatus.FLAKY
    else:
      status = data_types.TestcaseVariantStatus.REPRODUCIBLE

    crash_comparer = CrashComparer(crash_state, testcase.crash_state)
    is_similar = (
        crash_comparer.is_similar() and security_flag == testcase.security_flag)

    unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
    symbolized_crash_stacktrace = result.get_stacktrace(symbolized=True)
    crash_stacktrace_output = utils.get_crash_stacktrace_output(
        command, symbolized_crash_stacktrace, unsymbolized_crash_stacktrace)
  else:
    status = data_types.TestcaseVariantStatus.UNREPRODUCIBLE
    is_similar = False
    crash_type = None
    crash_state = None
    security_flag = False
    crash_stacktrace_output = 'No crash occurred.'

  testcase = data_handler.get_testcase_by_id(testcase_id)
  if testcase.job_type == job_type:
    # This case happens when someone clicks 'Update last tested stacktrace using
    # trunk build' button.
    testcase.last_tested_crash_stacktrace = (
        data_handler.filter_stacktrace(crash_stacktrace_output))
    testcase.set_metadata(
        'last_tested_crash_revision', revision, update_testcase=False)
  else:
    # Regular case of variant analysis.
    variant = data_handler.get_testcase_variant_entity(testcase_id, job_type)
    variant.status = status
    variant.revision = revision
    variant.crash_type = crash_type
    variant.crash_state = crash_state
    variant.security_flag = security_flag
    variant.is_similar = is_similar
    # Explicitly skipping crash stacktrace for now as it make entities larger
    # and we plan to use only crash paramaters in UI.
    variant.put()

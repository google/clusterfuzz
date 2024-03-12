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
"""Regression task.
   Find commit ranges where regressions were introduced."""

import random
import time
from typing import Dict
from typing import List
from typing import Optional

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.bot.tasks.utasks import uworker_handle_errors
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment

# Number of revisions before the maximum to test before doing a bisect. This
# is also used as a cap for revisions to test near the minimum if the minimum
# happens to be a bad build.
EXTREME_REVISIONS_TO_TEST = 3

# Number of earlier revisions to check when validating ranges.
REVISIONS_TO_TEST_FOR_VALIDATION = 2

# Maximum revisions to look back when validating.
EARLIER_REVISIONS_TO_CONSIDER_FOR_VALIDATION = 10


def write_to_big_query(testcase, regression_range_start, regression_range_end):
  """Write the regression range to BigQuery."""
  big_query.write_range(
      table_id='regressions',
      testcase=testcase,
      range_name='regression',
      start=regression_range_start,
      end=regression_range_end)


def _save_current_regression_range_indices(
    task_output: uworker_msg_pb2.RegressionTaskOutput, testcase_id: str):
  """Save current regression range indices in case we die in middle of task."""
  if not task_output.HasField(
      'last_regression_min') or not task_output.HasField('last_regression_max'):
    return

  testcase = data_handler.get_testcase_by_id(testcase_id)

  testcase.set_metadata(
      'last_regression_min',
      task_output.last_regression_min,
      update_testcase=False)

  testcase.set_metadata(
      'last_regression_max',
      task_output.last_regression_max,
      update_testcase=False)

  testcase.put()


def save_regression_range(output: uworker_msg_pb2.Output):
  """Saves the regression range and creates blame and impact task if needed."""
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  regression_range_start = output.regression_task_output.regression_range_start
  regression_range_end = output.regression_task_output.regression_range_end
  testcase.regression = '%d:%d' % (regression_range_start, regression_range_end)
  data_handler.update_testcase_comment(
      testcase, data_types.TaskState.FINISHED,
      'regressed in range %s' % testcase.regression)

  write_to_big_query(testcase, regression_range_start, regression_range_end)

  # Force impacts update after regression range is updated. In several cases,
  # we might not have a production build to test with, so regression range is
  # used to decide impacts.
  task_creation.create_impact_task_if_needed(testcase)

  # Get blame information using the regression range result.
  task_creation.create_blame_task_if_needed(testcase)


def _testcase_reproduces_in_revision(
    testcase: data_types.Testcase,
    testcase_file_path: str,
    job_type: str,
    revision: int,
    regression_task_output: uworker_msg_pb2.RegressionTaskOutput,
    should_log: bool = True,
    min_revision: Optional[int] = None,
    max_revision: Optional[int] = None):
  """Test to see if a test case reproduces in the specified revision.
  Returns a tuple containing the (result, error) depending on whether
  there was an error."""
  if should_log:
    log_message = 'Testing r%d' % revision
    if min_revision is not None and max_revision is not None:
      log_message += ' (current range %d:%d)' % (min_revision, max_revision)
    logs.log(log_message)

  build_manager.setup_build(revision)
  if not build_manager.check_app_path():
    error_message = f'Build setup failed r{revision}'
    return None, uworker_msg_pb2.Output(
        regression_task_output=regression_task_output,
        error_message=error_message,
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_BUILD_SETUP_ERROR)

  build_data = testcase_manager.check_for_bad_build(job_type, revision)
  regression_task_output.build_data_list.append(build_data)
  if build_data.is_bad_build:
    error_message = f'Bad build at r{revision}. Skipping'
    logs.log_error(error_message)
    return None, uworker_msg_pb2.Output(
        regression_task_output=regression_task_output,
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_BAD_BUILD_ERROR)

  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  result = testcase_manager.test_for_crash_with_retries(
      testcase, testcase_file_path, test_timeout, http_flag=testcase.http_flag)
  return result.is_crash(), None


def found_regression_near_extreme_revisions(
    testcase: data_types.Testcase, testcase_file_path: str, job_type: str,
    revision_list: List[int], min_index: int, max_index: int,
    regression_task_output: uworker_msg_pb2.RegressionTaskOutput
) -> Optional[uworker_msg_pb2.Output]:
  """Test to see if we regressed near either the min or max revision.
  Returns a uworker_msg_pb2.Output or None.
   The uworker_msg_pb2.Output contains either:
     a. The regression range start/end in case these were correctly determined.
     b. An error-code in case of error.
  """
  # Test a few of the most recent revisions.
  last_known_crashing_revision = revision_list[max_index]
  for offset in range(1, EXTREME_REVISIONS_TO_TEST + 1):
    current_index = max_index - offset
    if current_index < min_index:
      break

    # If we don't crash in a recent revision, we regressed in one of the
    # commits between the current revision and the one at the next index.
    is_crash, error = _testcase_reproduces_in_revision(
        testcase, testcase_file_path, job_type, revision_list[current_index],
        regression_task_output)

    if error:
      # Skip this revision only on bad build errors.
      if error.error_type == uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR:
        continue
      return error

    if not is_crash:
      regression_task_output.regression_range_start = revision_list[
          current_index]
      regression_task_output.regression_range_end = last_known_crashing_revision
      return uworker_msg_pb2.Output(
          regression_task_output=regression_task_output)

    last_known_crashing_revision = revision_list[current_index]

  # Test to see if we crash in the oldest revision we can run. This is a pre-
  # condition for our binary search. If we do crash in that revision, it
  # implies that we regressed between the first commit and our first revision,
  # which we represent as 0:|min_revision|.
  for _ in range(EXTREME_REVISIONS_TO_TEST):
    min_revision = revision_list[min_index]

    crashes_in_min_revision, error = _testcase_reproduces_in_revision(
        testcase,
        testcase_file_path,
        job_type,
        min_revision,
        regression_task_output,
        should_log=False)
    if error:
      if error.error_type == uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR:
        # If we find a bad build, potentially try another.
        if min_index + 1 >= max_index:
          break

        min_index += 1
        continue
      # Only bad build errors are skipped.
      return error

    if crashes_in_min_revision:
      regression_task_output.regression_range_start = 0
      regression_task_output.regression_range_end = min_revision
      return uworker_msg_pb2.Output(
          regression_task_output=regression_task_output)
    return None

  # We should have returned above. If we get here, it means we tried too many
  # builds near the min revision, and they were all bad.
  error_message = ('Tried too many builds near the min revision, and they were'
                   f' all bad. Bad build at r{revision_list[min_index]}')
  logs.log_error(error_message)
  return uworker_msg_pb2.Output(
      regression_task_output=regression_task_output,
      error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)


def validate_regression_range(
    testcase: data_types.Testcase, testcase_file_path: str, job_type: str,
    revision_list: List[int], min_index: int,
    regression_task_output: uworker_msg_pb2.RegressionTaskOutput
) -> Optional[uworker_msg_pb2.Output]:
  """Ensure that we found the correct min revision by testing earlier ones.
  Returns a uworker_msg_pb2.Output in case of error or crash, None otherwise."""
  earlier_revisions = revision_list[
      min_index - EARLIER_REVISIONS_TO_CONSIDER_FOR_VALIDATION:min_index]
  revision_count = min(len(earlier_revisions), REVISIONS_TO_TEST_FOR_VALIDATION)

  revisions_to_test = random.sample(earlier_revisions, revision_count)
  for revision in revisions_to_test:
    is_crash, error = _testcase_reproduces_in_revision(
        testcase, testcase_file_path, job_type, revision,
        regression_task_output)
    if error:
      if error.error_type == uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR:
        continue
      return error
    if is_crash:
      error_message = (
          'Low confidence in regression range. Test case crashes in '
          'revision r%d but not later revision r%d' %
          (revision, revision_list[min_index]))
      return uworker_msg_pb2.Output(
          error_message=error_message,
          error_type=uworker_msg_pb2.
          REGRESSION_LOW_CONFIDENCE_IN_REGRESSION_RANGE,
          regression_task_output=regression_task_output)
  return None


def find_regression_range(uworker_input: uworker_msg_pb2.Input,
                         ) -> uworker_msg_pb2.Output:
  """Attempt to find when the testcase regressed."""
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  job_type = uworker_input.job_type

  deadline = tasks.get_task_completion_deadline()

  # Setup testcase and its dependencies.
  _, testcase_file_path, error = setup.setup_testcase(testcase, job_type,
                                                      uworker_input.setup_input)
  if error:
    return error

  build_bucket_path = build_manager.get_primary_bucket_path()
  revision_list = build_manager.get_revisions_list(
      build_bucket_path,
      uworker_input.regression_task_input.bad_revisions,
      testcase=testcase)
  if not revision_list:
    return uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR)

  # Pick up where left off in a previous run if necessary.
  min_revision = testcase.get_metadata('last_regression_min')
  max_revision = testcase.get_metadata('last_regression_max')
  first_run = not min_revision and not max_revision
  if not min_revision:
    min_revision = revisions.get_first_revision_in_list(revision_list)
  if not max_revision:
    max_revision = testcase.crash_revision

  min_index = revisions.find_min_revision_index(revision_list, min_revision)
  if min_index is None:
    error_message = f'Could not find good min revision <= {min_revision}.'
    return uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_BUILD_NOT_FOUND,
        error_message=error_message)

  max_index = revisions.find_max_revision_index(revision_list, max_revision)
  if max_index is None:
    error_message = f'Could not find good max revision >= {max_revision}.'
    return uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_BUILD_NOT_FOUND,
        error_message=error_message)

  # Make sure that the revision where we noticed the crash, still crashes at
  # that revision. Otherwise, our binary search algorithm won't work correctly.
  max_revision = revision_list[max_index]
  regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
  crashes_in_max_revision, error = _testcase_reproduces_in_revision(
      testcase,
      testcase_file_path,
      job_type,
      max_revision,
      regression_task_output,
      should_log=False)
  if error:
    return error
  if not crashes_in_max_revision:
    error_message = f'Known crash revision {max_revision} did not crash'
    return uworker_msg_pb2.Output(
        regression_task_output=regression_task_output,
        error_message=error_message,
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_NO_CRASH)

  # If we've made it this far, the test case appears to be reproducible.
  regression_task_output.is_testcase_reproducible = True

  # On the first run, check to see if we regressed near either the min or max
  # revision.
  if first_run:
    result = found_regression_near_extreme_revisions(
        testcase, testcase_file_path, job_type, revision_list, min_index,
        max_index, regression_task_output)
    if result:
      return result

  while time.time() < deadline:
    min_revision = revision_list[min_index]
    max_revision = revision_list[max_index]

    # If the min and max revisions are one apart (or the same, if we only have
    # one build), this is as much as we can narrow the range.
    if max_index - min_index <= 1:
      # Verify that the regression range seems correct, and save it if so.
      error = validate_regression_range(testcase, testcase_file_path, job_type,
                                        revision_list, min_index,
                                        regression_task_output)
      if error:
        return error
      regression_task_output.regression_range_start = min_revision
      regression_task_output.regression_range_end = max_revision
      return uworker_msg_pb2.Output(
          regression_task_output=regression_task_output)

    middle_index = (min_index + max_index) // 2
    middle_revision = revision_list[middle_index]

    is_crash, error = _testcase_reproduces_in_revision(
        testcase,
        testcase_file_path,
        job_type,
        middle_revision,
        regression_task_output,
        min_revision=min_revision,
        max_revision=max_revision)
    if error:
      if error.error_type == uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR:
        # Skip this revision.
        del revision_list[middle_index]
        max_index -= 1
        continue
      return error

    if is_crash:
      max_index = middle_index
    else:
      min_index = middle_index

    # Save current regression range in case the task dies prematurely.
    regression_task_output.last_regression_min = revision_list[min_index]
    regression_task_output.last_regression_max = revision_list[max_index]

  # If we've broken out of the above loop, we timed out. We'll finish by
  # running another regression task and picking up from this point.
  # TODO: Error handling should be moved to postprocess.
  error_message = 'Timed out, current range r%d:r%d' % (
      revision_list[min_index], revision_list[max_index])
  regression_task_output.last_regression_min = revision_list[min_index]
  regression_task_output.last_regression_max = revision_list[max_index]
  return uworker_msg_pb2.Output(
      regression_task_output=regression_task_output,
      error_type=uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR,
      error_message=error_message)


def utask_preprocess(testcase_id: str, job_type: str,
                     uworker_env: Dict) -> Optional[uworker_msg_pb2.Input]:
  """Prepares inputs for `utask_main()` to run on an untrusted worker.

  Runs on a trusted worker.
  """
  testcase = data_handler.get_testcase_by_id(testcase_id)

  if testcase.regression:
    logs.log_error(
        f'Regression range is already set as {testcase.regression}, skip.')
    return None

  # This task is not applicable for custom binaries.
  if build_manager.is_custom_binary():
    testcase.regression = 'NA'
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Not applicable for custom binaries')
    return None

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  setup_input = setup.preprocess_setup_testcase(testcase)

  task_input = uworker_msg_pb2.RegressionTaskInput(
      bad_revisions=build_manager.get_job_bad_revisions())

  return uworker_msg_pb2.Input(
      testcase_id=testcase_id,
      testcase=uworker_io.entity_to_protobuf(testcase),
      job_type=job_type,
      uworker_env=uworker_env,
      setup_input=setup_input,
      regression_task_input=task_input,
  )


def utask_main(uworker_input: uworker_msg_pb2.Input,
              ) -> Optional[uworker_msg_pb2.Output]:
  """Runs regression task and handles potential errors.

  Runs on an untrusted worker.
  """
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  uworker_io.check_handling_testcase_safe(testcase)
  return find_regression_range(uworker_input)


def handle_revision_list_error(output: uworker_msg_pb2.Output):
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.close_testcase_with_error(testcase,
                                         'Failed to fetch revision list')


def handle_build_not_found_error(output: uworker_msg_pb2.Output):
  # If an expected build no longer exists, we can't continue.
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  testcase.regression = 'NA'
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)


def handle_regression_build_setup_error(output: uworker_msg_pb2.Output):
  # If we failed to setup a build, it is likely a bot error. We can retry
  # the task in this case.
  uworker_input = output.uworker_input
  testcase = data_handler.get_testcase_by_id(uworker_input.testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)
  build_fail_wait = environment.get_value('FAIL_WAIT')
  tasks.add_task(
      'regression',
      uworker_input.testcase_id,
      uworker_input.job_type,
      wait_time=build_fail_wait)


def handle_regression_bad_build_error(output: uworker_msg_pb2.Output):
  # Though bad builds when narrowing the range are recoverable, certain builds
  # being marked as bad may be unrecoverable. Recoverable ones should not
  # reach this point.
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  testcase.regression = 'NA'
  error_message = 'Unable to recover from bad build'
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       error_message)


def handle_regression_no_crash(output: uworker_msg_pb2.Output):
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)

  task_creation.mark_unreproducible_if_flaky(testcase, 'regression', True)


def handle_regression_timeout(output: uworker_msg_pb2.Output):
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)
  tasks.add_task('regression', output.uworker_input.testcase_id,
                 output.uworker_input.job_type)


def handle_low_confidence_in_regression_range(output: uworker_msg_pb2.Output):
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  testcase.regression = 'NA'
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)


_ERROR_HANDLER = uworker_handle_errors.CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.REGRESSION_BAD_BUILD_ERROR:
        handle_regression_bad_build_error,
    uworker_msg_pb2.ErrorType.REGRESSION_BUILD_NOT_FOUND:
        handle_build_not_found_error,
    uworker_msg_pb2.ErrorType.REGRESSION_BUILD_SETUP_ERROR:
        handle_regression_build_setup_error,
    uworker_msg_pb2.ErrorType.REGRESSION_LOW_CONFIDENCE_IN_REGRESSION_RANGE:
        handle_low_confidence_in_regression_range,
    uworker_msg_pb2.ErrorType.REGRESSION_NO_CRASH:
        handle_regression_no_crash,
    uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR:
        handle_revision_list_error,
    uworker_msg_pb2.ErrorType.REGRESSION_TIMEOUT_ERROR:
        handle_regression_timeout,
}).compose_with(setup.ERROR_HANDLER)


def utask_postprocess(output: uworker_msg_pb2.Output) -> None:
  """Handles the output of `utask_main()` run on an untrusted worker.

  Runs on a trusted worker.
  """
  if output.HasField('regression_task_output'):
    task_output = output.regression_task_output
    _update_build_metadata(output.uworker_input.job_type,
                           task_output.build_data_list)
    _save_current_regression_range_indices(task_output,
                                           output.uworker_input.testcase_id)
    if task_output.is_testcase_reproducible:
      # Clear metadata from previous runs had it been marked as potentially
      # flaky.
      testcase = data_handler.get_testcase_by_id(
          output.uworker_input.testcase_id)
      task_creation.mark_unreproducible_if_flaky(testcase, 'regression', False)

  if output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:
    _ERROR_HANDLER.handle(output)
    return

  save_regression_range(output)


def _update_build_metadata(job_type: str,
                           build_data_list: List[uworker_msg_pb2.BuildData]):
  """A helper method to update the build metadata corresponding to a
  job_type."""
  for build_data in build_data_list:
    testcase_manager.update_build_metadata(job_type, build_data)

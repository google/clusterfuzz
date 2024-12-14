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
from clusterfuzz._internal.common import testcase_utils
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
    task_output: uworker_msg_pb2.RegressionTaskOutput, testcase_id: str):  # pylint: disable=no-member
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


def save_regression_range(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
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
    regression_task_output: uworker_msg_pb2.RegressionTaskOutput,  # pylint: disable=no-member
    fuzz_target: Optional[data_types.FuzzTarget],
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
    logs.info(log_message)

  fuzz_target_binary = fuzz_target.binary if fuzz_target else None
  build_setup_result = build_manager.setup_build(
      revision, fuzz_target=fuzz_target_binary)
  if not build_setup_result or not build_manager.check_app_path():
    error_message = f'Build setup failed r{revision}'
    return None, uworker_msg_pb2.Output(  # pylint: disable=no-member
        regression_task_output=regression_task_output,
        error_message=error_message,
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_BUILD_SETUP_ERROR)  # pylint: disable=no-member

  build_data = testcase_manager.check_for_bad_build(job_type, revision)
  regression_task_output.build_data_list.append(build_data)
  if build_data.is_bad_build:
    error_message = f'Bad build at r{revision}. Skipping'
    logs.error(error_message)
    return None, uworker_msg_pb2.Output(  # pylint: disable=no-member
        regression_task_output=regression_task_output,
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_BAD_BUILD_ERROR)  # pylint: disable=no-member

  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  result = testcase_manager.test_for_crash_with_retries(
      fuzz_target,
      testcase,
      testcase_file_path,
      test_timeout,
      http_flag=testcase.http_flag)
  return result.is_crash(), None


def check_latest_revisions(
    testcase: data_types.Testcase,
    testcase_file_path: str,
    job_type: str,
    revision_range: List[int],
    fuzz_target: Optional[data_types.FuzzTarget],
    output: uworker_msg_pb2.RegressionTaskOutput,  # pylint: disable=no-member
) -> Optional[uworker_msg_pb2.Output]:  # pylint: disable=no-member
  """Check if the regression happened near the last revision in a range.

  Args:
    testcase: Passed to `_testcase_reproduces_in_revision()`.
    testcase_file_path: Passed to `_testcase_reproduces_in_revision()`.
    job_type: Passed to `_testcase_reproduces_in_revision()`.
    fuzz_target: Passed to `_testcase_reproduces_in_revision()`.
    revision_range: The range of revisions in which to search. Must not be
      empty. It is assumed that the last element / max revision is good and
      crashes.
    output: Output argument. Any bad builds encountered while searching for the
      latest passing revision are appended to `build_data_list`.
      See also below for values set in different return conditions.

  Returns:
    An output proto if the regression was found or in case of error.
    None otherwise, in which case `output.last_regression_max` is set to the
    lowest revision which reproduces the crash - at most `revision_range[-1]`.
  """
  output.last_regression_max = revision_range[-1]

  for revision in reversed(revision_range[-EXTREME_REVISIONS_TO_TEST - 1:-1]):
    # If we don't crash in a recent revision, we regressed in one of the
    # commits between the current revision and the next.
    is_crash, error = _testcase_reproduces_in_revision(
        testcase, testcase_file_path, job_type, revision, output, fuzz_target)

    if error:
      # Skip this revision only on bad build errors.
      if error.error_type == uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR:  # pylint: disable=no-member
        continue
      return error

    if not is_crash:
      # We've found the latest passing revision, no need to binary search.
      output.regression_range_start = revision
      output.regression_range_end = output.last_regression_max
      return uworker_msg_pb2.Output(regression_task_output=output)  # pylint: disable=no-member

    output.last_regression_max = revision

  # All most recent revisions crash.
  return None


def find_min_revision(
    testcase: data_types.Testcase,
    testcase_file_path: str,
    job_type: str,
    fuzz_target: Optional[data_types.FuzzTarget],
    deadline: float,
    revision_list: List[int],
    max_index: int,
    next_revision: Optional[int],
    regression_task_output: uworker_msg_pb2.RegressionTaskOutput,  # pylint: disable=no-member
) -> Optional[uworker_msg_pb2.Output]:  # pylint: disable=no-member
  """Attempts to find a min revision to start bisecting from. Such a revision
  must be good and the testcase must not reproduce at that revision.

  Args:
    testcase: Passed to `_testcase_reproduces_in_revision()`.
    testcase_file_path: Passed to `_testcase_reproduces_in_revision()`.
    job_type: Passed to `_testcase_reproduces_in_revision()`.
    fuzz_target: Passed to `_testcase_reproduces_in_revision()`.
    deadline: The timestamp (comparable to `time.time()`) past which we should
      stop the search and time out.
    revision_list: The list of all revisions known to exist.
    max_index: The index of the known max revision for bisection. Must be a
      valid index within `revision_list`. It is assumed that the testcase
      reproduces at the pointed-to revision.
    next_revision: The next revision at which to continue searching backwards
      for a min revision. Can be used to resume execution after timing out. If
      specified, the returned `min_index` will always point to a lower revision.
    regression_task_output: Output argument. Any bad builds encountered while
      searching for the earliest good build are appended to `build_data_list`.
      See also below for values set in different return conditions.

  Returns:
    a. If successful:

        min_index, max_index, None

      Where `min_index` points to the min revision in `revision_list`, and
      `max_index` points to a potentially-new max revision in `revision_list`
      (if we encountered lower revisions at which the testcase still
      reproduced).

      In this case, `regression_task_output` is modified in the following ways:

        regression_task_output.last_regression_min is set
        regression_task_output.last_regression_max is set

    a. If no such revision can be found - i.e. the earliest good revision X
      still reproduces the testcase:

        None, None, output

      where:

        output.regression_task_output.regression_range_start = 0
        output.regression_task_output.regression_range_end = X

    b. If we timed out:

        None, None, output

    d. If another error occurred:

        None, None, output

  """
  # Save this value so we can calculate exponential distances correctly even if
  # we find earlier builds that reproduce.
  original_max_index = max_index

  # TODO: Handle resumption.
  next_index = max_index - 1

  iterations = 0

  while time.time() < deadline:
    # If we fall off the end of the revision list, try the earliest revision.
    # Note that if the earliest revision is bad, we will skip it and try the
    # next one. This will go on until we find the first good revision, at which
    # point we will stop looping.
    if next_index < 0:
      print('Ran off')
      next_index = 0

    next_revision = revision_list[next_index]
    regression_task_output.last_regression_next = next_revision

    print({
        'next_index': next_index,
        'next_revision': next_revision,
        'max_index': max_index,
        'last_max': regression_task_output.last_regression_max,
        'revision_list': revision_list[:],
    })
    iterations += 1
    if iterations > 20:
      raise Exception(iterations)

    if next_index == max_index:
      # The first good build crashes, there is no min revision to be found.
      print('First good build crashes')
      regression_task_output.regression_range_start = 0
      regression_task_output.regression_range_end = next_revision
      return None, None, uworker_msg_pb2.Output(  # pylint: disable=no-member
          regression_task_output=regression_task_output)

    is_crash, error = _testcase_reproduces_in_revision(
        testcase,
        testcase_file_path,
        job_type,
        next_revision,
        regression_task_output,
        fuzz_target,
        should_log=False)

    if error:
      # If this revision contains a bad build, skip it and try the previous one.
      # Remove the revision from the list so we don't try using it again during
      # this run.
      if error.error_type == uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR:  # pylint: disable=no-member
        print(f'Skipping bad build r{next_revision}')
        del revision_list[next_index]
        next_index -= 1
        max_index -= 1
        continue

      # For all other errors, stop here.
      return None, None, error

    if not is_crash:
      # We found a suitable min revision, success!
      regression_task_output.last_regression_min = next_revision
      return next_index, max_index, None

    # This is the new max revision. Remember it for later bisection.
    max_index = next_index
    regression_task_output.last_regression_max = next_revision

    # Continue exponential search backwards. Double the distance (in indices)
    # from our start point.
    #
    # Note that this means we search exponentially through the indices in the
    # revision list, not through the revisions themselves. If revisions are
    # fairly evenly distributed, then this distinction is irrelevant. If however
    # there are large irregular gaps in between revisions, this might appear a
    # bit strange at a glance. Consider:
    #
    #   Revisions:    1, 2, 3, 4, 5, 50, 51, 127, 128
    #   Search order: 4           3       2    1
    #
    #   Appears as trying: 127, 51, 5, 1
    #   Instead of:        127, 126, 124, 120, 112, 96, 64, 1
    #
    # Both would work, but searching through indices in the revision list is
    # both easier to express in code and more efficient since what we care
    # about is searching through revisions that we *can* test against, not
    # through all revisions in the source code.
    #
    # The later bisection stage (once we have found a min revision) similarly
    # operates on indices and not revisions.
    distance = original_max_index - next_index
    next_index -= distance
    print('Doubling distance')

  return None, None, uworker_msg_pb2.Output(  # pylint: disable=no-member
      error_type=uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR,  # pylint: disable=no-member
      regression_task_output=regression_task_output)

  # If we get here, it means all builds except the max were bad. In other words,
  # the first good build crashes.
  regression_task_output.regression_range_start = 0
  regression_task_output.regression_range_end = revision_range[-1]
  return uworker_msg_pb2.Output(regression_task_output=regression_task_output)  # pylint: disable=no-member


def validate_regression_range(
    testcase: data_types.Testcase,
    testcase_file_path: str,
    job_type: str,
    revision_list: List[int],
    min_index: int,
    regression_task_output: uworker_msg_pb2.RegressionTaskOutput,  # pylint: disable=no-member
    fuzz_target: Optional[data_types.FuzzTarget],
) -> Optional[uworker_msg_pb2.Output]:  # pylint: disable=no-member
  """Ensure that we found the correct min revision by testing earlier ones.
  Returns a uworker_msg_pb2.Output in case of error or crash, None otherwise."""
  earlier_revisions = revision_list[
      min_index - EARLIER_REVISIONS_TO_CONSIDER_FOR_VALIDATION:min_index]
  revision_count = min(len(earlier_revisions), REVISIONS_TO_TEST_FOR_VALIDATION)

  revisions_to_test = random.sample(earlier_revisions, revision_count)
  for revision in revisions_to_test:
    is_crash, error = _testcase_reproduces_in_revision(
        testcase, testcase_file_path, job_type, revision,
        regression_task_output, fuzz_target)
    if error:
      if error.error_type == uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR:  # pylint: disable=no-member
        continue
      return error
    if is_crash:
      error_message = (
          'Low confidence in regression range. Test case crashes in '
          'revision r%d but not later revision r%d' %
          (revision, revision_list[min_index]))
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_message=error_message,
          error_type=uworker_msg_pb2.  # pylint: disable=no-member
          REGRESSION_LOW_CONFIDENCE_IN_REGRESSION_RANGE,
          regression_task_output=regression_task_output)
  return None


def find_regression_range(
    uworker_input: uworker_msg_pb2.Input,  # pylint: disable=no-member
) -> uworker_msg_pb2.Output:  # pylint: disable=no-member
  """Attempt to find when the testcase regressed."""
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  job_type = uworker_input.job_type

  deadline = tasks.get_task_completion_deadline()

  fuzz_target = testcase_manager.get_fuzz_target_from_input(uworker_input)

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
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR)  # pylint: disable=no-member

  # Pick up where left off in a previous run if necessary. Possible cases:
  #
  # - min and max are None: start from scratch, search exponentially backwards
  # - max is not None, min is None: we are searching exponentially
  #   backwards for a good revision. `next_revision` is the next version we
  #   should test, and is not None
  # - max and min are not None: we are bisecting. `next_revision` can be
  #   ignored.
  #
  min_revision = testcase.get_metadata('last_regression_min')
  max_revision = testcase.get_metadata('last_regression_max')
  next_revision = testcase.get_metadata('last_regression_next')

  # Notice that regardless of whether `max_revision` was None or not, if
  # `min_revision` is None then we should search exponentially backwards. Even
  # though we are overwriting `max_revision` here, `next_revision` will tell us
  # whether we should start from scratch or whether we should pick up where we
  # left off.
  if not max_revision:
    max_revision = testcase.crash_revision

  max_index = revisions.find_max_revision_index(revision_list, max_revision)
  if max_index is None:
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_BUILD_NOT_FOUND,  # pylint: disable=no-member
        error_message=f'Could not find good max revision >= {max_revision}.')

  known_crash_revision = max_revision
  max_revision = revision_list[max_index]  # Might be > `known_crash_revision`.

  # Check invariant: max revision crashes.
  regression_task_output = uworker_msg_pb2.RegressionTaskOutput()  # pylint: disable=no-member
  crashes_in_max_revision, error = _testcase_reproduces_in_revision(
      testcase,
      testcase_file_path,
      job_type,
      max_revision,
      regression_task_output,
      fuzz_target,
      should_log=False)
  if error:
    return error
  if not crashes_in_max_revision:
    if known_crash_revision == max_revision:
      error_message = f'Known crash revision {max_revision} did not crash.'
    else:
      error_message = (f'Max revision {max_revision} did not crash. ' +
                       f'Known crash revision was {known_crash_revision}. ' +
                       'Crash is either flaky or fixed in ' +
                       f'{known_crash_revision}:{max_revision}.')
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        regression_task_output=regression_task_output,
        error_message=error_message,
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_NO_CRASH)  # pylint: disable=no-member

  # If we've made it this far, the test case appears to be reproducible.
  regression_task_output.is_testcase_reproducible = True
  regression_task.output.last_regression_max = max_revision

  min_index = None
  if min_revision:
    min_index = revisions.find_min_revision_index(revision_list, min_revision)
    if not min_index:
      # The min revision we previously found to be good no longer exists, nor
      # do any earlier revisions. This is a weird case, but we can recover by
      # searching for a good revision once more.
      logs.warn(f'Min revision {min_revision} no longer exists, nor do any '
                'earlier revisions. Restarting search for a good revision. ')
      next_revision = None

  if not min_index:
    min_index, max_index, output = find_min_revision(
        testcase, testcase_file_path, job_type, fuzz_target, deadline,
        revision_list, max_index, next_revision, regression_task_output)
    if output:
      # Either we encountered an error, or there is no good revision and the
      # regression range is `0:revision_list[0]`.
      return output

  while time.time() < deadline:
    min_revision = revision_list[min_index]
    max_revision = revision_list[max_index]

    # If the min and max revisions are one apart (or the same, if we only have
    # one build), this is as much as we can narrow the range.
    if max_index - min_index <= 1:
      # Verify that the regression range seems correct, and save it if so.
      error = validate_regression_range(testcase, testcase_file_path, job_type,
                                        revision_list, min_index,
                                        regression_task_output, fuzz_target)
      if error:
        return error
      regression_task_output.regression_range_start = min_revision
      regression_task_output.regression_range_end = max_revision
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          regression_task_output=regression_task_output)

    middle_index = (min_index + max_index) // 2
    middle_revision = revision_list[middle_index]

    is_crash, error = _testcase_reproduces_in_revision(
        testcase,
        testcase_file_path,
        job_type,
        middle_revision,
        regression_task_output,
        fuzz_target,
        min_revision=min_revision,
        max_revision=max_revision)
    if error:
      if error.error_type == uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR:  # pylint: disable=no-member
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
  return uworker_msg_pb2.Output(  # pylint: disable=no-member
      regression_task_output=regression_task_output,
      error_type=uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR,  # pylint: disable=no-member
      error_message=error_message)


def utask_preprocess(testcase_id: str, job_type: str,
                     uworker_env: Dict) -> Optional[uworker_msg_pb2.Input]:  # pylint: disable=no-member
  """Prepares inputs for `utask_main()` to run on an untrusted worker.

  Runs on a trusted worker.
  """
  testcase = data_handler.get_testcase_by_id(testcase_id)

  if testcase.regression:
    logs.error(
        f'Regression range is already set as {testcase.regression}, skip.')
    return None

  # This task is not applicable for custom binaries.
  if build_manager.is_custom_binary():
    testcase.regression = 'NA'
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Not applicable for custom binaries')
    return None

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  setup_input = setup.preprocess_setup_testcase(testcase, uworker_env)

  task_input = uworker_msg_pb2.RegressionTaskInput(  # pylint: disable=no-member
      bad_revisions=build_manager.get_job_bad_revisions())

  uworker_input = uworker_msg_pb2.Input(  # pylint: disable=no-member
      testcase_id=testcase_id,
      testcase=uworker_io.entity_to_protobuf(testcase),
      job_type=job_type,
      uworker_env=uworker_env,
      setup_input=setup_input,
      regression_task_input=task_input,
  )
  testcase_manager.preprocess_testcase_manager(testcase, uworker_input)
  return uworker_input


def utask_main(
    uworker_input: uworker_msg_pb2.Input,  # pylint: disable=no-member
) -> Optional[uworker_msg_pb2.Output]:  # pylint: disable=no-member
  """Runs regression task and handles potential errors.

  Runs on an untrusted worker.
  """
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  uworker_io.check_handling_testcase_safe(testcase)
  return find_regression_range(uworker_input)


def handle_revision_list_error(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.close_testcase_with_error(testcase,
                                         'Failed to fetch revision list')


def handle_build_not_found_error(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  # If an expected build no longer exists, we can't continue.
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  testcase.regression = 'NA'
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)


def handle_regression_build_setup_error(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
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


def handle_regression_bad_build_error(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  # Though bad builds when narrowing the range are recoverable, certain builds
  # being marked as bad may be unrecoverable. Recoverable ones should not
  # reach this point.
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  testcase.regression = 'NA'
  error_message = 'Unable to recover from bad build'
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       error_message)


def handle_regression_no_crash(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)

  task_creation.mark_unreproducible_if_flaky(testcase, 'regression', True)


def handle_regression_timeout(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)
  tasks.add_task('regression', output.uworker_input.testcase_id,
                 output.uworker_input.job_type)


def handle_low_confidence_in_regression_range(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  testcase.regression = 'NA'
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       output.error_message)


_ERROR_HANDLER = uworker_handle_errors.CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.REGRESSION_BAD_BUILD_ERROR:  # pylint: disable=no-member
        handle_regression_bad_build_error,
    uworker_msg_pb2.ErrorType.REGRESSION_BUILD_NOT_FOUND:  # pylint: disable=no-member
        handle_build_not_found_error,
    uworker_msg_pb2.ErrorType.REGRESSION_BUILD_SETUP_ERROR:  # pylint: disable=no-member
        handle_regression_build_setup_error,
    uworker_msg_pb2.ErrorType.REGRESSION_LOW_CONFIDENCE_IN_REGRESSION_RANGE:  # pylint: disable=no-member
        handle_low_confidence_in_regression_range,
    uworker_msg_pb2.ErrorType.REGRESSION_NO_CRASH:  # pylint: disable=no-member
        handle_regression_no_crash,
    uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR:  # pylint: disable=no-member
        handle_revision_list_error,
    uworker_msg_pb2.ErrorType.REGRESSION_TIMEOUT_ERROR:  # pylint: disable=no-member
        handle_regression_timeout,
}).compose_with(setup.ERROR_HANDLER)


def utask_postprocess(output: uworker_msg_pb2.Output) -> None:  # pylint: disable=no-member
  """Handles the output of `utask_main()` run on an untrusted worker.

  Runs on a trusted worker.
  """
  testcase_id = output.uworker_input.testcase_id
  testcase_utils.emit_testcase_triage_duration_metric(
      int(testcase_id),
      testcase_utils.TESTCASE_TRIAGE_DURATION_REGRESSION_COMPLETED_STEP)

  if output.HasField('regression_task_output'):
    task_output = output.regression_task_output
    _update_build_metadata(output.uworker_input.job_type,
                           task_output.build_data_list)
    _save_current_regression_range_indices(task_output, testcase_id)
    if task_output.is_testcase_reproducible:
      # Clear metadata from previous runs had it been marked as potentially
      # flaky.
      testcase = data_handler.get_testcase_by_id(
          output.uworker_input.testcase_id)
      task_creation.mark_unreproducible_if_flaky(testcase, 'regression', False)

  if output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
    _ERROR_HANDLER.handle(output)
    return

  save_regression_range(output)


def _update_build_metadata(job_type: str,
                           build_data_list: List[uworker_msg_pb2.BuildData]):  # pylint: disable=no-member
  """A helper method to update the build metadata corresponding to a
  job_type."""
  for build_data in build_data_list:
    testcase_manager.update_build_metadata(job_type, build_data)

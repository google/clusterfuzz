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
from typing import Sequence

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
  last_regression_min = None
  if task_output.HasField('last_regression_min'):
    last_regression_min = task_output.last_regression_min

  last_regression_max = None
  if task_output.HasField('last_regression_max'):
    last_regression_max = task_output.last_regression_max

  if last_regression_min is None and last_regression_max is None:
    return  # Optimization to avoid useless load/put.

  testcase = data_handler.get_testcase_by_id(testcase_id)

  testcase.set_metadata(
      'last_regression_min', last_regression_min, update_testcase=False)

  testcase.set_metadata(
      'last_regression_max', last_regression_max, update_testcase=False)

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
  if not build_setup_result:
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


def find_min_revision(
    testcase: data_types.Testcase,
    testcase_file_path: str,
    job_type: str,
    fuzz_target: Optional[data_types.FuzzTarget],
    deadline: float,
    revision_list: List[int],
    max_index: int,
    regression_task_output: uworker_msg_pb2.RegressionTaskOutput,  # pylint: disable=no-member
) -> tuple[int, int, None] | tuple[None, None, uworker_msg_pb2.Output]:  # pylint: disable=no-member
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

    b. If no such revision can be found - i.e. the earliest good revision X
      still reproduces the testcase:

        None, None, output

      where:

        output.regression_task_output = regression_task_output
        output.regression_task_output.regression_range_start = 0
        output.regression_task_output.regression_range_end = X

    c. If we timed out:

        None, None, output

      where:

        output.error_type = REGRESSION_TIMED_OUT
        output.regression_task_output = regression_task_output
        output.regression_task_output.last_regression_max is set

    d. If another error occurred:

        None, None, output

      where:

        output.error_type indicates the error that occurred
        output.regression_task_output = regression_task_output
        output.regression_task_output.last_regression_max is set

  """
  assert max_index >= 0, max_index
  assert max_index < len(revision_list), max_index

  # Note that we search exponentially through the indices in the revision list,
  # not through the revisions themselves. If revisions are fairly evenly
  # distributed, then this distinction is irrelevant. If however there are large
  # irregular gaps in between revisions, this might appear a bit strange at a
  # glance. Consider:
  #
  #   Revisions:    1, 2, 3, 4, 5, 50, 51, 127, 128
  #   Search order: 4           3       2    1
  #
  #   Appears as trying: 127, 51, 5, 1
  #   Instead of:        127, 126, 124, 120, 112, 96, 64, 1
  #
  # Both would work, but searching through indices in the revision list is both
  # easier to express in code and more efficient since what we care about is
  # searching through revisions that we *can* test against, not through all
  # revisions in the source code.
  #
  # The later bisection stage (once we have found a min revision) similarly
  # operates on indices and not revisions.

  # Find the index of the original crashing revision so that we can keep
  # doubling the step size in our exponential search backwards.
  crash_index = revisions.find_max_revision_index(revision_list,
                                                  testcase.crash_revision)
  if crash_index is None:
    # If the crash revision is no longer in the revision list, nor does there
    # exist any later revision, just use the last revision in the list instead.
    # This will reduce the step size for our exponential search by as little as
    # possible.
    crash_index = len(revision_list) - 1

  if max_index == crash_index:
    # Starting from scratch.
    next_index = max_index - 1
  elif crash_index > max_index:
    # Double the distance to the original crash index.
    distance = crash_index - max_index
    next_index = max_index - distance
  else:
    # If `max_index` is higher than `crash_index`, this means that in some
    # previous iteration the original crash revision could not be found, so a
    # higher revision was used instead, *and* we timed out before we could
    # search below `crash_revision`. Now, for some reason, the crash revision is
    # found again, so just use it and restart from scratch.
    max_index = crash_index
    next_index = max_index - 1

  assert next_index < max_index, (next_index, max_index)
  assert max_index <= crash_index, (max_index, crash_index)

  # Make sure we account for MIN_REVISION.
  first_revision = revisions.get_first_revision_in_list(revision_list)
  first_index = revisions.find_min_revision_index(revision_list, first_revision)

  while True:
    # If we fall off the end of the revision list, try the earliest revision.
    # Note that if the earliest revision is bad, we will skip it and try the
    # next one. This will go on until we find the first good revision, at which
    # point we will stop looping.
    next_index = max(next_index, first_index)
    next_revision = revision_list[next_index]

    if next_index == max_index:
      # The first good build crashes, there is no min revision to be found.
      regression_task_output.regression_range_start = 0
      regression_task_output.regression_range_end = next_revision
      return None, None, uworker_msg_pb2.Output(  # pylint: disable=no-member
          regression_task_output=regression_task_output)

    if time.time() > deadline:
      return None, None, uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR,  # pylint: disable=no-member
          error_message='Timed out searching for min revision. ' +
          f'Current max: r{regression_task_output.last_regression_max}, ' +
          f'next revision: r{next_revision}',
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
        del revision_list[next_index]
        next_index -= 1
        max_index -= 1
        crash_index -= 1
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
    distance = crash_index - next_index
    next_index -= distance

    # Assert forward progress.
    # Note that `max_index` stores the previous value of `next_index`.
    assert distance >= 0, (distance, crash_index, max_index)


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

  # Help the type checker.
  assert isinstance(testcase_file_path, str)

  build_bucket_path = build_manager.get_primary_bucket_path()
  revision_list = build_manager.get_revisions_list(
      build_bucket_path,
      uworker_input.regression_task_input.bad_revisions,
      testcase=testcase)
  if not revision_list:
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR)  # pylint: disable=no-member

  # Pick up where left off in a previous run if necessary.
  # Cache this data here to judge in the end if we actually made progress.
  # Between here and the end of the loop also a lot of time might pass, in
  # which another simultaneously running regression task might mess with
  # the metadata.
  last_min_revision = testcase.get_metadata('last_regression_min')
  last_max_revision = testcase.get_metadata('last_regression_max')
  min_revision = last_min_revision
  max_revision = last_max_revision

  logs.info('Build set up, starting search for regression range. State: ' +
            f'crash_revision = {testcase.crash_revision}, ' +
            f'max_revision = {max_revision}, ' +
            f'min_revision = {min_revision}.')

  if max_revision is None:
    logs.info('Starting search for min revision from scratch.')
    max_revision = testcase.crash_revision

    if min_revision is not None:
      logs.error('Inconsistent regression state: ' +
                 'resetting min_revision to None.')
      min_revision = None

  elif min_revision is None:
    # max_revision is not None.
    logs.info('Resuming search for min revision.')

  else:
    # max_revision and min_revision are not None.
    logs.info('Resuming bisection.')

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
  regression_task_output.last_regression_max = max_revision

  min_index = None
  if min_revision:
    min_index = revisions.find_min_revision_index(revision_list, min_revision)
    if not min_index:
      # The min revision we previously found to be good no longer exists, nor
      # do any earlier revisions. This is a weird case, but we can recover by
      # searching for a good revision once more.
      logs.warning(f'Min revision {min_revision} no longer exists, nor do any '
                   'earlier revisions. Restarting search for a good revision. ')
      min_revision = None

  if not min_index:
    min_index, max_index, output = find_min_revision(
        testcase, testcase_file_path, job_type, fuzz_target, deadline,
        revision_list, max_index, regression_task_output)
    if output:
      # Either we encountered an error, or there is no good revision and the
      # regression range is `0:revision_list[0]`.
      return output

  # Type checker cannot figure this out.
  assert isinstance(min_index, int)
  assert isinstance(max_index, int)

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

  # If we've broken out of the above loop, we timed out. Remember where
  # we left.
  regression_task_output.last_regression_min = revision_list[min_index]
  regression_task_output.last_regression_max = revision_list[max_index]

  # Check if we made progress at all. If this task already resumed a previous
  # timeout, it started with known min/max revisions. Without any progress,
  # likely most builds failed the bad build check, in which case we don't
  # want to restart another task to avoid a task loop.
  if (last_min_revision == revision_list[min_index] and
      last_max_revision == revision_list[max_index]):
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        regression_task_output=regression_task_output,
        error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR,  # pylint: disable=no-member
        error_message='No progress during bisect.')

  # Because we made progress, the timeout error handler will trigger another
  # regression task and pick up from this point.
  # TODO: Error handling should be moved to postprocess.
  error_message = 'Timed out, current range r%d:r%d' % (
      revision_list[min_index], revision_list[max_index])
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
  with logs.testcase_log_context(testcase, testcase.get_fuzz_target()):
    if testcase.regression:
      logs.error(
          f'Regression range is already set as {testcase.regression}, skip.')
      return None

    # This task is not applicable for custom binaries.
    if build_manager.is_custom_binary():
      testcase.regression = 'NA'
      data_handler.update_testcase_comment(
          testcase, data_types.TaskState.ERROR,
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
  with logs.testcase_log_context(
      testcase, testcase_manager.get_fuzz_target_from_input(uworker_input)):
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


# TODO(https://crbug.com/396344382): Wait for all uworkers to run code past
# https://github.com/google/clusterfuzz/pull/3934 for a week, then delete this.
# This error type is obsolete.
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
  # Retrieve the testcase early to be used by logs context.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  with logs.testcase_log_context(testcase, testcase.get_fuzz_target()):
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
        task_creation.mark_unreproducible_if_flaky(testcase, 'regression',
                                                   False)

    if output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
      _ERROR_HANDLER.handle(output)
      return

    save_regression_range(output)


def _update_build_metadata(
    job_type: str, build_data_list: Sequence[uworker_msg_pb2.BuildData]):  # pylint: disable=no-member
  """A helper method to update the build metadata corresponding to a
  job_type."""
  for build_data in build_data_list:
    testcase_manager.update_build_metadata(job_type, build_data)

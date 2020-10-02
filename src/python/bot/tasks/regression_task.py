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

from base import errors
from base import tasks
from bot import testcase_manager
from bot.tasks import setup
from bot.tasks import task_creation
from build_management import build_manager
from build_management import revisions
from datastore import data_handler
from datastore import data_types
from google_cloud_utils import big_query
from metrics import logs
from system import environment

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


def _save_current_regression_range_indices(testcase_id, regression_range_start,
                                           regression_range_end):
  """Save current regression range indices in case we die in middle of task."""
  testcase = data_handler.get_testcase_by_id(testcase_id)
  testcase.set_metadata(
      'last_regression_min', regression_range_start, update_testcase=False)
  testcase.set_metadata(
      'last_regression_max', regression_range_end, update_testcase=False)
  testcase.put()


def save_regression_range(testcase_id, regression_range_start,
                          regression_range_end):
  """Saves the regression range and creates blame and impact task if needed."""
  testcase = data_handler.get_testcase_by_id(testcase_id)
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


def _testcase_reproduces_in_revision(testcase,
                                     testcase_file_path,
                                     job_type,
                                     revision,
                                     should_log=True,
                                     min_revision=None,
                                     max_revision=None):
  """Test to see if a test case reproduces in the specified revision."""
  if should_log:
    log_message = 'Testing r%d' % revision
    if min_revision is not None and max_revision is not None:
      log_message += ' (current range %d:%d)' % (min_revision, max_revision)

    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    data_handler.update_testcase_comment(testcase, data_types.TaskState.WIP,
                                         log_message)

  build_manager.setup_build(revision)
  if not build_manager.check_app_path():
    raise errors.BuildSetupError(revision, job_type)

  if testcase_manager.check_for_bad_build(job_type, revision):
    log_message = 'Bad build at r%d. Skipping' % revision
    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    data_handler.update_testcase_comment(testcase, data_types.TaskState.WIP,
                                         log_message)
    raise errors.BadBuildError(revision, job_type)

  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  result = testcase_manager.test_for_crash_with_retries(
      testcase, testcase_file_path, test_timeout, http_flag=testcase.http_flag)
  return result.is_crash()


def found_regression_near_extreme_revisions(testcase, testcase_file_path,
                                            job_type, revision_list, min_index,
                                            max_index):
  """Test to see if we regressed near either the min or max revision."""
  # Test a few of the most recent revisions.
  last_known_crashing_revision = revision_list[max_index]
  for offset in range(1, EXTREME_REVISIONS_TO_TEST + 1):
    current_index = max_index - offset
    if current_index < min_index:
      break

    # If we don't crash in a recent revision, we regressed in one of the
    # commits between the current revision and the one at the next index.
    try:
      is_crash = _testcase_reproduces_in_revision(
          testcase, testcase_file_path, job_type, revision_list[current_index])
    except errors.BadBuildError:
      # Skip this revision.
      continue

    if not is_crash:
      save_regression_range(testcase.key.id(), revision_list[current_index],
                            last_known_crashing_revision)
      return True

    last_known_crashing_revision = revision_list[current_index]

  # Test to see if we crash in the oldest revision we can run. This is a pre-
  # condition for our binary search. If we do crash in that revision, it
  # implies that we regressed between the first commit and our first revision,
  # which we represent as 0:|min_revision|.
  for _ in range(EXTREME_REVISIONS_TO_TEST):
    min_revision = revision_list[min_index]

    try:
      crashes_in_min_revision = _testcase_reproduces_in_revision(
          testcase,
          testcase_file_path,
          job_type,
          min_revision,
          should_log=False)
    except errors.BadBuildError:
      # If we find a bad build, potentially try another.
      if min_index + 1 >= max_index:
        break

      min_index += 1
      continue

    if crashes_in_min_revision:
      save_regression_range(testcase.key.id(), 0, min_revision)
      return True

    return False

  # We should have returned above. If we get here, it means we tried too many
  # builds near the min revision, and they were all bad.
  raise errors.BadBuildError(revision_list[min_index], job_type)


def validate_regression_range(testcase, testcase_file_path, job_type,
                              revision_list, min_index):
  """Ensure that we found the correct min revision by testing earlier ones."""
  earlier_revisions = revision_list[
      min_index - EARLIER_REVISIONS_TO_CONSIDER_FOR_VALIDATION:min_index]
  revision_count = min(len(earlier_revisions), REVISIONS_TO_TEST_FOR_VALIDATION)

  revisions_to_test = random.sample(earlier_revisions, revision_count)
  for revision in revisions_to_test:
    try:
      if _testcase_reproduces_in_revision(testcase, testcase_file_path,
                                          job_type, revision):
        testcase = data_handler.get_testcase_by_id(testcase.key.id())
        testcase.regression = 'NA'
        error_message = (
            'Low confidence in regression range. Test case crashes in '
            'revision r%d but not later revision r%d' %
            (revision, revision_list[min_index]))
        data_handler.update_testcase_comment(
            testcase, data_types.TaskState.ERROR, error_message)
        return False
    except errors.BadBuildError:
      pass

  return True


def find_regression_range(testcase_id, job_type):
  """Attempt to find when the testcase regressed."""
  deadline = tasks.get_task_completion_deadline()
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if not testcase:
    return

  if testcase.regression:
    logs.log_error(
        'Regression range is already set as %s, skip.' % testcase.regression)
    return

  # This task is not applicable for custom binaries.
  if build_manager.is_custom_binary():
    testcase.regression = 'NA'
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Not applicable for custom binaries')
    return

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  # Setup testcase and its dependencies.
  file_list, _, testcase_file_path = setup.setup_testcase(testcase, job_type)
  if not file_list:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Failed to setup testcase')
    tasks.add_task('regression', testcase_id, job_type)
    return

  build_bucket_path = build_manager.get_primary_bucket_path()
  revision_list = build_manager.get_revisions_list(
      build_bucket_path, testcase=testcase)
  if not revision_list:
    data_handler.close_testcase_with_error(testcase_id,
                                           'Failed to fetch revision list')
    return

  # Don't burden NFS server with caching these random builds.
  environment.set_value('CACHE_STORE', False)

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
    raise errors.BuildNotFoundError(min_revision, job_type)
  max_index = revisions.find_max_revision_index(revision_list, max_revision)
  if max_index is None:
    raise errors.BuildNotFoundError(max_revision, job_type)

  # Make sure that the revision where we noticed the crash, still crashes at
  # that revision. Otherwise, our binary search algorithm won't work correctly.
  max_revision = revision_list[max_index]
  crashes_in_max_revision = _testcase_reproduces_in_revision(
      testcase, testcase_file_path, job_type, max_revision, should_log=False)
  if not crashes_in_max_revision:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    error_message = ('Known crash revision %d did not crash' % max_revision)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         error_message)
    task_creation.mark_unreproducible_if_flaky(testcase, True)
    return

  # If we've made it this far, the test case appears to be reproducible. Clear
  # metadata from previous runs had it been marked as potentially flaky.
  task_creation.mark_unreproducible_if_flaky(testcase, False)

  # On the first run, check to see if we regressed near either the min or max
  # revision.
  if first_run and found_regression_near_extreme_revisions(
      testcase, testcase_file_path, job_type, revision_list, min_index,
      max_index):
    return

  while time.time() < deadline:
    min_revision = revision_list[min_index]
    max_revision = revision_list[max_index]

    # If the min and max revisions are one apart (or the same, if we only have
    # one build), this is as much as we can narrow the range.
    if max_index - min_index <= 1:
      # Verify that the regression range seems correct, and save it if so.
      if not validate_regression_range(testcase, testcase_file_path, job_type,
                                       revision_list, min_index):
        return

      save_regression_range(testcase_id, min_revision, max_revision)
      return

    middle_index = (min_index + max_index) // 2
    middle_revision = revision_list[middle_index]
    try:
      is_crash = _testcase_reproduces_in_revision(
          testcase,
          testcase_file_path,
          job_type,
          middle_revision,
          min_revision=min_revision,
          max_revision=max_revision)
    except errors.BadBuildError:
      # Skip this revision.
      del revision_list[middle_index]
      max_index -= 1
      continue

    if is_crash:
      max_index = middle_index
    else:
      min_index = middle_index

    _save_current_regression_range_indices(
        testcase_id, revision_list[min_index], revision_list[max_index])

  # If we've broken out of the above loop, we timed out. We'll finish by
  # running another regression task and picking up from this point.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  error_message = 'Timed out, current range r%d:r%d' % (
      revision_list[min_index], revision_list[max_index])
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       error_message)
  tasks.add_task('regression', testcase_id, job_type)


def execute_task(testcase_id, job_type):
  """Run regression task and handle potential errors."""
  try:
    find_regression_range(testcase_id, job_type)
  except errors.BuildSetupError as error:
    # If we failed to setup a build, it is likely a bot error. We can retry
    # the task in this case.
    testcase = data_handler.get_testcase_by_id(testcase_id)
    error_message = 'Build setup failed r%d' % error.revision
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         error_message)
    build_fail_wait = environment.get_value('FAIL_WAIT')
    tasks.add_task(
        'regression', testcase_id, job_type, wait_time=build_fail_wait)
  except errors.BadBuildError:
    # Though bad builds when narrowing the range are recoverable, certain builds
    # being marked as bad may be unrecoverable. Recoverable ones should not
    # reach this point.
    testcase = data_handler.get_testcase_by_id(testcase_id)
    testcase.regression = 'NA'
    error_message = 'Unable to recover from bad build'
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         error_message)

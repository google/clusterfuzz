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
"""Test to see if test cases are fixed."""

import time

from base import errors
from base import tasks
from base import utils
from bot.tasks import setup
from bot.tasks import task_creation
from build_management import build_manager
from build_management import revisions
from chrome import crash_uploader
from datastore import data_handler
from datastore import data_types
from fuzzing import tests
from google_cloud_utils import big_query
from issue_management import issue_tracker_utils
from metrics import logs
from system import environment

FIXED_REPORT_HEADER = 'ClusterFuzz has detected this issue as '
FIXED_REPORT_FOOTER = ('If you suspect that the result above is incorrect, '
                       'try re-doing that job on the test case report page.')


def _write_to_bigquery(testcase, progression_range_start,
                       progression_range_end):
  """Write the fixed range to BigQuery."""
  big_query.write_range(
      table_id='fixeds',
      testcase=testcase,
      range_name='fixed',
      start=progression_range_start,
      end=progression_range_end)


def _add_issue_comment(testcase, comment):
  """Helper function to add a comment to the bug associated with a test case."""
  if not testcase.bug_information:
    return

  # Populate the full message.
  report = data_handler.get_issue_description(testcase).rstrip('\n')
  full_comment = '%s\n\n%s\n\n%s' % (comment, report, FIXED_REPORT_FOOTER)

  # Update the issue.
  issue_tracker_manager = (
      issue_tracker_utils.get_issue_tracker_manager(testcase))
  issue = issue_tracker_manager.get_issue(int(testcase.bug_information))
  issue.comment = full_comment
  issue_tracker_manager.save(issue, send_email=True)


def _add_issue_comment_with_fixed_range(testcase):
  """Add the standard comment to the bug for a test case."""
  # Compose a build message based on build type.
  if build_manager.is_custom_binary():
    build_message = 'in the latest custom build'
  else:
    build_message = 'in range %s' % testcase.fixed

  comment = '%sfixed %s.' % (FIXED_REPORT_HEADER, build_message)
  _add_issue_comment(testcase, comment)


def _clear_progression_pending(testcase):
  """If we marked progression as pending for this testcase, clear that state."""
  if not testcase.get_metadata('progression_pending'):
    return

  testcase.delete_metadata('progression_pending', update_testcase=False)


def _update_completion_metadata(testcase, revision, is_crash=False):
  """Update metadata the progression task completes."""
  _clear_progression_pending(testcase)
  testcase.set_metadata('last_tested_revision', revision, update_testcase=False)
  if is_crash:
    testcase.set_metadata(
        'last_tested_crash_revision', revision, update_testcase=False)
    testcase.set_metadata(
        'last_tested_crash_time', utils.utcnow(), update_testcase=False)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED)


def _log_output(revision, crash_result):
  """Log process output."""
  logs.log(
      'Testing %s.' % revision,
      revision=revision,
      output=crash_result.get_stacktrace(symbolized=True))


def _check_fixed_for_custom_binary(testcase, job_type, testcase_file_path):
  """Simplified fixed check for test cases using custom binaries."""
  revision = environment.get_value('APP_REVISION')

  # Update comments to reflect bot information and clean up old comments.
  testcase_id = testcase.key.id()
  testcase = data_handler.get_testcase_by_id(testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  build_manager.setup_build()
  app_path = environment.get_value('APP_PATH')
  if not app_path:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.ERROR,
        'Build setup failed for custom binary')
    build_fail_wait = environment.get_value('FAIL_WAIT')
    tasks.add_task(
        'progression', testcase_id, job_type, wait_time=build_fail_wait)
    return

  testcase = data_handler.get_testcase_by_id(testcase.key.id())
  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  result = tests.test_for_crash_with_retries(
      testcase, testcase_file_path, test_timeout, http_flag=testcase.http_flag)
  _log_output(revision, result)

  # If this still crashes on the most recent build, it's not fixed. The task
  # will be rescheduled by a cron job and re-attempted eventually.
  if result.is_crash():
    command = tests.get_command_line_for_application(
        testcase_file_path, app_path=app_path, needs_http=testcase.http_flag)
    symbolized_crash_stacktrace = result.get_stacktrace(symbolized=True)
    unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
    stacktrace = utils.get_crash_stacktrace_output(
        command, symbolized_crash_stacktrace, unsymbolized_crash_stacktrace)
    testcase.last_tested_crash_stacktrace = data_handler.filter_stacktrace(
        stacktrace)
    _update_completion_metadata(testcase, revision, is_crash=True)
    return

  # Retry once on another bot to confirm our results and in case this bot is in
  # a bad state which we didn't catch through our usual means.
  if data_handler.is_first_retry_for_task(testcase, reset_after_retry=True):
    tasks.add_task('progression', testcase_id, job_type)
    _update_completion_metadata(testcase, revision)
    return

  # The bug is fixed.
  testcase.fixed = 'Yes'
  testcase.open = False
  _update_completion_metadata(testcase, revision)
  _add_issue_comment_with_fixed_range(testcase)


def _testcase_reproduces_in_revision(testcase, testcase_file_path, job_type,
                                     revision):
  """Test to see if a test case reproduces in the specified revision."""
  build_manager.setup_regular_build(revision)
  app_path = environment.get_value('APP_PATH')
  if not app_path:
    raise errors.BuildSetupError(revision, job_type)

  if tests.check_for_bad_build(job_type, revision):
    log_message = 'Bad build at r%d. Skipping' % revision
    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    data_handler.update_testcase_comment(testcase, data_types.TaskState.WIP,
                                         log_message)
    raise errors.BadBuildError(revision, job_type)

  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  result = tests.test_for_crash_with_retries(
      testcase, testcase_file_path, test_timeout, http_flag=testcase.http_flag)
  _log_output(revision, result)
  return result


def _save_current_fixed_range_indices(testcase_id, fixed_range_start,
                                      fixed_range_end):
  """Save current fixed range indices in case we die in middle of task."""
  testcase = data_handler.get_testcase_by_id(testcase_id)
  testcase.set_metadata(
      'last_progression_min', fixed_range_start, update_testcase=False)
  testcase.set_metadata(
      'last_progression_max', fixed_range_end, update_testcase=False)
  testcase.put()


def _save_fixed_range(testcase_id, min_revision, max_revision):
  """Update a test case and other metadata with a fixed range."""
  testcase = data_handler.get_testcase_by_id(testcase_id)
  testcase.fixed = '%d:%d' % (min_revision, max_revision)
  testcase.open = False
  _update_completion_metadata(testcase, max_revision)
  _add_issue_comment_with_fixed_range(testcase)
  _write_to_bigquery(testcase, min_revision, max_revision)


def find_fixed_range(testcase_id, job_type):
  """Attempt to find the revision range where a testcase was fixed."""
  deadline = tasks.get_task_completion_deadline()
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if not testcase:
    return

  if testcase.fixed:
    logs.log_error('Fixed range is already set as %s, skip.' % testcase.fixed)
    return

  # Setup testcase and its dependencies.
  file_list, _, testcase_file_path = setup.setup_testcase(testcase)
  if not file_list:
    return

  # Custom binaries are handled as special cases.
  if build_manager.is_custom_binary():
    _check_fixed_for_custom_binary(testcase, job_type, testcase_file_path)
    return

  release_build_bucket_path = environment.get_value('RELEASE_BUILD_BUCKET_PATH')
  revision_list = build_manager.get_revisions_list(
      release_build_bucket_path, testcase=testcase)
  if not revision_list:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Failed to fetch revision list')
    tasks.add_task('progression', testcase_id, job_type)
    return

  # Use min, max_index to mark the start and end of revision list that is used
  # for bisecting the progression range. Set start to the revision where noticed
  # the crash. Set end to the trunk revision. Also, use min, max from past run
  # if it timed out.
  min_revision = testcase.get_metadata('last_progression_min')
  max_revision = testcase.get_metadata('last_progression_max')
  last_tested_revision = testcase.get_metadata('last_tested_crash_revision')
  known_crash_revision = last_tested_revision or testcase.crash_revision
  if not min_revision:
    min_revision = known_crash_revision
  if not max_revision:
    max_revision = revisions.get_last_revision_in_list(revision_list)

  min_index = revisions.find_min_revision_index(revision_list, min_revision)
  if min_index is None:
    raise errors.BuildNotFoundError(min_revision, job_type)
  max_index = revisions.find_max_revision_index(revision_list, max_revision)
  if max_index is None:
    raise errors.BuildNotFoundError(max_revision, job_type)

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED,
                                       'r%d' % max_revision)

  # If there have been no updates since the build the crash was discovered in,
  # and this is not a redo testcase, then there is no work to do.
  is_redo_testcase = bool(testcase.get_metadata('progression_pending'))
  if not is_redo_testcase and testcase.crash_revision == max_revision:
    _update_completion_metadata(testcase, max_revision)
    return

  # Set progression status to true.
  testcase.set_metadata('progression_pending', True)

  # Check to see if this testcase is still crashing now. If it is, then just
  # bail out.
  result = _testcase_reproduces_in_revision(testcase, testcase_file_path,
                                            job_type, max_revision)
  if result.is_crash():
    logs.log('Found crash with same signature on latest revision r%d.' %
             max_revision)
    app_path = environment.get_value('APP_PATH')
    command = tests.get_command_line_for_application(
        testcase_file_path, app_path=app_path, needs_http=testcase.http_flag)
    symbolized_crash_stacktrace = result.get_stacktrace(symbolized=True)
    unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
    stacktrace = utils.get_crash_stacktrace_output(
        command, symbolized_crash_stacktrace, unsymbolized_crash_stacktrace)
    testcase.last_tested_crash_stacktrace = data_handler.filter_stacktrace(
        stacktrace)
    _update_completion_metadata(testcase, max_revision, is_crash=True)

    # Since we've verified that the test case is still crashing, clear out any
    # metadata indicating potential flake from previous runs.
    task_creation.mark_unreproducible_if_flaky(testcase, False)

    # For chromium project, save latest crash information for later upload
    # to chromecrash/.
    state = result.get_symbolized_data()
    crash_uploader.save_crash_info_if_needed(testcase_id, max_revision,
                                             job_type, state.crash_type,
                                             state.crash_address, state.frames)
    return

  # Don't burden NFS server with caching these random builds.
  environment.set_value('CACHE_STORE', False)

  # Verify that we do crash in the min revision. This is assumed to be true
  # while we are doing the bisect.
  result = _testcase_reproduces_in_revision(testcase, testcase_file_path,
                                            job_type, min_revision)
  if result and not result.is_crash():
    # Retry once on another bot to confirm our result.
    if data_handler.is_first_retry_for_task(testcase, reset_after_retry=True):
      tasks.add_task('progression', testcase_id, job_type)
      error_message = (
          'Known crash revision %d did not crash, will retry on another bot to '
          'confirm result' % known_crash_revision)
      data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                           error_message)
      _update_completion_metadata(testcase, max_revision)
      return

    testcase = data_handler.get_testcase_by_id(testcase_id)
    _clear_progression_pending(testcase)
    error_message = (
        'Known crash revision %d did not crash' % known_crash_revision)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         error_message)
    task_creation.mark_unreproducible_if_flaky(testcase, True)
    return

  # Start a binary search to find last non-crashing revision. At this point, we
  # know that we do crash in the min_revision, and do not crash in max_revision.
  while time.time() < deadline:
    min_revision = revision_list[min_index]
    max_revision = revision_list[max_index]

    # If the min and max revisions are one apart this is as much as we can
    # narrow the range.
    if max_index - min_index == 1:
      _save_fixed_range(testcase_id, min_revision, max_revision)
      return

    # Test the middle revision of our range.
    middle_index = (min_index + max_index) / 2
    middle_revision = revision_list[middle_index]

    testcase = data_handler.get_testcase_by_id(testcase_id)
    log_message = 'Testing r%d (current range %d:%d)' % (
        middle_revision, min_revision, max_revision)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.WIP,
                                         log_message)

    try:
      result = _testcase_reproduces_in_revision(testcase, testcase_file_path,
                                                job_type, middle_revision)
    except errors.BadBuildError:
      # Skip this revision.
      del revision_list[middle_index]
      max_index -= 1
      continue

    if result.is_crash():
      min_index = middle_index
    else:
      max_index = middle_index

    _save_current_fixed_range_indices(testcase_id, revision_list[min_index],
                                      revision_list[max_index])

  # If we've broken out of the loop, we've exceeded the deadline. Recreate the
  # task to pick up where we left off.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  error_message = ('Timed out, current range r%d:r%d' %
                   (revision_list[min_index], revision_list[max_index]))
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       error_message)
  tasks.add_task('progression', testcase_id, job_type)


def execute_task(testcase_id, job_type):
  """Execute progression task."""
  try:
    find_fixed_range(testcase_id, job_type)
  except errors.BuildSetupError as error:
    # If we failed to setup a build, it is likely a bot error. We can retry
    # the task in this case.
    testcase = data_handler.get_testcase_by_id(testcase_id)
    error_message = 'Build setup failed r%d' % error.revision
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         error_message)
    build_fail_wait = environment.get_value('FAIL_WAIT')
    tasks.add_task(
        'progression', testcase_id, job_type, wait_time=build_fail_wait)
  except errors.BadBuildError:
    # Though bad builds when narrowing the range are recoverable, certain builds
    # being marked as bad may be unrecoverable. Recoverable ones should not
    # reach this point.
    testcase = data_handler.get_testcase_by_id(testcase_id)
    error_message = 'Unable to recover from bad build'
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         error_message)

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

import os
import time

import six

from clusterfuzz._internal.base import bisection
from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.chrome import crash_uploader
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def _write_to_bigquery(testcase, progression_range_start,
                       progression_range_end):
  """Write the fixed range to BigQuery."""
  big_query.write_range(
      table_id='fixeds',
      testcase=testcase,
      range_name='fixed',
      start=progression_range_start,
      end=progression_range_end)


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
  if not build_manager.check_app_path():
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.ERROR,
        'Build setup failed for custom binary')
    build_fail_wait = environment.get_value('FAIL_WAIT')
    tasks.add_task(
        'progression', testcase_id, job_type, wait_time=build_fail_wait)
    return

  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  result = testcase_manager.test_for_crash_with_retries(
      testcase, testcase_file_path, test_timeout, http_flag=testcase.http_flag)
  _log_output(revision, result)

  # Re-fetch to finalize testcase updates in branches below.
  testcase = data_handler.get_testcase_by_id(testcase.key.id())

  # If this still crashes on the most recent build, it's not fixed. The task
  # will be rescheduled by a cron job and re-attempted eventually.
  if result.is_crash():
    app_path = environment.get_value('APP_PATH')
    command = testcase_manager.get_command_line_for_application(
        testcase_file_path, app_path=app_path, needs_http=testcase.http_flag)
    symbolized_crash_stacktrace = result.get_stacktrace(symbolized=True)
    unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
    stacktrace = utils.get_crash_stacktrace_output(
        command, symbolized_crash_stacktrace, unsymbolized_crash_stacktrace)
    testcase.last_tested_crash_stacktrace = data_handler.filter_stacktrace(
        stacktrace)
    data_handler.update_progression_completion_metadata(
        testcase,
        revision,
        is_crash=True,
        message='still crashes on latest custom build')
    return

  # Retry once on another bot to confirm our results and in case this bot is in
  # a bad state which we didn't catch through our usual means.
  if data_handler.is_first_retry_for_task(testcase, reset_after_retry=True):
    tasks.add_task('progression', testcase_id, job_type)
    data_handler.update_progression_completion_metadata(testcase, revision)
    return

  # The bug is fixed.
  testcase.fixed = 'Yes'
  testcase.open = False
  data_handler.update_progression_completion_metadata(
      testcase, revision, message='fixed on latest custom build')


def _update_issue_metadata(testcase):
  """Update issue metadata."""
  if testcase.uploader_email:
    # Trust the uploader specified metadata.
    return

  metadata = engine_common.get_all_issue_metadata_for_testcase(testcase)
  if not metadata:
    return

  for key, value in six.iteritems(metadata):
    old_value = testcase.get_metadata(key)
    if old_value != value:
      logs.log('Updating issue metadata for {} from {} to {}.'.format(
          key, old_value, value))
      testcase.set_metadata(key, value)


def _testcase_reproduces_in_revision(testcase,
                                     testcase_file_path,
                                     job_type,
                                     revision,
                                     update_metadata=False):
  """Test to see if a test case reproduces in the specified revision."""
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
  _log_output(revision, result)

  if update_metadata:
    _update_issue_metadata(testcase)

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


def _save_fixed_range(testcase_id, min_revision, max_revision,
                      testcase_file_path):
  """Update a test case and other metadata with a fixed range."""
  testcase = data_handler.get_testcase_by_id(testcase_id)
  testcase.fixed = '%d:%d' % (min_revision, max_revision)
  testcase.open = False

  data_handler.update_progression_completion_metadata(
      testcase, max_revision, message='fixed in range r%s' % testcase.fixed)
  _write_to_bigquery(testcase, min_revision, max_revision)

  _store_testcase_for_regression_testing(testcase, testcase_file_path)


def _store_testcase_for_regression_testing(testcase, testcase_file_path):
  """Stores reproduction testcase for future regression testing in corpus
  pruning task."""
  if testcase.open:
    # Store testcase only after the crash is fixed.
    return

  if not testcase.bug_information:
    # Only store crashes with bugs associated with them.
    return

  fuzz_target = data_handler.get_fuzz_target(testcase.overridden_fuzzer_name)
  if not fuzz_target:
    # No work to do, only applicable for engine fuzzers.
    return

  corpus = corpus_manager.FuzzTargetCorpus(fuzz_target.engine,
                                           fuzz_target.project_qualified_name())
  regression_testcase_url = os.path.join(
      corpus.get_regressions_corpus_gcs_url(),
      utils.file_hash(testcase_file_path))

  if storage.copy_file_to(testcase_file_path, regression_testcase_url):
    logs.log('Successfully stored testcase for regression testing: ' +
             regression_testcase_url)
  else:
    logs.log_error('Failed to store testcase for regression testing: ' +
                   regression_testcase_url)


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
  file_list, _, testcase_file_path = setup.setup_testcase(testcase, job_type)
  if not file_list:
    return

  # Set a flag to indicate we are running progression task. This shows pending
  # status on testcase report page and avoid conflicting testcase updates by
  # triage cron.
  testcase.set_metadata('progression_pending', True)

  # Custom binaries are handled as special cases.
  if build_manager.is_custom_binary():
    _check_fixed_for_custom_binary(testcase, job_type, testcase_file_path)
    return

  build_bucket_path = build_manager.get_primary_bucket_path()
  revision_list = build_manager.get_revisions_list(
      build_bucket_path, testcase=testcase)
  if not revision_list:
    data_handler.close_testcase_with_error(testcase_id,
                                           'Failed to fetch revision list')
    return

  # Use min, max_index to mark the start and end of revision list that is used
  # for bisecting the progression range. Set start to the revision where noticed
  # the crash. Set end to the trunk revision. Also, use min, max from past run
  # if it timed out.
  min_revision = testcase.get_metadata('last_progression_min')
  max_revision = testcase.get_metadata('last_progression_max')

  if min_revision or max_revision:
    # Clear these to avoid using them in next run. If this run fails, then we
    # should try next run without them to see it succeeds. If this run succeeds,
    # we should still clear them to avoid capping max revision in next run.
    testcase = data_handler.get_testcase_by_id(testcase_id)
    testcase.delete_metadata('last_progression_min', update_testcase=False)
    testcase.delete_metadata('last_progression_max', update_testcase=False)
    testcase.put()

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

  testcase = data_handler.get_testcase_by_id(testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED,
                                       'r%d' % max_revision)

  # Check to see if this testcase is still crashing now. If it is, then just
  # bail out.
  result = _testcase_reproduces_in_revision(
      testcase,
      testcase_file_path,
      job_type,
      max_revision,
      update_metadata=True)
  if result.is_crash():
    logs.log('Found crash with same signature on latest revision r%d.' %
             max_revision)
    app_path = environment.get_value('APP_PATH')
    command = testcase_manager.get_command_line_for_application(
        testcase_file_path, app_path=app_path, needs_http=testcase.http_flag)
    symbolized_crash_stacktrace = result.get_stacktrace(symbolized=True)
    unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
    stacktrace = utils.get_crash_stacktrace_output(
        command, symbolized_crash_stacktrace, unsymbolized_crash_stacktrace)
    testcase = data_handler.get_testcase_by_id(testcase_id)
    testcase.last_tested_crash_stacktrace = data_handler.filter_stacktrace(
        stacktrace)
    data_handler.update_progression_completion_metadata(
        testcase,
        max_revision,
        is_crash=True,
        message='still crashes on latest revision r%s' % max_revision)

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
    testcase = data_handler.get_testcase_by_id(testcase_id)

    # Retry once on another bot to confirm our result.
    if data_handler.is_first_retry_for_task(testcase, reset_after_retry=True):
      tasks.add_task('progression', testcase_id, job_type)
      error_message = (
          'Known crash revision %d did not crash, will retry on another bot to '
          'confirm result' % known_crash_revision)
      data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                           error_message)
      data_handler.update_progression_completion_metadata(
          testcase, max_revision)
      return

    data_handler.clear_progression_pending(testcase)
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
      _save_fixed_range(testcase_id, min_revision, max_revision,
                        testcase_file_path)
      return

    # Occasionally, we get into this bad state. It seems to be related to test
    # cases with flaky stacks, but the exact cause is unknown.
    if max_index - min_index < 1:
      testcase = data_handler.get_testcase_by_id(testcase_id)
      testcase.fixed = 'NA'
      testcase.open = False
      message = ('Fixed testing errored out (min and max revisions '
                 'are both %d)' % min_revision)
      data_handler.update_progression_completion_metadata(
          testcase, max_revision, message=message)

      # Let the bisection service know about the NA status.
      bisection.request_bisection(testcase)
      return

    # Test the middle revision of our range.
    middle_index = (min_index + max_index) // 2
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

  # If there is a fine grained bisection service available, request it. Both
  # regression and fixed ranges are requested once. Regression is also requested
  # here as the bisection service may require details that are not yet available
  # (e.g. issue ID) at the time regress_task completes.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  bisection.request_bisection(testcase)

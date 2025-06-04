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

import json
import time
from typing import Dict
from typing import List
from typing import Optional

from clusterfuzz._internal.base import bisection
from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.bot.tasks.utasks import uworker_handle_errors
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment


def _maybe_clear_progression_last_min_max_metadata(
    testcase: data_types.Testcase, uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Clears last_progression_min and last_progression_max when
  clear_min_max_metadata is set to True"""
  if not uworker_output.HasField('progression_task_output'):
    return

  task_output = uworker_output.progression_task_output
  if task_output.clear_min_max_metadata:
    testcase.delete_metadata('last_progression_min', update_testcase=False)
    testcase.delete_metadata('last_progression_max', update_testcase=False)
    testcase.put()


def _update_build_metadata(job_type: str,
                           build_data_list: List[uworker_msg_pb2.BuildData]):  # pylint: disable=no-member
  """A helper method to update the build metadata corresponding to a
  job_type."""
  for build_data in build_data_list:
    testcase_manager.update_build_metadata(job_type, build_data)


def _save_current_fixed_range_indices(testcase, uworker_output):
  """Save current fixed range indices in case we die in middle of task."""
  task_output = uworker_output.progression_task_output
  last_progression_min = None
  last_progression_max = None

  if task_output.HasField('last_progression_min'):
    last_progression_min = task_output.last_progression_min
  if task_output.HasField('last_progression_max'):
    last_progression_max = task_output.last_progression_max

  testcase.set_metadata(
      'last_progression_min', last_progression_min, update_testcase=False)
  testcase.set_metadata(
      'last_progression_max', last_progression_max, update_testcase=False)


def handle_progression_timeout(uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Job has exceeded the deadline. Recreate the task to pick up where we left
  off."""
  testcase_id = uworker_output.uworker_input.testcase_id
  job_type = uworker_output.uworker_input.job_type
  testcase = data_handler.get_testcase_by_id(testcase_id)
  _save_current_fixed_range_indices(testcase, uworker_output)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       uworker_output.error_message)
  tasks.add_task('progression', testcase_id, job_type)


def handle_progression_build_not_found(uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Handles an expected build that no longer exists, we can't continue. Also,
  clears progression_pending testcase metadata"""
  testcase_id = uworker_output.uworker_input.testcase_id
  testcase = data_handler.get_testcase_by_id(testcase_id)
  testcase.fixed = 'NA'
  testcase.open = False
  data_handler.clear_progression_pending(testcase)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       uworker_output.error_message)


def handle_progression_revision_list_error(
    uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Handles revision list errors, in which case the testcase is closed with
  error."""
  testcase_id = uworker_output.uworker_input.testcase_id
  testcase = data_handler.get_testcase_by_id(testcase_id)
  data_handler.close_testcase_with_error(testcase,
                                         'Failed to fetch revision list')


def _cleanup_stacktrace_blob_from_storage(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Cleanup the blob created in preprocess if it wasn't used to store the
  filterd stacktrace."""
  if output.HasField('progression_task_output'):
    stacktrace = output.progression_task_output.last_tested_crash_stacktrace
    if stacktrace.startswith(data_types.BLOBSTORE_STACK_PREFIX):
      return

  if not output.uworker_input.progression_task_input.blob_name:
    raise ValueError('blob_name should not be empty here.')
  blob_name = output.uworker_input.progression_task_input.blob_name

  blobs.delete_blob(blob_name)


def crash_on_latest(uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Handles crash on latest revision, or custom binary crashes. Saves the crash
  info for non-custom binaries."""
  testcase_id = uworker_output.uworker_input.testcase_id
  progression_task_output = uworker_output.progression_task_output
  testcase = data_handler.get_testcase_by_id(testcase_id)

  testcase.last_tested_crash_stacktrace = (
      progression_task_output.last_tested_crash_stacktrace)
  data_handler.update_progression_completion_metadata(
      testcase,
      progression_task_output.crash_revision,
      is_crash=True,
      message=progression_task_output.crash_on_latest_message)

  # This means we are in a custom binary crash, we do not upload crash info.
  if uworker_output.uworker_input.progression_task_input.custom_binary:
    return

  # Since we've verified that the test case is still crashing, clear out any
  # metadata indicating potential flake from previous runs.
  task_creation.mark_unreproducible_if_flaky(testcase, 'progression', False)


def handle_progression_bad_state_min_max(
    uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Handles when we end up in a state having min and max versions the same
  during a progression."""
  testcase = data_handler.get_testcase_by_id(
      uworker_output.uworker_input.testcase_id)
  _save_current_fixed_range_indices(testcase, uworker_output)
  testcase.fixed = 'NA'
  testcase.open = False
  message = ('Fixed testing errored out (min and max revisions are both '
             f'{uworker_output.progression_task_output.min_revision}')

  data_handler.update_progression_completion_metadata(
      testcase,
      uworker_output.progression_task_output.max_revision,
      message=message)

  # Let the bisection service know about the NA status.
  bisection.request_bisection(testcase)


def handle_progression_no_crash(uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Expected crash version doesn't crash. Retries once to confirm the result
  otherwise marks unreproducible if the testcase is flaky."""
  testcase_id = uworker_output.uworker_input.testcase_id
  job_type = uworker_output.uworker_input.job_type
  testcase = data_handler.get_testcase_by_id(testcase_id)
  # Retry once on another bot to confirm our result.
  if data_handler.is_first_attempt_for_task(
      'progression', testcase, reset_after_retry=True):
    tasks.add_task('progression', testcase_id, job_type)
    error_message = (
        uworker_output.error_message +
        ', will retry on another bot to confirm result.')
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         error_message)
    data_handler.update_progression_completion_metadata(
        testcase, uworker_output.progression_task_output.crash_revision)
    return

  data_handler.clear_progression_pending(testcase)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       uworker_output.error_message)
  task_creation.mark_unreproducible_if_flaky(testcase, 'progression', True)
  return


def handle_progression_build_setup_error(
    uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Handles errors for scenarios where build setup fails."""
  # If we failed to setup a build, it is likely a bot error. We can retry
  # the task in this case.
  testcase_id = uworker_output.uworker_input.testcase_id
  job_type = uworker_output.uworker_input.job_type
  testcase = data_handler.get_testcase_by_id(testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       uworker_output.error_message)
  build_fail_wait = environment.get_value('FAIL_WAIT')
  tasks.add_task(
      'progression', testcase_id, job_type, wait_time=build_fail_wait)


def handle_progression_bad_build(uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Handles unrecoverable bad build errors."""
  # Though bad builds when narrowing the range are recoverable, certain builds
  # being marked as bad may be unrecoverable. Recoverable ones should not
  # reach this point.
  testcase_id = uworker_output.uworker_input.testcase_id
  testcase = data_handler.get_testcase_by_id(testcase_id)
  error_message = 'Unable to recover from bad build'
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       error_message)


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
  logs.info(
      f'Testing {revision}',
      revision=revision,
      output=crash_result.get_stacktrace(symbolized=True))


def _check_fixed_for_custom_binary(testcase: data_types.Testcase,
                                   testcase_file_path: str,
                                   uworker_input: uworker_msg_pb2.Input):  # pylint: disable=no-member
  """Simplified fixed check for test cases using custom binaries."""
  build_setup_result = build_manager.setup_build()
  # 'APP_REVISION' is set during setup_build().
  revision = environment.get_value('APP_REVISION')
  if revision is None:
    logs.error('APP_REVISION is not set, setting revision to 0')
    revision = 0

  if not build_setup_result or not build_manager.check_app_path():
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_message='Build setup failed for custom binary',
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP_ERROR)  # pylint: disable=no-member

  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  fuzz_target = testcase_manager.get_fuzz_target_from_input(uworker_input)
  result = testcase_manager.test_for_crash_with_retries(
      fuzz_target,
      testcase,
      testcase_file_path,
      test_timeout,
      http_flag=testcase.http_flag)
  _log_output(revision, result)

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
    progression_task_input = uworker_input.progression_task_input
    last_tested_crash_stacktrace = data_handler.filter_stacktrace(
        stacktrace, progression_task_input.blob_name,
        progression_task_input.stacktrace_upload_url)
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput(
        crash_on_latest=True,
        crash_on_latest_message='Still crashes on latest custom build.',
        crash_revision=int(revision),
        last_tested_crash_stacktrace=last_tested_crash_stacktrace)
    return uworker_msg_pb2.Output(
        progression_task_output=progression_task_output)

  progression_task_output = uworker_msg_pb2.ProgressionTaskOutput(  # pylint: disable=no-member
      crash_revision=int(revision))
  return uworker_msg_pb2.Output(progression_task_output=progression_task_output)  # pylint: disable=no-member


def _update_issue_metadata(testcase: data_types.Testcase, metadata: Dict):
  if not metadata:
    return

  for key, value in metadata.items():
    old_value = testcase.get_metadata(key)
    if old_value != value:
      logs.info(
          f'Updating issue metadata for {key} from {old_value} to {value}.')
      testcase.set_metadata(key, value)


def _testcase_reproduces_in_revision(
    testcase: data_types.Testcase, testcase_file_path: str, job_type: str,
    revision: int, fuzz_target: Optional[data_types.FuzzTarget],
    progression_task_output: uworker_msg_pb2.ProgressionTaskOutput):  # pylint: disable=no-member
  """Tests to see if a test case reproduces in the specified revision.
  Returns a tuple containing the (result, error) depending on whether
  there was an error."""
  try:
    fuzz_target_binary = fuzz_target.binary if fuzz_target else None
    build_setup_result = build_manager.setup_build(
        revision, fuzz_target=fuzz_target_binary)
  except errors.BuildNotFoundError as e:
    # Build no longer exists, so we need to mark this testcase as invalid.
    error_message = f'Build not found at r{e.revision}'
    return None, uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_message=error_message,
        progression_task_output=progression_task_output,
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_NOT_FOUND)  # pylint: disable=no-member

  if not build_setup_result:
    # Let postprocess handle the failure and reschedule the task if needed.
    error_message = f'Build setup failed at r{revision}'
    return None, uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_message=error_message,
        progression_task_output=progression_task_output,
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP_ERROR)  # pylint: disable=no-member

  build_data = testcase_manager.check_for_bad_build(job_type, revision)
  progression_task_output.build_data_list.append(build_data)
  if build_data.is_bad_build:
    # TODO(alhijazi): This is not logged for recoverable builds.
    error_message = f'Bad build at r{revision}. Skipping'
    return None, uworker_msg_pb2.Output(  # pylint: disable=no-member
        progression_task_output=progression_task_output,
        error_message=error_message,
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD)  # pylint: disable=no-member

  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  result = testcase_manager.test_for_crash_with_retries(
      fuzz_target,
      testcase,
      testcase_file_path,
      test_timeout,
      http_flag=testcase.http_flag)
  _log_output(revision, result)
  return result, None


def _save_fixed_range(testcase_id, min_revision, max_revision):
  """Update a test case and other metadata with a fixed range."""
  testcase = data_handler.get_testcase_by_id(testcase_id)
  testcase.fixed = f'{min_revision}:{max_revision}'
  testcase.open = False
  data_handler.update_progression_completion_metadata(
      testcase, max_revision, message=f'fixed in range r{testcase.fixed}')
  _write_to_bigquery(testcase, min_revision, max_revision)
  bisection.request_bisection(testcase)


def _store_testcase_for_regression_testing(
    testcase: data_types.Testcase, testcase_file_path: str,
    progression_task_input: uworker_msg_pb2.ProgressionTaskInput):  # pylint: disable=no-member
  """Stores reproduction testcase for future regression testing in corpus
  pruning task."""
  if testcase.open:
    # Store testcase only after the crash is fixed.
    return

  if not testcase.bug_information:
    # Only store crashes with bugs associated with them.
    return

  if not progression_task_input.HasField('regression_testcase_url'):
    return

  regression_testcase_url = progression_task_input.regression_testcase_url

  with open(testcase_file_path, 'rb') as testcase_file_handle:
    testcase_file = testcase_file_handle.read()
    try:
      storage.upload_signed_url(testcase_file, regression_testcase_url)
      logs.info('Successfully stored testcase for regression testing: ' +
                regression_testcase_url)
    except:
      logs.error('Failed to store testcase for regression testing: ' +
                 regression_testcase_url)


def _set_regression_testcase_upload_url(
    progression_input: uworker_msg_pb2.ProgressionTaskInput,  # pylint: disable=no-member
    testcase: data_types.Testcase):
  """Determines and sets the signed regression_testcase_url (if any) in
  the progression task input.
  Raises RuntimeError in case of UUID collision on the generated filename.
  """
  fuzz_target = data_handler.get_fuzz_target(testcase.overridden_fuzzer_name)
  if not fuzz_target:
    # No work to do, only applicable for engine fuzzers.
    return

  if not testcase.trusted:
    logs.warning('Not saving untrusted testcase to regression corpus.')
    return

  # We probably don't need these checks, but do them anyway since it is
  # important not to mess this up.
  if testcase.uploader_email:
    logs.error(
        'Not saving uploaded testcase to regression corpus (uploaded not set).')
    return
  upload_metadata = data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.testcase_id == testcase.key.id()).get()
  if upload_metadata:
    logs.error('Not saving uploaded testcase to regression corpus '
               '(uploaded and email not set).')
    return
  progression_input.regression_testcase_url = (
      corpus_manager.get_regressions_signed_upload_url(
          fuzz_target.engine, fuzz_target.project_qualified_name()))


def utask_preprocess(testcase_id, job_type, uworker_env):
  """Runs preprocessing for progression task."""
  testcase = data_handler.get_testcase_by_id(testcase_id)
  with logs.testcase_log_context(testcase, testcase.get_fuzz_target()):
    if not testcase:
      return None
    if testcase.fixed:
      logs.error(f'Fixed range is already set as {testcase.fixed}, skip.')
      return None

    # Set a flag to indicate we are running progression task. This shows pending
    # status on testcase report page and avoid conflicting testcase updates by
    # triage cron.
    testcase.set_metadata('progression_pending', True)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)
    blob_name, blob_upload_url = blobs.get_blob_signed_upload_url()
    progression_input = uworker_msg_pb2.ProgressionTaskInput(  # pylint: disable=no-member
        custom_binary=build_manager.is_custom_binary(),
        bad_revisions=build_manager.get_job_bad_revisions(),
        blob_name=blob_name,
        stacktrace_upload_url=blob_upload_url)
    # Setup testcase and its dependencies.
    setup_input = setup.preprocess_setup_testcase(testcase, uworker_env)

    _set_regression_testcase_upload_url(progression_input, testcase)
    uworker_input = uworker_msg_pb2.Input(  # pylint: disable=no-member
        job_type=job_type,
        testcase_id=str(testcase_id),
        uworker_env=uworker_env,
        progression_task_input=progression_input,
        testcase=uworker_io.entity_to_protobuf(testcase),
        setup_input=setup_input)

    testcase_manager.preprocess_testcase_manager(testcase, uworker_input)
    return uworker_input


def find_fixed_range(uworker_input):
  """Attempt to find the revision range where a testcase was fixed."""
  deadline = tasks.get_task_completion_deadline()
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  job_type = uworker_input.job_type
  setup_input = uworker_input.setup_input
  fuzz_target = testcase_manager.get_fuzz_target_from_input(uworker_input)

  _, testcase_file_path, error = setup.setup_testcase(testcase, job_type,
                                                      setup_input)
  if error:
    return error

  # Custom binaries are handled as special cases.
  if build_manager.is_custom_binary():
    return _check_fixed_for_custom_binary(testcase, testcase_file_path,
                                          uworker_input)

  build_bucket_path = build_manager.get_primary_bucket_path()
  bad_revisions = uworker_input.progression_task_input.bad_revisions

  revision_list = build_manager.get_revisions_list(
      build_bucket_path, bad_revisions, testcase=testcase)
  if not revision_list:
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_REVISION_LIST_ERROR)  # pylint: disable=no-member

  # Use min, max_index to mark the start and end of revision list that is used
  # for bisecting the progression range. Set start to the revision where noticed
  # the crash. Set end to the trunk revision. Also, use min, max from past run
  # if it timed out.
  min_revision = testcase.get_metadata('last_progression_min')
  max_revision = testcase.get_metadata('last_progression_max')
  progression_task_output = uworker_msg_pb2.ProgressionTaskOutput(  # pylint: disable=no-member
      clear_min_max_metadata=False,
      build_data_list=[])
  if min_revision or max_revision:
    # Clear these to avoid using them in next run. If this run fails, then we
    # should try next run without them to see it succeeds. If this run succeeds,
    # we should still clear them to avoid capping max revision in next run.
    progression_task_output.clear_min_max_metadata = True

  last_tested_revision = testcase.get_metadata('last_tested_crash_revision')
  known_crash_revision = last_tested_revision or testcase.crash_revision
  if not min_revision:
    min_revision = known_crash_revision
    # If the min_revision (based on last_tested_crash_revision or
    # known_crash_revision) no longer exists, then use the first
    # revision in the list so that progression does not error out with
    # "Build not found"
    min_revision_in_list = revisions.get_first_revision_in_list(revision_list)
    if min_revision < min_revision_in_list:
      logs.info(f'Build {min_revision} might not exist in the list. Hence '
                f'updating the min_revision to {min_revision_in_list}')
      min_revision = min_revision_in_list
  if not max_revision:
    max_revision = revisions.get_last_revision_in_list(revision_list)

  logs.info(
      f'min_revision is {min_revision} and max_revision is {max_revision}.')

  min_index = revisions.find_min_revision_index(revision_list, min_revision)
  if min_index is None:
    error_message = f'Build {min_revision} no longer exists.'
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_message=error_message,
        progression_task_output=progression_task_output,
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_NOT_FOUND)  # pylint: disable=no-member
  max_index = revisions.find_max_revision_index(revision_list, max_revision)
  if max_index is None:
    error_message = f'Build {max_revision} no longer exists.'
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_message=error_message,
        progression_task_output=progression_task_output,
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_NOT_FOUND)  # pylint: disable=no-member

  # Check to see if this testcase is still crashing now. If it is, then just
  # bail out.
  result, error = _testcase_reproduces_in_revision(
      testcase, testcase_file_path, job_type, max_revision, fuzz_target,
      progression_task_output)

  issue_metadata = engine_common.get_fuzz_target_issue_metadata(fuzz_target)
  issue_metadata = issue_metadata or {}

  if error is not None:
    return error

  if result.is_crash():
    logs.info(f'Found crash with same signature on latest'
              f' revision r{max_revision}.')
    app_path = environment.get_value('APP_PATH')
    command = testcase_manager.get_command_line_for_application(
        testcase_file_path, app_path=app_path, needs_http=testcase.http_flag)
    symbolized_crash_stacktrace = result.get_stacktrace(symbolized=True)
    unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
    stacktrace = utils.get_crash_stacktrace_output(
        command, symbolized_crash_stacktrace, unsymbolized_crash_stacktrace)

    last_tested_crash_stacktrace = data_handler.filter_stacktrace(
        stacktrace, uworker_input.progression_task_input.blob_name,
        uworker_input.progression_task_input.stacktrace_upload_url)

    crash_on_latest_message = ('Still crashes on latest'
                               f' revision r{max_revision}.')
    progression_task_output.crash_on_latest = True
    progression_task_output.crash_on_latest_message = crash_on_latest_message
    progression_task_output.crash_revision = int(max_revision)
    progression_task_output.last_tested_crash_stacktrace = (
        last_tested_crash_stacktrace)
    return uworker_msg_pb2.Output(
        progression_task_output=progression_task_output,
        issue_metadata=json.dumps(issue_metadata))

  # Verify that we do crash in the min revision. This is assumed to be true
  # while we are doing the bisect.
  result, error = _testcase_reproduces_in_revision(
      testcase, testcase_file_path, job_type, min_revision, fuzz_target,
      progression_task_output)
  if error is not None:
    return error

  if result and not result.is_crash():
    error_message = f'Minimum revision r{min_revision} did not crash.'
    progression_task_output.crash_revision = int(min_revision)
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        progression_task_output=progression_task_output,
        issue_metadata=json.dumps(issue_metadata),
        error_message=error_message,
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_NO_CRASH)  # pylint: disable=no-member

  last_progression_min = None
  last_progression_max = None
  # Start a binary search to find last non-crashing revision. At this point, we
  # know that we do crash in the min_revision, and do not crash in max_revision.
  while time.time() < deadline:
    min_revision = revision_list[min_index]
    max_revision = revision_list[max_index]

    # If the min and max revisions are one apart this is as much as we can
    # narrow the range.
    if max_index - min_index == 1:
      testcase.open = False
      _store_testcase_for_regression_testing(
          testcase, testcase_file_path, uworker_input.progression_task_input)
      progression_task_output.min_revision = int(min_revision)
      progression_task_output.max_revision = int(max_revision)
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          progression_task_output=progression_task_output,
          issue_metadata=json.dumps(issue_metadata))

    # Occasionally, we get into this bad state. It seems to be related to test
    # cases with flaky stacks, but the exact cause is unknown.
    if max_index - min_index < 1:
      progression_task_output.min_revision = int(min_revision)
      progression_task_output.max_revision = int(max_revision)
      # We could be in a bad state from the beginning of this loop. In that
      # case, both last_progression_min and last_progression_max would be None.
      if last_progression_min:
        progression_task_output.last_progression_min = int(last_progression_min)
      if last_progression_max:
        progression_task_output.last_progression_max = int(last_progression_max)
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          progression_task_output=progression_task_output,
          issue_metadata=json.dumps(issue_metadata),
          error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BAD_STATE_MIN_MAX)  # pylint: disable=no-member

    # Test the middle revision of our range.
    middle_index = (min_index + max_index) // 2
    middle_revision = revision_list[middle_index]

    result, error = _testcase_reproduces_in_revision(
        testcase, testcase_file_path, job_type, middle_revision, fuzz_target,
        progression_task_output)
    if error is not None:
      if error.error_type == uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD:  # pylint: disable=no-member
        # Skip this revision.
        del revision_list[middle_index]
        max_index -= 1
        continue
      # Only bad build errors are recoverable.
      progression_task_output.last_progression_min = int(last_progression_min)
      progression_task_output.last_progression_max = int(last_progression_max)
      error.progression_task_output.CopyFrom(progression_task_output)
      return error

    if result.is_crash():
      min_index = middle_index
    else:
      max_index = middle_index

    last_progression_min = int(revision_list[min_index])
    last_progression_max = int(revision_list[max_index])

  # If we've broken out of the loop, we've exceeded the deadline. Recreate the
  # task to pick up where we left off.
  error_message = (f'Timed out, current range '
                   f'r{revision_list[min_index]}:r{revision_list[max_index]}')
  if last_progression_min is not None:
    progression_task_output.last_progression_min = last_progression_min
  if last_progression_max is not None:
    progression_task_output.last_progression_max = last_progression_max
  return uworker_msg_pb2.Output(  # pylint: disable=no-member
      error_message=error_message,
      issue_metadata=json.dumps(issue_metadata),
      progression_task_output=progression_task_output,
      error_type=uworker_msg_pb2.ErrorType.PROGRESSION_TIMEOUT)  # pylint: disable=no-member


def utask_main(uworker_input):
  """Executes the untrusted part of progression_task."""
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  with logs.testcase_log_context(
      testcase, testcase_manager.get_fuzz_target_from_input(uworker_input)):
    uworker_io.check_handling_testcase_safe(testcase)
    return find_fixed_range(uworker_input)


_ERROR_HANDLER = uworker_handle_errors.CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD:  # pylint: disable=no-member
        handle_progression_bad_build,
    uworker_msg_pb2.ErrorType.PROGRESSION_BAD_STATE_MIN_MAX:  # pylint: disable=no-member
        handle_progression_bad_state_min_max,
    uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_NOT_FOUND:  # pylint: disable=no-member
        handle_progression_build_not_found,
    uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP_ERROR:  # pylint: disable=no-member
        handle_progression_build_setup_error,
    uworker_msg_pb2.ErrorType.PROGRESSION_NO_CRASH:  # pylint: disable=no-member
        handle_progression_no_crash,
    uworker_msg_pb2.ErrorType.PROGRESSION_REVISION_LIST_ERROR:  # pylint: disable=no-member
        handle_progression_revision_list_error,
    uworker_msg_pb2.ErrorType.PROGRESSION_TIMEOUT:  # pylint: disable=no-member
        handle_progression_timeout,
}).compose_with(
    setup.ERROR_HANDLER,
    uworker_handle_errors.UNHANDLED_ERROR_HANDLER,
)


def utask_postprocess(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Trusted: Cleans up after a uworker execute_task, writing anything needed to
  the db."""
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  with logs.testcase_log_context(testcase, testcase.get_fuzz_target()):
    _maybe_clear_progression_last_min_max_metadata(testcase, output)
    _cleanup_stacktrace_blob_from_storage(output)
    task_output = None

    if output.issue_metadata:
      _update_issue_metadata(testcase, json.loads(output.issue_metadata))

    if output.HasField('progression_task_output'):
      task_output = output.progression_task_output
      _update_build_metadata(output.uworker_input.job_type,
                             task_output.build_data_list)

    if output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
      _ERROR_HANDLER.handle(output)
      return

    # If there is a fine grained bisection service available, request it.
    # Both regression and fixed ranges are requested once. Regression is also
    # requested here as the bisection service may require details that
    # are not yet available (e.g. issue ID) at the time regress_task completes.
    bisection.request_bisection(testcase)

    if task_output and task_output.crash_on_latest:
      crash_on_latest(output)
      return

    if output.uworker_input.progression_task_input.custom_binary:
      # Retry once on another bot to confirm our results and in case this bot is
      # in a bad state which we didn't catch through our usual means.
      if data_handler.is_first_attempt_for_task(
          'progression', testcase, reset_after_retry=True):
        tasks.add_task('progression', output.uworker_input.testcase_id,
                       output.uworker_input.job_type)
        data_handler.update_progression_completion_metadata(
            testcase, task_output.crash_revision)
        return

      # The bug is fixed.
      testcase.fixed = 'Yes'
      testcase.open = False
      data_handler.update_progression_completion_metadata(
          testcase,
          task_output.crash_revision,
          message='fixed on latest custom build')
      return

    testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
    if task_output.HasField('min_revision'):
      _save_fixed_range(output.uworker_input.testcase_id,
                        task_output.min_revision, task_output.max_revision)

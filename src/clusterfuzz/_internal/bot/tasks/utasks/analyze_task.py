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
"""Analyze task for handling user uploads."""

import datetime
from typing import Optional

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
from clusterfuzz._internal.chrome import crash_uploader
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis import severity_analyzer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import leak_blacklist
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment


def _add_default_issue_metadata(testcase):
  """Adds the default issue metadata (e.g. components, labels) to testcase."""
  default_metadata = engine_common.get_all_issue_metadata_for_testcase(testcase)
  if not default_metadata:
    return

  testcase_metadata = testcase.get_metadata()
  for key, default_value in default_metadata.items():
    # Only string metadata are supported.
    if not isinstance(default_value, str):
      continue

    # Add the default issue metadata first. This gives preference to uploader
    # specified issue metadata.
    new_value_list = utils.parse_delimited(
        default_value, delimiter=',', strip=True, remove_empty=True)

    # Append uploader specified testcase metadata value to end (for preference).
    uploader_value = testcase_metadata.get(key, '')
    uploader_value_list = utils.parse_delimited(
        uploader_value, delimiter=',', strip=True, remove_empty=True)
    for value in uploader_value_list:
      if value not in new_value_list:
        new_value_list.append(value)

    new_value = ','.join(new_value_list)
    if new_value == uploader_value:
      continue

    logs.log('Updating issue metadata for {} from {} to {}.'.format(
        key, uploader_value, new_value))
    testcase.set_metadata(key, new_value)


def setup_build(
    testcase: data_types.Testcase) -> Optional[uworker_io.UworkerOutput]:
  """Set up a custom or regular build based on revision. For regular builds,
  if a provided revision is not found, set up a build with the
  closest revision <= provided revision."""
  revision = testcase.crash_revision

  if revision and not build_manager.is_custom_binary():
    build_bucket_path = build_manager.get_primary_bucket_path()
    revision_list = build_manager.get_revisions_list(
        build_bucket_path, testcase=testcase)
    if not revision_list:
      data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                           'Failed to fetch revision list')
      return uworker_io.UworkerOutput(
          testcase=testcase,
          error=uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP)

    revision_index = revisions.find_min_revision_index(revision_list, revision)
    if revision_index is None:
      data_handler.update_testcase_comment(
          testcase, data_types.TaskState.ERROR,
          f'Build {testcase.job_type} r{revision} does not exist')
      return uworker_io.UworkerOutput(
          testcase=testcase,
          error=uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP)
    revision = revision_list[revision_index]

  build_manager.setup_build(revision)
  return None


def prepare_env_for_main(testcase_upload_metadata):
  """Prepares the environment for execute_task."""
  # Reset redzones.
  environment.reset_current_memory_tool_options(redzone_size=128)

  # Unset window location size and position properties so as to use default.
  environment.set_value('WINDOW_ARG', '')

  # Adjust the test timeout, if user has provided one.
  if testcase_upload_metadata.timeout:
    environment.set_value('TEST_TIMEOUT', testcase_upload_metadata.timeout)

  # Adjust the number of retries, if user has provided one.
  if testcase_upload_metadata.retries is not None:
    environment.set_value('CRASH_RETRIES', testcase_upload_metadata.retries)


def setup_testcase_and_build(
    testcase, testcase_upload_metadata, job_type, testcase_download_url
) -> (Optional[str], Optional[uworker_io.UworkerOutput]):
  """Sets up the |testcase| and builds. Returns the path to the testcase on
  success, None on error."""
  # Set up testcase and get absolute testcase path.
  _, testcase_file_path, error = setup.setup_testcase(
      testcase,
      job_type,
      testcase_download_url=testcase_download_url,
      metadata=testcase_upload_metadata)
  if error:
    return None, error

  # Set up build.
  error = setup_build(testcase)
  if error:
    return None, error

  # Check if we have an application path. If not, our build failed
  # to setup correctly.
  if not build_manager.check_app_path():
    # Let postprocess handle ANALYZE_BUILD_SETUP and restart tasks if needed.
    return None, uworker_io.UworkerOutput(
        testcase=testcase,
        testcase_upload_metadata=testcase_upload_metadata,
        error=uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP)

  update_testcase_after_build_setup(testcase)
  testcase.absolute_path = testcase_file_path
  return testcase_file_path, None


def update_testcase_after_build_setup(testcase):
  """Updates the testcase entity with values from global state that was set
  during build setup."""
  # NOTE: This must be done after setting up the build, which also sets
  # environment variables consumed by set_initial_testcase_metadata. See
  # https://crbug.com/1453576.
  # Set initial testcase metadata fields (e.g. build url, etc).
  data_handler.set_initial_testcase_metadata(testcase)

  # Update minimized arguments and use ones provided during user upload.
  if not testcase.minimized_arguments:
    minimized_arguments = environment.get_value('APP_ARGS') or ''
    additional_command_line_flags = testcase.get_metadata(
        'uploaded_additional_args')
    if additional_command_line_flags:
      minimized_arguments += ' %s' % additional_command_line_flags
    environment.set_value('APP_ARGS', minimized_arguments)
    testcase.minimized_arguments = minimized_arguments


def initialize_testcase_for_main(testcase, job_type):
  """Initializes a testcase for the crash testing phase."""
  # Update initial testcase information.
  testcase.job_type = job_type
  testcase.queue = tasks.default_queue()
  testcase.crash_state = ''
  testcase.put()


def save_minidump(testcase, state, application_command_line, gestures):
  """Saves a minidump when on Windows."""
  # Get crash info object with minidump info. Also, re-generate unsymbolized
  # stacktrace if needed.
  crash_info, _ = (
      crash_uploader.get_crash_info_and_stacktrace(
          application_command_line, state.crash_stacktrace, gestures))
  if crash_info:
    testcase.minidump_keys = crash_info.store_minidump()


def test_for_crash_with_retries(testcase, testcase_file_path, test_timeout):
  """Tests for a crash with retries. Tries with HTTP (with retries) if initial
  attempts fail. Returns the most recent crash result and the possibly updated
  HTTP flag."""
  # Get the crash output.
  http_flag = testcase.http_flag
  result = testcase_manager.test_for_crash_with_retries(
      testcase,
      testcase_file_path,
      test_timeout,
      http_flag=http_flag,
      compare_crash=False)

  # If we don't get a crash, try enabling http to see if we can get a crash.
  # Skip engine fuzzer jobs (e.g. libFuzzer, AFL) for which http testcase paths
  # are not applicable.
  if (not result.is_crash() and not http_flag and
      not environment.is_engine_fuzzer_job()):
    result_with_http = testcase_manager.test_for_crash_with_retries(
        testcase,
        testcase_file_path,
        test_timeout,
        http_flag=True,
        compare_crash=False)
    if result_with_http.is_crash():
      logs.log('Testcase needs http flag for crash.')
      http_flag = True
      result = result_with_http
    return result, http_flag

  return result, http_flag


def handle_noncrash(output):
  """Handles a non-crashing testcase. Either deletes the testcase or schedules
  another, final analysis."""
  # Could not reproduce the crash.
  log_message = (
      f'Testcase didn\'t crash in {output.test_timeout} seconds (with retries)')
  data_handler.update_testcase_comment(
      output.testcase, data_types.TaskState.FINISHED, log_message)

  # For an unreproducible testcase, retry once on another bot to confirm
  # our results and in case this bot is in a bad state which we didn't catch
  # through our usual means.
  if data_handler.is_first_retry_for_task(output.testcase):
    output.testcase.status = 'Unreproducible, retrying'
    output.testcase.put()

    tasks.add_task('analyze', output.uworker_input.testcase_id,
                   output.uworker_input.job_type)
    return

  data_handler.mark_invalid_uploaded_testcase(
      output.testcase, output.testcase_upload_metadata, 'Unreproducible')


def update_testcase_after_crash(testcase, state, job_type, http_flag):
  """Updates |testcase| based on |state|."""
  testcase.crash_type = state.crash_type
  testcase.crash_address = state.crash_address
  testcase.crash_state = state.crash_state
  testcase.http_flag = http_flag

  testcase.security_flag = crash_analyzer.is_security_issue(
      state.crash_stacktrace, state.crash_type, state.crash_address)
  # If it is, guess the severity.
  if testcase.security_flag:
    testcase.security_severity = severity_analyzer.get_security_severity(
        state.crash_type, state.crash_stacktrace, job_type,
        bool(testcase.gestures))


def utask_preprocess(testcase_id, job_type, uworker_env):
  """Runs preprocessing for analyze task."""

  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if not testcase:
    return None

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  testcase_upload_metadata = data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.testcase_id == int(testcase_id)).get()
  if not testcase_upload_metadata:
    logs.log_error(
        'Testcase %s has no associated upload metadata.' % testcase_id)
    testcase.key.delete()
    return None

  # Store the bot name and timestamp in upload metadata.
  testcase_upload_metadata.bot_name = environment.get_value('BOT_NAME')
  testcase_upload_metadata.timestamp = datetime.datetime.utcnow()
  testcase_upload_metadata.put()

  initialize_testcase_for_main(testcase, job_type)

  testcase_download_url = setup.get_signed_testcase_download_url(testcase)
  return uworker_io.UworkerInput(
      testcase_upload_metadata=testcase_upload_metadata,
      testcase=testcase,
      testcase_id=testcase_id,
      uworker_env=uworker_env,
      job_type=job_type,
      testcase_download_url=testcase_download_url)


def utask_main(uworker_input):
  """Executes the untrusted part of analyze_task."""
  prepare_env_for_main(uworker_input.testcase_upload_metadata)

  is_lsan_enabled = environment.get_value('LSAN')
  if is_lsan_enabled:
    # Creates empty local blacklist so all leaks will be visible to uploader.
    leak_blacklist.create_empty_local_blacklist()

  testcase_file_path, output = setup_testcase_and_build(
      uworker_input.testcase, uworker_input.testcase_upload_metadata,
      uworker_input.job_type, uworker_input.testcase_download_url)
  uworker_input.testcase.crash_revision = environment.get_value('APP_REVISION')

  if not testcase_file_path:
    return output

  # Initialize some variables.
  gestures = uworker_input.testcase.gestures
  test_timeout = environment.get_value('TEST_TIMEOUT')
  result, http_flag = test_for_crash_with_retries(
      uworker_input.testcase, testcase_file_path, test_timeout)

  # Set application command line with the correct http flag.
  application_command_line = (
      testcase_manager.get_command_line_for_application(
          testcase_file_path, needs_http=http_flag))

  # Get the crash data.
  crashed = result.is_crash()
  crash_time = result.get_crash_time()
  state = result.get_symbolized_data()

  save_minidump(uworker_input.testcase, state, application_command_line,
                gestures)
  unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)

  # In the general case, we will not attempt to symbolize if we do not detect
  # a crash. For user uploads, we should symbolize anyway to provide more
  # information about what might be happening.
  crash_stacktrace_output = utils.get_crash_stacktrace_output(
      application_command_line, state.crash_stacktrace,
      unsymbolized_crash_stacktrace)
  uworker_input.testcase.crash_stacktrace = data_handler.filter_stacktrace(
      crash_stacktrace_output)

  if not crashed:
    return uworker_io.UworkerOutput(
        testcase=uworker_input.testcase,
        testcase_upload_metadata=uworker_input.testcase_upload_metadata,
        error=uworker_msg_pb2.ErrorType.ANALYZE_NO_CRASH,
        test_timeout=test_timeout)
  # Update testcase crash parameters.
  update_testcase_after_crash(uworker_input.testcase, state,
                              uworker_input.job_type, http_flag)

  # See if we have to ignore this crash.
  if crash_analyzer.ignore_stacktrace(state.crash_stacktrace):
    # TODO(metzman): Handle this by closing the testcase on the trusted worker.
    # Also, deal with the other cases where we are updating testcase comment
    # in untrusted.
    data_handler.close_invalid_uploaded_testcase(
        uworker_input.testcase, uworker_input.testcase_upload_metadata,
        'Irrelevant')
    return uworker_io.UworkerOutput(
        testcase=uworker_input.testcase,
        testcase_upload_metadata=uworker_input.testcase_upload_metadata,
        error=uworker_msg_pb2.ErrorType.UNHANDLED)

  test_for_reproducibility(uworker_input.testcase, testcase_file_path, state,
                           test_timeout)
  return uworker_io.UworkerOutput(
      testcase=uworker_input.testcase,
      testcase_upload_metadata=uworker_input.testcase_upload_metadata,
      test_timeout=test_timeout,
      crash_time=crash_time)


def test_for_reproducibility(testcase, testcase_file_path, state, test_timeout):
  one_time_crasher_flag = not testcase_manager.test_for_reproducibility(
      testcase.fuzzer_name, testcase.actual_fuzzer_name(), testcase_file_path,
      state.crash_type, state.crash_state, testcase.security_flag, test_timeout,
      testcase.http_flag, testcase.gestures)
  testcase.one_time_crasher_flag = one_time_crasher_flag


def handle_build_setup_error(output):
  """Handles errors for scenarios where build setup fails."""
  data_handler.update_testcase_comment(
      output.testcase, data_types.TaskState.ERROR, 'Build setup failed')

  if data_handler.is_first_retry_for_task(output.testcase):
    task_name = environment.get_value('TASK_NAME')
    testcase_fail_wait = environment.get_value('FAIL_WAIT')
    tasks.add_task(
        task_name,
        output.uworker_input.testcase_id,
        output.uworker_input.job_type,
        wait_time=testcase_fail_wait)
    return
  data_handler.mark_invalid_uploaded_testcase(
      output.testcase, output.testcase_upload_metadata, 'Build setup failed')


HANDLED_ERRORS = [
    uworker_msg_pb2.ErrorType.ANALYZE_NO_CRASH,
    uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP,
    uworker_msg_pb2.ErrorType.TESTCASE_SETUP,
    uworker_msg_pb2.ErrorType.TESTCASE_SETUP_INVALID_FUZZER,
    uworker_msg_pb2.ErrorType.UNHANDLED
]


def utask_postprocess(output):
  """Trusted: Cleans up after a uworker execute_task, writing anything needed to
  the db."""
  if output.error is not None:
    uworker_handle_errors.handle(output, HANDLED_ERRORS)
    return
  testcase = output.testcase
  testcase_upload_metadata = output.testcase_upload_metadata

  log_message = (f'Testcase crashed in {output.test_timeout} seconds '
                 f'(r{testcase.crash_revision})')
  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED,
                                       log_message)

  # Check to see if this is a duplicate.
  data_handler.check_uploaded_testcase_duplicate(testcase,
                                                 testcase_upload_metadata)

  # Set testcase and metadata status if not set already.
  if testcase.status == 'Duplicate':
    # For testcase uploaded by bots (with quiet flag), don't create additional
    # tasks.
    if testcase_upload_metadata.quiet_flag:
      data_handler.close_invalid_uploaded_testcase(
          testcase, testcase_upload_metadata, 'Duplicate')
      return
  else:
    # New testcase.
    testcase.status = 'Processed'
    testcase_upload_metadata.status = 'Confirmed'

    # Reset the timestamp as well, to respect
    # data_types.MIN_ELAPSED_TIME_SINCE_REPORT. Otherwise it may get filed by
    # triage task prematurely without the grouper having a chance to run on this
    # testcase.
    testcase.timestamp = utils.utcnow()

    # Add new leaks to global blacklist to avoid detecting duplicates.
    # Only add if testcase has a direct leak crash and if it's reproducible.
    is_lsan_enabled = output.uworker_input.uworker_env.get('LSAN')
    if is_lsan_enabled:
      leak_blacklist.add_crash_to_global_blacklist_if_needed(testcase)

  # Update the testcase values.
  testcase.put()

  # Update the upload metadata.
  testcase_upload_metadata.security_flag = testcase.security_flag
  testcase_upload_metadata.put()

  _add_default_issue_metadata(testcase)

  # Create tasks to
  # 1. Minimize testcase (minimize).
  # 2. Find regression range (regression).
  # 3. Find testcase impact on production branches (impact).
  # 4. Check whether testcase is fixed (progression).
  # 5. Get second stacktrace from another job in case of
  #    one-time crashes (stack).
  task_creation.create_tasks(testcase)

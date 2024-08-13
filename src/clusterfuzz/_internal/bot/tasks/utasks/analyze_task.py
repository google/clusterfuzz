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
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis import severity_analyzer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import leak_blacklist
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment


def _add_default_issue_metadata(testcase, fuzz_target_metadata):
  """Adds the default issue metadata (e.g. components, labels) to testcase."""
  for key, default_value in fuzz_target_metadata.items():
    # Only string metadata are supported.
    if not isinstance(default_value, str):
      continue

    uploader_value = testcase.get_metadata(key, '')
    if not isinstance(uploader_value, str):
      continue

    # Add the default issue metadata first. This gives preference to uploader
    # specified issue metadata.
    new_value_list = utils.parse_delimited(
        default_value, delimiter=',', strip=True, remove_empty=True)

    # Append uploader specified testcase metadata value to end (for preference).
    uploader_value_list = utils.parse_delimited(
        uploader_value, delimiter=',', strip=True, remove_empty=True)
    for value in uploader_value_list:
      if value not in new_value_list:
        new_value_list.append(value)

    new_value = ','.join(new_value_list)
    if new_value == uploader_value:
      continue

    logs.info('Updating issue metadata for {} from {} to {}.'.format(
        key, uploader_value, new_value))
    testcase.set_metadata(key, new_value)


def handle_analyze_no_revisions_list_error(output):
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       'Failed to fetch revision list')
  handle_build_setup_error(output)


def setup_build(testcase: data_types.Testcase,
                bad_revisions) -> Optional[uworker_msg_pb2.Output]:  # pylint: disable=no-member
  """Set up a custom or regular build based on revision. For regular builds,
  if a provided revision is not found, set up a build with the
  closest revision <= provided revision."""
  revision = testcase.crash_revision

  if revision and not build_manager.is_custom_binary():
    build_bucket_path = build_manager.get_primary_bucket_path()
    revision_list = build_manager.get_revisions_list(
        build_bucket_path, bad_revisions, testcase=testcase)
    if not revision_list:
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.ErrorType.ANALYZE_NO_REVISIONS_LIST)  # pylint: disable=no-member

    revision_index = revisions.find_min_revision_index(revision_list, revision)
    if revision_index is None:
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.ErrorType.ANALYZE_NO_REVISION_INDEX)  # pylint: disable=no-member
    revision = revision_list[revision_index]

  build_manager.setup_build(revision)
  return None


def handle_analyze_no_revision_index(output):
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(
      testcase, data_types.TaskState.ERROR,
      f'Build {testcase.job_type} r{testcase.crash_revision} '
      'does not exist')
  handle_build_setup_error(output)


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
    testcase, job_type, setup_input,
    bad_revisions) -> (Optional[str], Optional[uworker_msg_pb2.Output]):  # pylint: disable=no-member
  """Sets up the |testcase| and builds. Returns the path to the testcase on
  success, None on error."""
  # Set up testcase and get absolute testcase path.
  _, testcase_file_path, error = setup.setup_testcase(testcase, job_type,
                                                      setup_input)
  if error:
    return None, error

  # Set up build.
  error = setup_build(testcase, bad_revisions)
  if error:
    return None, error

  # Check if we have an application path. If not, our build failed
  # to setup correctly.
  if not build_manager.check_app_path():
    # Let postprocess handle ANALYZE_BUILD_SETUP and restart tasks if needed.
    return None, uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP)

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


def test_for_crash_with_retries(fuzz_target, testcase, testcase_file_path,
                                test_timeout):
  """Tests for a crash with retries. Tries with HTTP (with retries) if initial
  attempts fail. Returns the most recent crash result and the possibly updated
  HTTP flag."""
  # Get the crash output.
  http_flag = testcase.http_flag
  result = testcase_manager.test_for_crash_with_retries(
      fuzz_target,
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
        fuzz_target,
        testcase,
        testcase_file_path,
        test_timeout,
        http_flag=True,
        compare_crash=False)
    if result_with_http.is_crash():
      logs.info('Testcase needs http flag for crash.')
      http_flag = True
      result = result_with_http
    return result, http_flag

  return result, http_flag


def is_first_analyze_attempt(testcase):
  return data_handler.is_first_attempt_for_task('analyze', testcase)


def handle_noncrash(output):
  """Handles a non-crashing testcase. Either deletes the testcase or schedules
  another, final analysis."""
  # Could not reproduce the crash.
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  log_message = (
      f'Testcase didn\'t crash in {output.test_timeout} seconds (with retries)')
  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED,
                                       log_message)

  # For an unreproducible testcase, retry once on another bot to confirm
  # our results and in case this bot is in a bad state which we didn't catch
  # through our usual means.
  if is_first_analyze_attempt(testcase):
    testcase.status = 'Unreproducible, retrying'
    testcase.put()

    tasks.add_task('analyze', output.uworker_input.testcase_id,
                   output.uworker_input.job_type)
    return
  testcase_upload_metadata = query_testcase_upload_metadata(
      output.uworker_input.testcase_id)
  data_handler.mark_invalid_uploaded_testcase(
      testcase, testcase_upload_metadata, 'Unreproducible')


def update_testcase_after_crash(testcase, state, job_type, http_flag,
                                analyze_task_output):
  """Updates |testcase| based on |state|."""
  testcase.crash_type = state.crash_type
  testcase.crash_address = state.crash_address
  testcase.crash_state = state.crash_state
  testcase.http_flag = http_flag

  testcase.security_flag = crash_analyzer.is_security_issue(
      state.crash_stacktrace, state.crash_type, state.crash_address)

  # These are passed back to postprocess to update the testcase.
  analyze_task_output.crash_info_set = True
  analyze_task_output.http_flag = http_flag
  analyze_task_output.crash_type = state.crash_type
  analyze_task_output.crash_address = state.crash_address
  analyze_task_output.crash_state = state.crash_state
  analyze_task_output.security_flag = testcase.security_flag

  # If it is, guess the severity.
  if testcase.security_flag:
    testcase.security_severity = severity_analyzer.get_security_severity(
        state.crash_type, state.crash_stacktrace, job_type,
        bool(testcase.gestures))
    if testcase.security_severity is not None:
      analyze_task_output.security_severity = testcase.security_severity


def utask_preprocess(testcase_id, job_type, uworker_env):
  """Runs preprocessing for analyze task."""
  # Get the testcase from the database and mark it as started.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  testcase_upload_metadata = query_testcase_upload_metadata(testcase_id)
  if not testcase_upload_metadata:
    logs.error('Testcase %s has no associated upload metadata.' % testcase_id)
    testcase.key.delete()
    return None

  # Store the bot name and timestamp in upload metadata.
  testcase_upload_metadata.bot_name = environment.get_value('BOT_NAME')
  testcase_upload_metadata.timestamp = datetime.datetime.utcnow()
  testcase_upload_metadata.put()

  initialize_testcase_for_main(testcase, job_type)

  setup_input = setup.preprocess_setup_testcase(testcase, uworker_env)
  analyze_task_input = get_analyze_task_input()
  uworker_input = uworker_msg_pb2.Input(  # pylint: disable=no-member
      testcase_upload_metadata=uworker_io.entity_to_protobuf(
          testcase_upload_metadata),
      testcase=uworker_io.entity_to_protobuf(testcase),
      testcase_id=testcase_id,
      uworker_env=uworker_env,
      setup_input=setup_input,
      job_type=job_type,
      analyze_task_input=analyze_task_input,
  )
  testcase_manager.preprocess_testcase_manager(testcase, uworker_input)
  return uworker_input


def get_analyze_task_input():
  return uworker_msg_pb2.AnalyzeTaskInput(  # pylint: disable=no-member
      bad_revisions=build_manager.get_job_bad_revisions())


def _build_task_output(
    testcase: data_types.Testcase) -> uworker_msg_pb2.AnalyzeTaskOutput:  # pylint: disable=no-member
  """Copies the testcase updated fields to analyze_task_output to be updated in
  postprocess."""
  analyze_task_output = uworker_msg_pb2.AnalyzeTaskOutput()  # pylint: disable=no-member
  analyze_task_output.crash_revision = int(testcase.crash_revision)
  analyze_task_output.absolute_path = testcase.absolute_path
  analyze_task_output.minimized_arguments = testcase.minimized_arguments
  if testcase.get_metadata('build_key'):
    analyze_task_output.build_key = testcase.get_metadata('build_key')
  if testcase.get_metadata('build_url'):
    analyze_task_output.build_url = testcase.get_metadata('build_url')
  if testcase.get_metadata('gn_args'):
    analyze_task_output.gn_args = testcase.get_metadata('gn_args')
  if testcase.platform:
    analyze_task_output.platform = testcase.platform
  if testcase.platform_id:
    analyze_task_output.platform_id = testcase.platform_id
  return analyze_task_output


def utask_main(uworker_input):
  """Executes the untrusted part of analyze_task."""
  testcase_upload_metadata = uworker_io.entity_from_protobuf(
      uworker_input.testcase_upload_metadata, data_types.TestcaseUploadMetadata)
  testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                             data_types.Testcase)
  uworker_io.check_handling_testcase_safe(testcase)
  prepare_env_for_main(testcase_upload_metadata)

  is_lsan_enabled = environment.get_value('LSAN')
  if is_lsan_enabled:
    # Creates empty local blacklist so all leaks will be visible to uploader.
    leak_blacklist.create_empty_local_blacklist()

  testcase_file_path, output = setup_testcase_and_build(
      testcase, uworker_input.job_type, uworker_input.setup_input,
      uworker_input.analyze_task_input.bad_revisions)
  testcase.crash_revision = environment.get_value('APP_REVISION')

  if not testcase_file_path:
    return output

  analyze_task_output = _build_task_output(testcase)

  # Initialize some variables.
  test_timeout = environment.get_value('TEST_TIMEOUT')
  fuzz_target = testcase_manager.get_fuzz_target_from_input(uworker_input)
  result, http_flag = test_for_crash_with_retries(
      fuzz_target, testcase, testcase_file_path, test_timeout)

  # Set application command line with the correct http flag.
  application_command_line = (
      testcase_manager.get_command_line_for_application(
          testcase_file_path, needs_http=http_flag))

  # Get the crash data.
  crashed = result.is_crash()
  crash_time = result.get_crash_time()
  state = result.get_symbolized_data()

  unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)

  # In the general case, we will not attempt to symbolize if we do not detect
  # a crash. For user uploads, we should symbolize anyway to provide more
  # information about what might be happening.
  crash_stacktrace_output = utils.get_crash_stacktrace_output(
      application_command_line, state.crash_stacktrace,
      unsymbolized_crash_stacktrace)
  testcase.crash_stacktrace = data_handler.filter_stacktrace(
      crash_stacktrace_output)

  analyze_task_output.crash_stacktrace = testcase.crash_stacktrace

  if not crashed:
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        analyze_task_output=analyze_task_output,
        error_type=uworker_msg_pb2.ErrorType.ANALYZE_NO_CRASH,  # pylint: disable=no-member
        test_timeout=test_timeout)
  # Update testcase crash parameters.
  update_testcase_after_crash(testcase, state, uworker_input.job_type,
                              http_flag, analyze_task_output)

  # See if we have to ignore this crash.
  if crash_analyzer.ignore_stacktrace(state.crash_stacktrace):
    # TODO(metzman): Handle this by closing the testcase on the trusted worker.
    # Also, deal with the other cases where we are updating testcase comment
    # in untrusted.
    data_handler.close_invalid_uploaded_testcase(
        testcase, testcase_upload_metadata, 'Irrelevant')
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        analyze_task_output=analyze_task_output,
        error_type=uworker_msg_pb2.ErrorType.UNHANDLED)  # pylint: disable=no-member

  test_for_reproducibility(fuzz_target, testcase, testcase_file_path, state,
                           test_timeout)
  analyze_task_output.one_time_crasher_flag = testcase.one_time_crasher_flag

  fuzz_target_metadata = engine_common.get_fuzz_target_issue_metadata(
      fuzz_target)

  return uworker_msg_pb2.Output(  # pylint: disable=no-member
      analyze_task_output=analyze_task_output,
      test_timeout=test_timeout,
      crash_time=crash_time,
      issue_metadata=fuzz_target_metadata)


def test_for_reproducibility(fuzz_target, testcase, testcase_file_path, state,
                             test_timeout):
  one_time_crasher_flag = not testcase_manager.test_for_reproducibility(
      fuzz_target, testcase_file_path, state.crash_type, state.crash_state,
      testcase.security_flag, test_timeout, testcase.http_flag,
      testcase.gestures)
  testcase.one_time_crasher_flag = one_time_crasher_flag


def handle_build_setup_error(output):
  """Handles errors for scenarios where build setup fails."""
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       'Build setup failed')

  if is_first_analyze_attempt(testcase):
    task_name = 'analyze'
    testcase_fail_wait = environment.get_value('FAIL_WAIT')
    tasks.add_task(
        task_name,
        output.uworker_input.testcase_id,
        output.uworker_input.job_type,
        wait_time=testcase_fail_wait)
    return
  testcase_upload_metadata = query_testcase_upload_metadata(
      output.uworker_input.testcase_id)
  data_handler.mark_invalid_uploaded_testcase(
      testcase, testcase_upload_metadata, 'Build setup failed')


_ERROR_HANDLER = uworker_handle_errors.CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP:  # pylint: disable=no-member
        handle_build_setup_error,
    uworker_msg_pb2.ErrorType.ANALYZE_NO_CRASH:  # pylint: disable=no-member
        handle_noncrash,
    uworker_msg_pb2.ErrorType.ANALYZE_NO_REVISION_INDEX:  # pylint: disable=no-member
        handle_analyze_no_revision_index,
    uworker_msg_pb2.ErrorType.ANALYZE_NO_REVISIONS_LIST:  # pylint: disable=no-member
        handle_analyze_no_revisions_list_error,
}).compose_with(
    setup.ERROR_HANDLER,
    uworker_handle_errors.UNHANDLED_ERROR_HANDLER,
)


def _update_testcase(output):
  """Updates the testcase using the info passed from utask_main."""
  if not output.HasField('analyze_task_output'):
    return

  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  analyze_task_output = output.analyze_task_output
  testcase.crash_revision = analyze_task_output.crash_revision

  testcase.absolute_path = analyze_task_output.absolute_path
  testcase.minimized_arguments = analyze_task_output.minimized_arguments
  testcase.crash_stacktrace = analyze_task_output.crash_stacktrace

  if analyze_task_output.crash_info_set:
    testcase.http_flag = analyze_task_output.http_flag
    testcase.crash_type = analyze_task_output.crash_type
    testcase.crash_address = analyze_task_output.crash_address
    testcase.crash_state = analyze_task_output.crash_state
    testcase.security_flag = analyze_task_output.security_flag
    if testcase.security_flag:
      if analyze_task_output.HasField('security_severity'):
        testcase.security_severity = analyze_task_output.security_severity
      else:
        testcase.security_severity = None

  testcase.one_time_crasher_flag = analyze_task_output.one_time_crasher_flag

  # For the following fields, we are assuming an empty string/ None is invalid.
  if analyze_task_output.build_key:
    testcase.set_metadata(
        'build_key', analyze_task_output.build_key, update_testcase=False)
  if analyze_task_output.build_url:
    testcase.set_metadata(
        'build_url', analyze_task_output.build_url, update_testcase=False)
  if analyze_task_output.gn_args:
    testcase.set_metadata(
        'gn_args', analyze_task_output.gn_args, update_testcase=False)
  if analyze_task_output.platform:
    testcase.platform = analyze_task_output.platform
  if analyze_task_output.platform_id:
    testcase.platform_id = analyze_task_output.platform_id

  testcase.put()


def utask_postprocess(output):
  """Trusted: Cleans up after a uworker execute_task, writing anything needed to
  the db."""
  _update_testcase(output)
  if output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
    _ERROR_HANDLER.handle(output)
    return
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  testcase_upload_metadata = query_testcase_upload_metadata(
      output.uworker_input.testcase_id)

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

  _add_default_issue_metadata(testcase, output.issue_metadata)
  logs.info('Creating post-analyze tasks.')

  # Create tasks to
  # 1. Minimize testcase (minimize).
  # 2. Find regression range (regression).
  # 3. Find testcase impact on production branches (impact).
  # 4. Check whether testcase is fixed (progression).
  # 5. Get second stacktrace from another job in case of
  #    one-time crashes (stack).
  task_creation.create_tasks(testcase)


def query_testcase_upload_metadata(
    testcase_id: str) -> Optional[data_types.TestcaseUploadMetadata]:
  return data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.testcase_id == int(testcase_id)).get()

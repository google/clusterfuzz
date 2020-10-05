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
import six

from base import errors
from base import tasks
from base import utils
from bot import testcase_manager
from bot.fuzzers import engine_common
from bot.tasks import setup
from bot.tasks import task_creation
from build_management import build_manager
from build_management import revisions
from chrome import crash_uploader
from crash_analysis import crash_analyzer
from crash_analysis import severity_analyzer
from datastore import data_handler
from datastore import data_types
from fuzzing import leak_blacklist
from metrics import logs
from system import environment


def _add_default_issue_metadata(testcase):
  """Adds the default issue metadata (e.g. components, labels) to testcase."""
  default_metadata = engine_common.get_all_issue_metadata_for_testcase(testcase)
  if not default_metadata:
    return

  testcase_metadata = testcase.get_metadata()
  for key, default_value in six.iteritems(default_metadata):
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


def close_invalid_testcase_and_update_status(testcase, metadata, status):
  """Closes an invalid testcase and updates metadata."""
  testcase.status = status
  testcase.open = False
  testcase.minimized_keys = 'NA'
  testcase.regression = 'NA'
  testcase.set_impacts_as_na()
  testcase.fixed = 'NA'
  testcase.triaged = True
  testcase.put()

  metadata.status = status
  metadata.put()


def setup_build(testcase):
  """Set up a custom or regular build based on revision. For regular builds,
  if a provided revision is not found, set up a build with the
  closest revision <= provided revision."""
  revision = testcase.crash_revision

  if revision and not build_manager.is_custom_binary():
    build_bucket_path = build_manager.get_primary_bucket_path()
    revision_list = build_manager.get_revisions_list(
        build_bucket_path, testcase=testcase)
    if not revision_list:
      logs.log_error('Failed to fetch revision list.')
      return

    revision_index = revisions.find_min_revision_index(revision_list, revision)
    if revision_index is None:
      raise errors.BuildNotFoundError(revision, testcase.job_type)
    revision = revision_list[revision_index]

  build_manager.setup_build(revision)


def execute_task(testcase_id, job_type):
  """Run analyze task."""
  # Reset redzones.
  environment.reset_current_memory_tool_options(redzone_size=128)

  # Unset window location size and position properties so as to use default.
  environment.set_value('WINDOW_ARG', '')

  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if not testcase:
    return

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  metadata = data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.testcase_id == int(testcase_id)).get()
  if not metadata:
    logs.log_error(
        'Testcase %s has no associated upload metadata.' % testcase_id)
    testcase.key.delete()
    return

  is_lsan_enabled = environment.get_value('LSAN')
  if is_lsan_enabled:
    # Creates empty local blacklist so all leaks will be visible to uploader.
    leak_blacklist.create_empty_local_blacklist()

  # Store the bot name and timestamp in upload metadata.
  bot_name = environment.get_value('BOT_NAME')
  metadata.bot_name = bot_name
  metadata.timestamp = datetime.datetime.utcnow()
  metadata.put()

  # Adjust the test timeout, if user has provided one.
  if metadata.timeout:
    environment.set_value('TEST_TIMEOUT', metadata.timeout)

  # Adjust the number of retries, if user has provided one.
  if metadata.retries is not None:
    environment.set_value('CRASH_RETRIES', metadata.retries)

  # Set up testcase and get absolute testcase path.
  file_list, _, testcase_file_path = setup.setup_testcase(testcase, job_type)
  if not file_list:
    return

  # Set up build.
  setup_build(testcase)

  # Check if we have an application path. If not, our build failed
  # to setup correctly.
  if not build_manager.check_app_path():
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Build setup failed')

    if data_handler.is_first_retry_for_task(testcase):
      build_fail_wait = environment.get_value('FAIL_WAIT')
      tasks.add_task(
          'analyze', testcase_id, job_type, wait_time=build_fail_wait)
    else:
      close_invalid_testcase_and_update_status(testcase, metadata,
                                               'Build setup failed')
    return

  # Update initial testcase information.
  testcase.absolute_path = testcase_file_path
  testcase.job_type = job_type
  testcase.binary_flag = utils.is_binary_file(testcase_file_path)
  testcase.queue = tasks.default_queue()
  testcase.crash_state = ''

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

  # Update other fields not set at upload time.
  testcase.crash_revision = environment.get_value('APP_REVISION')
  data_handler.set_initial_testcase_metadata(testcase)
  testcase.put()

  # Initialize some variables.
  gestures = testcase.gestures
  http_flag = testcase.http_flag
  test_timeout = environment.get_value('TEST_TIMEOUT')

  # Get the crash output.
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

  # Refresh our object.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if not testcase:
    return

  # Set application command line with the correct http flag.
  application_command_line = (
      testcase_manager.get_command_line_for_application(
          testcase_file_path, needs_http=http_flag))

  # Get the crash data.
  crashed = result.is_crash()
  crash_time = result.get_crash_time()
  state = result.get_symbolized_data()
  unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)

  # Get crash info object with minidump info. Also, re-generate unsymbolized
  # stacktrace if needed.
  crash_info, _ = (
      crash_uploader.get_crash_info_and_stacktrace(
          application_command_line, state.crash_stacktrace, gestures))
  if crash_info:
    testcase.minidump_keys = crash_info.store_minidump()

  if not crashed:
    # Could not reproduce the crash.
    log_message = (
        'Testcase didn\'t crash in %d seconds (with retries)' % test_timeout)
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.FINISHED, log_message)

    # In the general case, we will not attempt to symbolize if we do not detect
    # a crash. For user uploads, we should symbolize anyway to provide more
    # information about what might be happening.
    crash_stacktrace_output = utils.get_crash_stacktrace_output(
        application_command_line, state.crash_stacktrace,
        unsymbolized_crash_stacktrace)
    testcase.crash_stacktrace = data_handler.filter_stacktrace(
        crash_stacktrace_output)

    # For an unreproducible testcase, retry once on another bot to confirm
    # our results and in case this bot is in a bad state which we didn't catch
    # through our usual means.
    if data_handler.is_first_retry_for_task(testcase):
      testcase.status = 'Unreproducible, retrying'
      testcase.put()

      tasks.add_task('analyze', testcase_id, job_type)
      return

    close_invalid_testcase_and_update_status(testcase, metadata,
                                             'Unreproducible')

    # A non-reproducing testcase might still impact production branches.
    # Add the impact task to get that information.
    task_creation.create_impact_task_if_needed(testcase)
    return

  # Update testcase crash parameters.
  testcase.http_flag = http_flag
  testcase.crash_type = state.crash_type
  testcase.crash_address = state.crash_address
  testcase.crash_state = state.crash_state
  crash_stacktrace_output = utils.get_crash_stacktrace_output(
      application_command_line, state.crash_stacktrace,
      unsymbolized_crash_stacktrace)
  testcase.crash_stacktrace = data_handler.filter_stacktrace(
      crash_stacktrace_output)

  # Try to guess if the bug is security or not.
  security_flag = crash_analyzer.is_security_issue(
      state.crash_stacktrace, state.crash_type, state.crash_address)
  testcase.security_flag = security_flag

  # If it is, guess the severity.
  if security_flag:
    testcase.security_severity = severity_analyzer.get_security_severity(
        state.crash_type, state.crash_stacktrace, job_type, bool(gestures))

  log_message = ('Testcase crashed in %d seconds (r%d)' %
                 (crash_time, testcase.crash_revision))
  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED,
                                       log_message)

  # See if we have to ignore this crash.
  if crash_analyzer.ignore_stacktrace(state.crash_stacktrace):
    close_invalid_testcase_and_update_status(testcase, metadata, 'Irrelavant')
    return

  # Test for reproducibility.
  one_time_crasher_flag = not testcase_manager.test_for_reproducibility(
      testcase.fuzzer_name, testcase.actual_fuzzer_name(), testcase_file_path,
      state.crash_state, security_flag, test_timeout, http_flag, gestures)
  testcase.one_time_crasher_flag = one_time_crasher_flag

  # Check to see if this is a duplicate.
  project_name = data_handler.get_project_name(job_type)
  existing_testcase = data_handler.find_testcase(
      project_name, state.crash_type, state.crash_state, security_flag)
  if existing_testcase:
    # If the existing test case is unreproducible and we are, replace the
    # existing test case with this one.
    if existing_testcase.one_time_crasher_flag and not one_time_crasher_flag:
      duplicate_testcase = existing_testcase
      original_testcase = testcase
    else:
      duplicate_testcase = testcase
      original_testcase = existing_testcase
      metadata.status = 'Duplicate'
      metadata.duplicate_of = existing_testcase.key.id()

    duplicate_testcase.status = 'Duplicate'
    duplicate_testcase.duplicate_of = original_testcase.key.id()
    duplicate_testcase.put()

  # Set testcase and metadata status if not set already.
  if testcase.status == 'Duplicate':
    # For testcase uploaded by bots (with quiet flag), don't create additional
    # tasks.
    if metadata.quiet_flag:
      close_invalid_testcase_and_update_status(testcase, metadata, 'Duplicate')
      return
  else:
    # New testcase.
    testcase.status = 'Processed'
    metadata.status = 'Confirmed'

    # Add new leaks to global blacklist to avoid detecting duplicates.
    # Only add if testcase has a direct leak crash and if it's reproducible.
    if is_lsan_enabled:
      leak_blacklist.add_crash_to_global_blacklist_if_needed(testcase)

  # Update the testcase values.
  testcase.put()

  # Update the upload metadata.
  metadata.security_flag = security_flag
  metadata.put()

  _add_default_issue_metadata(testcase)

  # Create tasks to
  # 1. Minimize testcase (minimize).
  # 2. Find regression range (regression).
  # 3. Find testcase impact on production branches (impact).
  # 4. Check whether testcase is fixed (progression).
  # 5. Get second stacktrace from another job in case of
  #    one-time crashers (stack).
  task_creation.create_tasks(testcase)

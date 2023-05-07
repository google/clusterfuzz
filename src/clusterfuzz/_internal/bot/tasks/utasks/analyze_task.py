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
import enum

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
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
from clusterfuzz._internal.system import environment


def _add_default_issue_metadata(testcase):
  """Adds the default issue metadata (e.g. components, labels) to testcase."""
  default_metadata = engine_common.get_all_issue_metadata_for_testcase(testcase)
  if not default_metadata:
    return

  testcase_metadata = testcase.get_metadata()
  for key, default_value in default_metadata.items():
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


def test_for_crash_with_retries(testcase, testcase_file_path, test_timeout):
  # Get the crash output.
  result = testcase_manager.test_for_crash_with_retries(
      testcase,
      testcase_file_path,
      test_timeout,
      http_flag=testcase.http_flag,
      compare_crash=False)

  # If we don't get a crash, try enabling http to see if we can get a crash.
  # Skip engine fuzzer jobs (e.g. libFuzzer, AFL) for which http testcase paths
  # are not applicable.
  if (not result.is_crash() and not testcase.http_flag and
      not environment.is_engine_fuzzer_job()):
    result_with_http = testcase_manager.test_for_crash_with_retries(
        testcase,
        testcase_file_path,
        test_timeout,
        http_flag=True,
        compare_crash=False)
    if result_with_http.is_crash():
      logs.log('Testcase needs http flag for crash.')
      testcase.http_flag = True
      result = result_with_http
  return result


def prepare_env_for_main(metadata):
  environment.reset_current_memory_tool_options(redzone_size=128)

  # Unset window location size and position properties so as to use default.
  environment.set_value('WINDOW_ARG', '')

  # Adjust the test timeout, if user has provided one.
  if metadata.timeout:
    environment.set_value('TEST_TIMEOUT', metadata.timeout)

  # Adjust the number of retries, if user has provided one.
  if metadata.retries is not None:
    environment.set_value('CRASH_RETRIES', metadata.retries)


def setup_testcase_and_build(testcase, metadata, job_type,
                             testcase_download_url):
  # Set up testcase and get absolute testcase path.
  file_list, _, testcase_file_path = setup.setup_testcase(
      testcase, job_type, testcase_download_url=testcase_download_url)
  if not file_list:
    return False, AnalyzeUworkerOutput(
        testcase=testcase, metadata=metadata, error=Error.BUILD_SETUP)

  # Set up build.
  setup_build(testcase)

  # Check if we have an application path. If not, our build failed
  # to setup correctly.
  if not build_manager.check_app_path():
    return False, AnalyzeUworkerOutput(
        testcase=testcase, metadata=metadata, error=Error.BUILD_SETUP)
  return True, None


def initialize_testcase_for_main(testcase, file_path, job_type):
  # Update initial testcase information.
  testcase.absolute_path = testcase_file_path
  testcase.job_type = job_type
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


def save_minidump(testcase, application_command_line, state):
  # Get crash info object with minidump info. Also, re-generate unsymbolized
  # stacktrace if needed.
  crash_info, _ = (
      crash_uploader.get_crash_info_and_stacktrace(
          application_command_line, state.crash_stacktrace, testcase.gestures))
  if crash_info:
    testcase.minidump_keys = crash_info.store_minidump()


def get_application_command_line(testcase):
  return testcase_manager.get_command_line_for_application(
      testcase.absolute_path, needs_http=testcase.http_flag)


def update_testcase(testcase, state, crash_stacktrace, job_type):

  testcase.crash_type = state.crash_type
  testcase.crash_address = state.crash_address
  testcase.crash_state = state.crash_state

  testcase.security_flag = crash_analyzer.is_security_issue(
      state.crash_stacktrace, state.crash_type, state.crash_address)
  # If it is, guess the severity.
  if testcase.security_flag:
    testcase.security_severity = severity_analyzer.get_security_severity(
        state.crash_type, state.crash_stacktrace, job_type,
        bool(testcase.gestures))


# !!! Testcase download URL.
def utask_main(testcase, testcase_download_url, job_type, metadata):
  """Executes the untrusted part of analyze_task."""
  prepare_env_for_main(metadata)

  is_lsan_enabled = environment.get_value('LSAN')
  if is_lsan_enabled:
    # Creates empty local blacklist so all leaks will be visible to uploader.
    leak_blacklist.create_empty_local_blacklist()

  setup_success, output = setup_testcase_and_build(testcase, metadata, job_type,
                                                   testcase_download_url)
  if not setup_success:
    return output

  initialize_testcase_for_main(testcase, file_path, job_type)

  # Initialize some variables.
  test_timeout = environment.get_value('TEST_TIMEOUT')

  result = test_for_crash_with_retries(testcase, testcase_file_path,
                                       test_timeout)

  # Set application command line with the correct http flag.
  application_command_line = get_application_command_line(testcase)

  # Get the crash data.
  crashed = result.is_crash()
  state = result.get_symbolized_data()
  unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
  save_minidump(testcase, application_command_line, state)

  crash_stacktrace_output = utils.get_crash_stacktrace_output(
      application_command_line, state.crash_stacktrace,
      unsymbolized_crash_stacktrace)
  testcase.crash_stacktrace = data_handler.filter_stacktrace(
      crash_stacktrace_output)

  if not crashed:
    pass
  # Update testcase crash parameters.
  update_testcase(testcase, state, crash_stacktrace, job_type)
  test_for_reproducibility(testcase, test_timeout)
  return AnalyzeUworkerOutput(
      testcase=testcase,
      crash_stacktrace=crash_stacktrace,
      crashed=crashed,
      crash_time=crash_time)


def test_for_reproducibility(testcase, test_timeout):
  reproduces = testcase_manager.test_for_reproducibility(
      testcase.fuzzer_name, testcase.actual_fuzzer_name(), testcase_file_path,
      state.crash_type, state.crash_state, testcase.security_flag, test_timeout,
      testcase.http_flag, testcase.gestures)
  testcase.one_time_crasher_flag = reproduces


class AnalyzeUworkerOutput(uworker_io.UworkerOutput):

  def __init__(self,
               testcase,
               error=None,
               crash_stacktrace=None,
               crashed=False,
               crash_time=None):
    super().__init__(testcase, error)
    self.crash_stacktrace = crash_stacktrace
    self.crashed = crash_stacktrace
    self.crash_time = crash_time


class Error(enum.Enum):
  BUILD_SETUP = 1


def utask_preprocess(testcase_id, job_type, uworker_env):
  """Run analyze task."""
  # Reset redzones.
  # Locate the testcase associated with the id.
  del job_type
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if not testcase:
    return None

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  metadata = data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.testcase_id == int(testcase_id)).get()
  if not metadata:
    logs.log_error(
        'Testcase %s has no associated upload metadata.' % testcase_id)
    testcase.key.delete()
    return

  # Store the bot name and timestamp in upload metadata.
  bot_name = environment.get_value('BOT_NAME')
  metadata.bot_name = bot_name
  metadata.timestamp = datetime.datetime.utcnow()
  metadata.put()

  # Adjust the test timeout, if user has provided one.
  if metadata.timeout:
    environment.set_value('TEST_TIMEOUT', metadata.timeout)
    untrusted_env['TEST_TIMEOUT'] = metadata.timeout

  # Adjust the number of retries, if user has provided one.
  if metadata.retries is not None:
    environment.set_value('CRASH_RETRIES', metadata.retries)
    untrusted_env['CRASH_RETRIES'] = metadata.retries

  testcase_download_url = setup.get_testcase_download_url(testcase)
  return {
      'metadata': metadata,
      'testcase': testcase,
      'uworker_env': uworker_env,
      'testcase_download_url': testcase_download_url
  }


def utask_handle_errors(testcase, metadata, error):
  if error == Error.BUILD_SETUP:
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         'Build setup failed')

    if data_handler.is_first_retry_for_task(testcase):
      build_fail_wait = environment.get_value('FAIL_WAIT')
      tasks.add_task(
          'analyze', testcase_id, job_type, wait_time=build_fail_wait)
    else:
      data_handler.close_invalid_uploaded_testcase(testcase, metadata,
                                                   'Build setup failed')

  if error == Error.NO_CRASH:
    # !!!
    pass


def utask_postprocess(crashed, crash_stacktrace, crash_time, testcase, error,
                      metadata):
  """Trusted: Clean up after a uworker execute_task, write anything needed to
  the db."""
  if error:
    utask_handle_errors(testcase, metadata, error)

  # # !!! Check for bad build.
  # data_handler.close_invalid_uploaded_testcase(testcase, metadata,
  #                                              'Build setup failed')
  if not crashed:
    # Could not reproduce the crash.
    log_message = (
        'Testcase didn\'t crash in %d seconds (with retries)' % test_timeout)
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.FINISHED, log_message)

    # For an unreproducible testcase, retry once on another bot to confirm
    # our results and in case this bot is in a bad state which we didn't catch
    # through our usual means.
    if data_handler.is_first_retry_for_task(testcase):
      testcase.status = 'Unreproducible, retrying'
      testcase.put()

      tasks.add_task('analyze', testcase.id, job_type)
      return
      # data_handler.close_invalid_uploaded_testcase(testcase, metadata,
      #                                              'Unreproducible')

      # A non-reproducing testcase might still impact production branches.
      # Add the impact task to get that information.
      task_creation.create_impact_task_if_needed(testcase)
      return

  log_message = ('Testcase crashed in %d seconds (r%d)' %
                 (crash_time, testcase.crash_revision))
  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED,
                                       log_message)

  # See if we have to ignore this crash.
  if crash_analyzer.ignore_stacktrace(crash_stacktrace):
    # data_handler.close_invalid_uploaded_testcase(testcase, metadata,
    #                                              'Irrelavant')
    return

  # Check to see if this is a duplicate.
  # data_handler.check_uploaded_testcase_duplicate(testcase, metadata)

  # Set testcase and metadata status if not set already.
  if testcase.status == 'Duplicate':
    # For testcase uploaded by bots (with quiet flag), don't create additional
    # tasks.
    # if metadata.quiet_flag:
    #   data_handler.close_invalid_uploaded_testcase(testcase, metadata,
    #                                                'Duplicate')
    return
  else:
    # New testcase.
    testcase.status = 'Processed'
    # metadata.status = 'Confirmed'

    # Reset the timestamp as well, to respect
    # data_types.MIN_ELAPSED_TIME_SINCE_REPORT. Otherwise it may get filed by
    # triage task prematurely without the grouper having a chance to run on this
    # testcase.
    testcase.timestamp = utils.utcnow()

    # Add new leaks to global blacklist to avoid detecting duplicates.
    # Only add if testcase has a direct leak crash and if it's reproducible.
    is_lsan_enabled = environment.get_value('LSAN')
    if is_lsan_enabled:
      leak_blacklist.add_crash_to_global_blacklist_if_needed(testcase)

  # Update the testcase values.
  testcase.put()

  # !!! Ignore metadata for now.
  # # Update the upload metadata.
  # metadata.security_flag = security_flag
  # metadata.put()
  # _add_default_issue_metadata(testcase)

  # Create tasks to
  # 1. Minimize testcase (minimize).
  # 2. Find regression range (regression).
  # 3. Find testcase impact on production branches (impact).
  # 4. Check whether testcase is fixed (progression).
  # 5. Get second stacktrace from another job in case of
  #    one-time crashes (stack).
  task_creation.create_tasks(testcase)

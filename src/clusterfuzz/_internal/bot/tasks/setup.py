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
"""Common helper functions for setup at the start of tasks."""

import datetime
import os
import shlex
import time
from typing import Optional
import zipfile

from clusterfuzz._internal.base import dates
from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import task_utils
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks.utasks import uworker_handle_errors
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.fuzzing import leak_blacklist
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import fuzzer_logs
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

_BOT_DIR = 'bot'
_DATA_BUNDLE_CACHE_COUNT = 10
_DATA_BUNDLE_SYNC_INTERVAL_IN_SECONDS = 6 * 60 * 60
_SYNC_FILENAME = '.sync'
_TESTCASE_ARCHIVE_EXTENSION = '.zip'


def _set_timeout_value_from_user_upload(testcase_id, uworker_env):
  """Get the timeout associated with this testcase."""
  metadata = data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.testcase_id == int(testcase_id)).get()
  if metadata and metadata.timeout:
    uworker_env['TEST_TIMEOUT'] = str(metadata.timeout)


def _copy_testcase_to_device_and_setup_environment(testcase,
                                                   testcase_file_path):
  """Android specific setup steps for testcase."""
  # Copy test(s) to device.
  android.device.push_testcases_to_device()

  # The following steps need privileged job access.
  job_type_has_privileged_access = environment.get_value('PRIVILEGED_ACCESS')
  if not job_type_has_privileged_access:
    return

  # Install testcase if it is an app.
  package_name = android.app.get_package_name(testcase_file_path)
  if package_name:
    # Set the package name for later use.
    environment.set_value('PKG_NAME', package_name)

    # Install the application apk.
    android.device.install_application_if_needed(
        testcase_file_path, force_update=True)

  # Set app launch command if available from upload.
  app_launch_command = testcase.get_metadata('app_launch_command')
  if app_launch_command:
    environment.set_value('APP_LAUNCH_COMMAND', app_launch_command)

  # Set executable bit on the testcase (to allow binary executable testcases
  # to work in app launch command, e.g. shell %TESTCASE%).
  local_testcases_directory = environment.get_value('FUZZ_INPUTS')
  if (testcase_file_path and
      testcase_file_path.startswith(local_testcases_directory)):
    relative_testcase_file_path = (
        testcase_file_path[len(local_testcases_directory) + 1:])
    device_testcase_file_path = os.path.join(
        android.constants.DEVICE_TESTCASES_DIR, relative_testcase_file_path)
    android.adb.run_shell_command(['chmod', '0755', device_testcase_file_path])


def _get_application_arguments(testcase, job_type, task_name):
  """Get application arguments to use for setting up |testcase|. Use minimized
   arguments if available. For variant task, where we run a testcase against
   another job type, use both minimized arguments and application arguments
   from job."""
  testcase_args = testcase.minimized_arguments
  if not testcase_args:
    return None

  if task_name != 'variant':
    return testcase_args

  # TODO(aarya): Use %TESTCASE% explicitly since it will not exist with new
  # engine impl libFuzzer testcases and AFL's launcher.py requires it as the
  # first argument. Remove once AFL is migrated to the new engine impl.
  if environment.is_afl_job(job_type):
    return '%TESTCASE%'

  job_args = data_handler.get_value_from_job_definition(
      job_type, 'APP_ARGS', default='')
  job_args_list = shlex.split(job_args)
  testcase_args_list = shlex.split(testcase_args)
  testcase_args_filtered_list = [
      arg for arg in testcase_args_list if arg not in job_args_list
  ]

  app_args = ' '.join(testcase_args_filtered_list)
  if job_args:
    if app_args:
      app_args += ' '
    app_args += job_args

  return app_args


def _setup_memory_tools_environment(testcase):
  """Set up environment for various memory tools used."""
  env = testcase.get_metadata('env')
  if not env:
    environment.reset_current_memory_tool_options(
        redzone_size=testcase.redzone, disable_ubsan=testcase.disable_ubsan)
    return

  for options_name, options_value in env.items():
    if not options_value:
      environment.remove_key(options_name)
      continue
    environment.set_memory_tool_options(options_name, options_value)


def prepare_environment_for_testcase(testcase):
  """Set various environment variables based on the test case."""
  _setup_memory_tools_environment(testcase)

  # Setup environment variable for windows size and location properties.
  # Explicit override to avoid using the default one from job definition since
  # that contains unsubsituted vars like $WIDTH, etc.
  environment.set_value('WINDOW_ARG', testcase.window_argument)

  # Adjust timeout based on the stored multiplier (if available).
  if testcase.timeout_multiplier:
    test_timeout = environment.get_value('TEST_TIMEOUT')
    environment.set_value('TEST_TIMEOUT',
                          int(test_timeout * testcase.timeout_multiplier))

  # Add FUZZ_TARGET to environment if this is a fuzz target testcase.
  fuzz_target = testcase.get_metadata('fuzzer_binary_name')
  if fuzz_target:
    environment.set_value('FUZZ_TARGET', fuzz_target)


def handle_setup_testcase_error(uworker_output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Error handler for setup_testcase that is called by uworker_postprocess."""
  # Get the testcase again because it is too hard to set the testcase for
  # partially migrated tasks.
  # TODO(metzman): Experiment with making this unnecessary.
  # First update comment.
  testcase = data_handler.get_testcase_by_id(
      uworker_output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       uworker_output.error_message)

  # Then reschedule the task.
  command = task_utils.get_command_from_module(
      uworker_output.uworker_input.module_name)

  testcase_fail_wait = environment.get_value('FAIL_WAIT')
  tasks.add_task(
      command,
      uworker_output.uworker_input.testcase_id,
      uworker_output.uworker_input.job_type,
      wait_time=testcase_fail_wait)


ERROR_HANDLER = uworker_handle_errors.CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.TESTCASE_SETUP: handle_setup_testcase_error,  # pylint: disable=no-member
})


def preprocess_setup_testcase(testcase,
                              uworker_env,
                              fuzzer_override=None,
                              with_deps=True):
  """Preprocessing for setup_testcase function."""
  fuzzer_name = fuzzer_override or testcase.fuzzer_name
  testcase_id = testcase.key.id()
  if fuzzer_name and not with_deps:
    logs.info(f'Skipping fuzzer preprocess: {fuzzer_name}.')
  if fuzzer_name and with_deps:
    # This branch is taken when we assume fuzzer needs to be set up for a
    # testcase to be executed (i.e. when a testcase was found by a fuzzer).
    # It's not the case for testcases uploaded by users.
    try:
      setup_input = preprocess_update_fuzzer_and_data_bundles(fuzzer_name)
    except errors.InvalidFuzzerError:
      # Close testcase and don't recreate tasks if this fuzzer is invalid.
      logs.error('Closed testcase %d with invalid fuzzer %s.' % (testcase_id,
                                                                 fuzzer_name))
      error_message = f'Fuzzer {fuzzer_name} no longer exists.'
      # First update comment.
      testcase = data_handler.get_testcase_by_id(testcase_id)
      data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                           error_message)
      testcase.open = False
      testcase.fixed = 'NA'
      testcase.set_metadata('fuzzer_was_deleted', True)
      testcase.put()
      raise
  else:
    setup_input = uworker_msg_pb2.SetupInput()  # pylint: disable=no-member
  setup_input.testcase_download_url = get_signed_testcase_download_url(testcase)
  if environment.get_value('LSAN'):
    setup_input.global_blacklisted_functions.extend(
        leak_blacklist.get_global_blacklisted_functions())
  if testcase.uploader_email:
    _set_timeout_value_from_user_upload(testcase_id, uworker_env)

  # Override APP_ARGS with minimized arguments (if available). Don't do this
  # for variant task since other job types can have its own set of required
  # arguments, so use the full set of arguments of that job.
  app_args = _get_application_arguments(testcase, uworker_env['JOB_NAME'],
                                        uworker_env['TASK_NAME'])
  if app_args:
    environment.set_value('APP_ARGS', app_args, uworker_env)
  return setup_input


def setup_testcase(testcase: data_types.Testcase, job_type: str,
                   setup_input: uworker_msg_pb2.SetupInput):  # pylint: disable=no-member
  """Sets up the testcase and needed dependencies like fuzzer, data bundle,
  etc."""
  testcase_id = testcase.key.id()
  # Prepare an error result to return in case of error.
  # Only include uworker_input for callers that aren't deserializing the output
  # and thus, uworker_io is not adding the input to.
  # TODO(metzman): Remove the input when the consolidation is complete.
  uworker_error_input = uworker_msg_pb2.Input(  # pylint: disable=no-member
      testcase_id=str(testcase_id),
      job_type=job_type)
  uworker_error_output = uworker_msg_pb2.Output(  # pylint: disable=no-member
      uworker_input=uworker_error_input,
      error_type=uworker_msg_pb2.ErrorType.TESTCASE_SETUP)  # pylint: disable=no-member

  testcase_setup_error_result = (None, None, uworker_error_output)

  # Clear testcase directories.
  shell.clear_testcase_directories()

  # Update the fuzzer if necessary in order to get the updated data bundle.
  if setup_input.fuzzer_name:
    update_successful = update_fuzzer_and_data_bundles(setup_input)
    if not update_successful:
      error_message = f'Unable to setup fuzzer {setup_input.fuzzer_name}'
      uworker_error_output.error_message = error_message
      return testcase_setup_error_result

  # Extract the testcase and any of its resources to the input directory.
  file_list, testcase_file_path = unpack_testcase(
      testcase, setup_input.testcase_download_url)
  if not file_list:
    error_message = f'Unable to setup testcase {testcase_file_path}'
    uworker_error_output.error_message = error_message
    return testcase_setup_error_result

  # For Android/Fuchsia, we need to sync our local testcases directory with the
  # one on the device.
  if environment.is_android():
    _copy_testcase_to_device_and_setup_environment(testcase, testcase_file_path)

  # Push testcases to worker.
  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    file_host.push_testcases_to_worker()

  # Copy global blacklist into local blacklist.
  if setup_input.global_blacklisted_functions:
    # Get local blacklist without this testcase's entry.
    leak_blacklist.copy_global_to_local_blacklist(
        setup_input.global_blacklisted_functions, excluded_testcase=testcase)

  prepare_environment_for_testcase(testcase)

  return file_list, testcase_file_path, None


def _get_testcase_file_and_path(testcase):
  """Figure out the relative path and input directory for this testcase."""
  testcase_absolute_path = testcase.absolute_path

  # This hack is needed so that we can run a testcase generated on windows, on
  # linux. os.path.isabs return false on paths like c:\a\b\c.
  testcase_path_is_absolute = (
      testcase_absolute_path[1:3] == ':\\' or
      os.path.isabs(testcase_absolute_path))

  # Fix os.sep in testcase path if we are running this on non-windows platform.
  # It is unusual to have '\\' on linux paths, so substitution should be safe.
  if environment.platform() != 'WINDOWS' and '\\' in testcase_absolute_path:
    testcase_absolute_path = testcase_absolute_path.replace('\\', os.sep)

  # Default directory for testcases.
  input_directory = environment.get_value('FUZZ_INPUTS')
  if not testcase_path_is_absolute:
    testcase_path = os.path.join(input_directory, testcase_absolute_path)
    return input_directory, testcase_path

  # Root directory can be different on bots. Fix the path to account for this.
  root_directory = environment.get_value('ROOT_DIR')
  search_string = '%s%s%s' % (os.sep, _BOT_DIR, os.sep)
  search_index = testcase_absolute_path.find(search_string)
  relative_path = testcase_absolute_path[search_index + len(search_string):]
  testcase_path = os.path.join(root_directory, _BOT_DIR, relative_path)

  return input_directory, testcase_path


def get_signed_testcase_download_url(testcase):
  """Returns a signed download URL for the testcase."""
  key, _ = _get_testcase_key_and_archive_status(testcase)
  return blobs.get_signed_download_url(key)


def _get_testcase_key_and_archive_status(testcase):
  """Returns the testcase's key and whether or not it is archived."""
  if _is_testcase_minimized(testcase):
    key = testcase.minimized_keys
    archived = bool(testcase.archive_state & data_types.ArchiveStatus.MINIMIZED)
    return key, archived

  key = testcase.fuzzed_keys
  archived = bool(testcase.archive_state & data_types.ArchiveStatus.FUZZED)
  return key, archived


def _is_testcase_minimized(testcase):
  return testcase.minimized_keys and testcase.minimized_keys != 'NA'


def download_testcase(testcase_download_url, dst):
  logs.info(f'Downloading testcase from: {testcase_download_url}')
  return storage.download_signed_url_to_file(testcase_download_url, dst)


def unpack_testcase(testcase, testcase_download_url):
  """Unpacks a testcase and returns all files it is composed of."""
  # Figure out where the testcase file should be stored.
  input_directory, testcase_file_path = _get_testcase_file_and_path(testcase)

  key, archived = _get_testcase_key_and_archive_status(testcase)
  if _is_testcase_minimized(testcase) and archived:
    temp_filename = (
        os.path.join(input_directory,
                     str(testcase.key.id()) + _TESTCASE_ARCHIVE_EXTENSION))
  elif archived:
    temp_filename = os.path.join(input_directory, testcase.archive_filename)
  else:
    temp_filename = testcase_file_path

  if not download_testcase(testcase_download_url, temp_filename):
    logs.info(f'Couldn\'t download testcase {key} {testcase_download_url}.')
    return None, testcase_file_path

  file_list = []
  if archived:
    with archive.open(temp_filename) as reader:
      reader.extract_all(input_directory)
      file_list = [f.name for f in reader.list_members()]

    shell.remove_file(temp_filename)

    file_exists = False
    for file_name in file_list:
      if os.path.basename(file_name) == os.path.basename(testcase_file_path):
        file_exists = True
        break

    if not file_exists:
      logs.error(
          'Expected file to run %s is not in archive. Base directory is %s and '
          'files in archive are [%s].' % (testcase_file_path, input_directory,
                                          ','.join(file_list)))
      return None, testcase_file_path
  else:
    file_list.append(testcase_file_path)

  return file_list, testcase_file_path


def _get_data_bundle_update_lock_name(data_bundle_name):
  """Return the lock key name for the given data bundle."""
  return f'update:data_bundle:{data_bundle_name}'


def _get_data_bundle_sync_file_path(data_bundle_directory):
  """Return path to data bundle sync file."""
  return os.path.join(data_bundle_directory, _SYNC_FILENAME)


def _clear_old_data_bundles_if_needed():
  """Clear old data bundles so as to keep the disk cache restricted to
  |_DATA_BUNDLE_CACHE_COUNT| data bundles and prevent potential out-of-disk
  spaces."""
  data_bundles_directory = environment.get_value('DATA_BUNDLES_DIR')

  dirs = []
  for filename in os.listdir(data_bundles_directory):
    file_path = os.path.join(data_bundles_directory, filename)
    if not os.path.isdir(file_path):
      continue
    dirs.append(file_path)

  dirs_to_remove = sorted(
      dirs, key=os.path.getmtime, reverse=True)[_DATA_BUNDLE_CACHE_COUNT:]
  for dir_to_remove in dirs_to_remove:
    logs.info('Removing data bundle directory to keep disk cache small: %s' %
              dir_to_remove)
    shell.remove_directory(dir_to_remove)


def _should_update_data_bundle(data_bundle, data_bundle_directory):
  """Returns True if the data bundle should be updated because it is out of
  date."""
  # Check if data bundle is up to date. If yes, skip the update.
  if _is_data_bundle_up_to_date(data_bundle, data_bundle_directory):
    logs.info('Data bundle was recently synced, skip.')
    return False

  # Re-check if another bot did the sync already. If yes, skip.
  # TODO(metzman): Figure out if is this even needed without NFS?
  if _is_data_bundle_up_to_date(data_bundle, data_bundle_directory):
    logs.info('Another bot finished the sync, skip.')
    return False

  return True


def _prepare_update_data_bundle(fuzzer, data_bundle):
  """Create necessary directories to download the data bundle."""
  data_bundle_directory = get_data_bundle_directory(fuzzer, data_bundle)
  if not data_bundle_directory:
    logs.error('Failed to setup data bundle %s.' % data_bundle.name)
    return None

  if not shell.create_directory(
      data_bundle_directory, create_intermediates=True):
    logs.error('Failed to create data bundle %s directory.' % data_bundle.name)
    return None

  return data_bundle_directory


def update_data_bundle(
    fuzzer: data_types.Fuzzer,
    data_bundle_corpus: uworker_msg_pb2.DataBundleCorpus) -> bool:  # pylint: disable=no-member
  """Updates a data bundle to the latest version."""
  data_bundle = uworker_io.entity_from_protobuf(data_bundle_corpus.data_bundle,
                                                data_types.DataBundle)
  logs.info('Setting up data bundle %s.' % data_bundle)

  data_bundle_directory = _prepare_update_data_bundle(fuzzer, data_bundle)

  if not _should_update_data_bundle(data_bundle, data_bundle_directory):
    return True

  time_before_sync_start = time.time()

  # No need to sync anything if this is a search index data bundle. In that
  # case, the fuzzer will generate testcases from a gcs bucket periodically.
  if not _is_search_index_data_bundle(data_bundle.name):

    if not (environment.is_trusted_host() and data_bundle.sync_to_worker):
      result = corpus_manager.sync_data_bundle_corpus_to_disk(
          data_bundle_corpus, data_bundle_directory)
    else:
      from clusterfuzz._internal.bot.untrusted_runner import \
          corpus_manager as untrusted_corpus_manager
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      worker_data_bundle_directory = file_host.rebase_to_worker_root(
          data_bundle_directory)

      file_host.create_directory(
          worker_data_bundle_directory, create_intermediates=True)
      result = untrusted_corpus_manager.RemoteGSUtilRunner().rsync(
          data_bundle_corpus.gcs_url,
          worker_data_bundle_directory,
          delete=False)
      result = result.return_code == 0

    if not result:
      logs.error(f'Failed to sync data bundle {data_bundle.name}.')
      return False

  # Update the testcase list file.
  testcase_manager.create_testcase_list_file(data_bundle_directory)
  logs.info('Synced data bundle.')

  #  Write last synced time in the sync file.
  sync_file_path = _get_data_bundle_sync_file_path(data_bundle_directory)
  utils.write_data_to_file(time_before_sync_start, sync_file_path)
  if environment.is_trusted_host() and data_bundle.sync_to_worker:
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    worker_sync_file_path = file_host.rebase_to_worker_root(sync_file_path)
    file_host.copy_file_to_worker(sync_file_path, worker_sync_file_path)

  return True


def _set_fuzzer_env_vars(fuzzer):
  """Sets fuzzer env vars for fuzzer set up."""
  environment.set_value('UNTRUSTED_CONTENT', fuzzer.untrusted_content)
  # Adjust the test timeout, if user has provided one.
  if fuzzer.timeout:
    environment.set_value('TEST_TIMEOUT', fuzzer.timeout)

    # Increase fuzz test timeout if the fuzzer timeout is higher than its
    # current value.
    fuzz_test_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')
    if fuzz_test_timeout and fuzz_test_timeout < fuzzer.timeout:
      environment.set_value('FUZZ_TEST_TIMEOUT', fuzzer.timeout)

  # Adjust the max testcases if this fuzzer has specified a lower limit.
  max_testcases = environment.get_value('MAX_TESTCASES')
  if fuzzer.max_testcases and fuzzer.max_testcases < max_testcases:
    environment.set_value('MAX_TESTCASES', fuzzer.max_testcases)

  # If the fuzzer generates large testcases or a large number of small ones
  # that don't fit on tmpfs, then use the larger disk directory.
  if fuzzer.has_large_testcases:
    testcase_disk_directory = environment.get_value('FUZZ_INPUTS_DISK')
    environment.set_value('FUZZ_INPUTS', testcase_disk_directory)


def preprocess_get_data_bundles(data_bundle_name, setup_input):
  data_bundles = list(
      ndb_utils.get_all_from_query(
          data_types.DataBundle.query(
              data_types.DataBundle.name == data_bundle_name)))
  logs.info(f'Data bundles: {data_bundles}')
  setup_input.data_bundle_corpuses.extend([
      corpus_manager.get_proto_data_bundle_corpus(bundle_entity)
      for bundle_entity in data_bundles
  ])


def preprocess_update_fuzzer_and_data_bundles(
    fuzzer_name: str) -> uworker_msg_pb2.SetupInput:  # pylint: disable=no-member
  """Does preprocessing for calls to update_fuzzer_and_data_bundles in
  uworker_main. Returns a SetupInput object."""
  fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer_name).get()
  if not fuzzer:
    logs.error('No fuzzer exists with name %s.' % fuzzer_name)
    raise errors.InvalidFuzzerError

  update_input = uworker_msg_pb2.SetupInput(  # pylint: disable=no-member
      fuzzer_name=fuzzer_name,
      fuzzer=uworker_io.entity_to_protobuf(fuzzer))
  preprocess_get_data_bundles(fuzzer.data_bundle_name, update_input)
  update_input.fuzzer_log_upload_url = storage.get_signed_upload_url(
      fuzzer_logs.get_logs_gcs_path(fuzzer_name=fuzzer_name))
  if not fuzzer.builtin:
    update_input.fuzzer_download_url = blobs.get_signed_download_url(
        fuzzer.blobstore_key)

  # TODO(https://github.com/google/clusterfuzz/issues/3008): Finish migrating
  # update data bundles.

  return update_input


def _update_fuzzer(
    update_input: uworker_msg_pb2.SetupInput,  # pylint: disable=no-member
    fuzzer_directory: str,
    version_file: str) -> bool:
  """Updates the fuzzer. Helper for update_fuzzer_and_data_bundles."""
  fuzzer = uworker_io.entity_from_protobuf(update_input.fuzzer,
                                           data_types.Fuzzer)
  fuzzer_name = update_input.fuzzer_name
  if fuzzer.builtin:
    return True

  if not revisions.needs_update(version_file, fuzzer.revision):
    return True

  logs.info('Fuzzer update was found, updating.')

  # Clear the old fuzzer directory if it exists.
  if not shell.remove_directory(fuzzer_directory, recreate=True):
    logs.error('Failed to clear fuzzer directory.')
    return False

  # Copy the archive to local disk and unpack it.
  archive_path = os.path.join(fuzzer_directory, fuzzer.filename)
  if not storage.download_signed_url_to_file(update_input.fuzzer_download_url,
                                             archive_path):
    logs.error('Failed to copy fuzzer archive.')
    return False

  try:
    with archive.open(archive_path) as reader:
      reader.extract_all(fuzzer_directory)
  except Exception:
    error_message = (f'Failed to unpack fuzzer archive {fuzzer.filename} '
                     '(bad archive or unsupported format).')
    logs.error(error_message)
    fuzzer_logs.upload_script_log(
        'Fatal error: ' + error_message,
        signed_upload_url=update_input.fuzzer_log_upload_url)

    return False

  fuzzer_path = os.path.join(fuzzer_directory, fuzzer.executable_path)
  if not os.path.exists(fuzzer_path):
    error_message = ('Fuzzer executable %s not found. '
                     'Check fuzzer configuration.') % fuzzer.executable_path
    logs.error(error_message)
    fuzzer_logs.upload_script_log(
        'Fatal error: ' + error_message,
        fuzzer_name=fuzzer_name,
        signed_upload_url=update_input.fuzzer_log_upload_url)
    return False

  # Make fuzzer executable.
  os.chmod(fuzzer_path, 0o750)

  # Cleanup unneeded archive.
  shell.remove_file(archive_path)

  # Save the current revision of this fuzzer in a file for later checks.
  revisions.write_revision_to_revision_file(version_file, fuzzer.revision)
  logs.info('Updated fuzzer to revision %d.' % fuzzer.revision)
  return True


def _set_up_data_bundles(update_input: uworker_msg_pb2.SetupInput):  # pylint: disable=no-member
  """Sets up data bundles. Helper for update_fuzzer_and_data_bundles."""
  # Setup data bundles associated with this fuzzer.
  logs.info('Setting up data bundles.')
  fuzzer = uworker_io.entity_from_protobuf(update_input.fuzzer,
                                           data_types.Fuzzer)
  for data_bundle_corpus in update_input.data_bundle_corpuses:
    if not update_data_bundle(fuzzer, data_bundle_corpus):
      return False

  return True


def update_fuzzer_and_data_bundles(
    update_input: uworker_msg_pb2.SetupInput) -> Optional[data_types.Fuzzer]:  # pylint: disable=no-member
  """Updates the fuzzer specified by |update_input| and its data bundles."""
  fuzzer = uworker_io.entity_from_protobuf(update_input.fuzzer,
                                           data_types.Fuzzer)

  _set_fuzzer_env_vars(fuzzer)
  # Set some helper environment variables.
  fuzzer_directory = get_fuzzer_directory(update_input.fuzzer_name)
  environment.set_value('FUZZER_DIR', fuzzer_directory)

  # Check for updates to this fuzzer.
  version_file = os.path.join(fuzzer_directory,
                              f'.{update_input.fuzzer_name}_version')
  if not _update_fuzzer(update_input, fuzzer_directory, version_file):
    return None
  _clear_old_data_bundles_if_needed()
  if not _set_up_data_bundles(update_input):
    return None

  # Setup environment variable for launcher script path.
  if fuzzer.launcher_script:
    fuzzer_launcher_path = os.path.join(fuzzer_directory,
                                        fuzzer.launcher_script)
    environment.set_value('LAUNCHER_PATH', fuzzer_launcher_path)

    # For launcher script usecase, we need the entire fuzzer directory on the
    # worker.
    if environment.is_trusted_host():
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      worker_fuzzer_directory = file_host.rebase_to_worker_root(
          fuzzer_directory)
      file_host.copy_directory_to_worker(
          fuzzer_directory, worker_fuzzer_directory, replace=True)

  return fuzzer


def _is_search_index_data_bundle(data_bundle_name):
  """Return true on if this is a search index data bundle, false otherwise."""
  return data_bundle_name.startswith(
      testcase_manager.SEARCH_INDEX_BUNDLE_PREFIX)


def _is_data_bundle_up_to_date(data_bundle, data_bundle_directory):
  """Return true if the data bundle is up to date, false otherwise."""
  sync_file_path = _get_data_bundle_sync_file_path(data_bundle_directory)

  if environment.is_trusted_host() and data_bundle.sync_to_worker:
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    worker_sync_file_path = file_host.rebase_to_worker_root(sync_file_path)
    shell.remove_file(sync_file_path)
    file_host.copy_file_from_worker(worker_sync_file_path, sync_file_path)

  if not os.path.exists(sync_file_path):
    return False

  last_sync_time = datetime.datetime.utcfromtimestamp(
      utils.read_data_from_file(sync_file_path))

  # Check if we recently synced.
  if not dates.time_has_expired(
      last_sync_time, seconds=_DATA_BUNDLE_SYNC_INTERVAL_IN_SECONDS):
    return True

  # For search index data bundle, we don't sync them from bucket. Instead, we
  # rely on the fuzzer to generate testcases periodically.
  if _is_search_index_data_bundle(data_bundle.name):
    return False

  # Check when the bucket url had last updates. If no new updates, no need to
  # update directory.
  bucket_url = data_handler.get_data_bundle_bucket_url(data_bundle.name)
  last_updated_time = storage.last_updated(bucket_url)
  if last_updated_time and last_sync_time > last_updated_time:
    logs.info(
        'Data bundle %s has no new content from last sync.' % data_bundle.name)
    return True

  return False


def trusted_get_data_bundle_directory(fuzzer):
  """For fuzz_task which doesn't get data bundles in an untrusted manner."""
  # TODO(metzman): Delete this when fuzz_task is migrated.
  # Check if we have a fuzzer-specific data bundle. Use it to calculate the
  # data directory we will fetch our testcases from.
  data_bundle = data_types.DataBundle.query(
      data_types.DataBundle.name == fuzzer.data_bundle_name).get()
  return get_data_bundle_directory(fuzzer, data_bundle)


def get_data_bundle_directory(fuzzer, data_bundle):
  """Return data bundle data directory."""
  # Store corpora for built-in fuzzers like libFuzzer in the same directory
  # as other local data bundles. This makes it easy to clear them when we run
  # out of disk space.
  local_data_bundles_directory = environment.get_value('DATA_BUNDLES_DIR')
  if fuzzer.builtin:
    return local_data_bundles_directory

  if not data_bundle:
    # Generic data bundle directory. Available to all fuzzers if they don't
    # have their own data bundle.
    return environment.get_value('FUZZ_DATA')

  local_data_bundle_directory = os.path.join(local_data_bundles_directory,
                                             data_bundle.name)

  return local_data_bundle_directory


def get_fuzzer_directory(fuzzer_name):
  """Return directory used by a fuzzer."""
  fuzzer_directory = environment.get_value('FUZZERS_DIR')
  fuzzer_directory = os.path.join(fuzzer_directory, fuzzer_name)
  return fuzzer_directory


def archive_testcase_and_dependencies_in_gcs(resource_list, testcase_path: str,
                                             upload_url: str):
  """Archive testcase and its dependencies, and store in blobstore. Returns
  whether it is archived, the absolute_filename, and the zip_filename."""
  if not os.path.exists(testcase_path):
    logs.error('Unable to find testcase %s.' % testcase_path)
    return None, None, None

  absolute_filename = testcase_path
  archived = False
  zip_filename = None
  zip_path = None

  if not resource_list:
    resource_list = []

  # Add resource dependencies based on testcase path. These include
  # stuff like extensions directory, dependency files, etc.
  resource_list.extend(
      testcase_manager.get_resource_dependencies(testcase_path))

  # Filter out duplicates, directories, and files that do not exist.
  resource_list = utils.filter_file_list(resource_list)

  logs.info('Testcase and related files :\n%s' % str(resource_list))

  if len(resource_list) <= 1:
    # If this does not have any resources, just save the testcase.
    # TODO(flowerhack): Update this when we teach CF how to download testcases.
    try:
      file_handle = open(testcase_path, 'rb')
    except OSError:
      logs.error('Unable to open testcase %s.' % testcase_path)
      return None, None, None
  else:
    # If there are resources, create an archive.

    # Find the common root directory for all of the resources.
    # Assumption: resource_list[0] is the testcase path.
    base_directory_list = resource_list[0].split(os.path.sep)
    for list_index in range(1, len(resource_list)):
      current_directory_list = resource_list[list_index].split(os.path.sep)
      length = min(len(base_directory_list), len(current_directory_list))
      for directory_index in range(length):
        if (current_directory_list[directory_index] !=
            base_directory_list[directory_index]):
          base_directory_list = base_directory_list[0:directory_index]
          break

    base_directory = os.path.sep.join(base_directory_list)
    logs.info('Subresource common base directory: %s' % base_directory)
    if base_directory:
      # Common parent directory, archive sub-paths only.
      base_len = len(base_directory) + len(os.path.sep)
    else:
      # No common parent directory, archive all paths as it-is.
      base_len = 0

    # Prepare the filename for the archive.
    zip_filename, _ = os.path.splitext(os.path.basename(testcase_path))
    zip_filename += _TESTCASE_ARCHIVE_EXTENSION

    # Create the archive.
    zip_path = os.path.join(environment.get_value('INPUT_DIR'), zip_filename)
    zip_file = zipfile.ZipFile(zip_path, 'w')
    for file_name in resource_list:
      if os.path.exists(file_name):
        relative_filename = file_name[base_len:]
        zip_file.write(file_name, relative_filename, zipfile.ZIP_DEFLATED)
    zip_file.close()

    try:
      file_handle = open(zip_path, 'rb')
    except OSError:
      logs.error('Unable to open testcase archive %s.' % zip_path)
      return None, None, None

    archived = True
    absolute_filename = testcase_path[base_len:]

  if not storage.upload_signed_url(file_handle, upload_url):
    logs.log_error('Failed to upload testcase.')
    return None, None, None

  file_handle.close()

  # Don't need the archive after writing testcase to blobstore.
  if zip_path:
    shell.remove_file(zip_path)

  return archived, absolute_filename, zip_filename

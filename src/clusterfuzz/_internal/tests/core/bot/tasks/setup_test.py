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
"""Tests for setup."""

import os
import unittest

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


# pylint: disable=protected-access
@test_utils.with_cloud_emulators('datastore')
class GetApplicationArgumentsTest(unittest.TestCase):
  """Tests _get_application_arguments."""

  def setUp(self):
    helpers.patch_environ(self)

    data_types.Job(
        name='linux_asan_chrome',
        environment_string='APP_ARGS = --orig-arg1 --orig-arg2').put()
    data_types.Job(
        name='linux_msan_chrome_variant',
        environment_string=(
            'APP_ARGS = --arg1 --arg2 --arg3="--flag1 --flag2"')).put()

    data_types.Job(name='libfuzzer_asan_chrome', environment_string='').put()
    data_types.Job(
        name='libfuzzer_msan_chrome_variant', environment_string='').put()
    data_types.Job(name='afl_asan_chrome_variant', environment_string='').put()

    self.testcase = test_utils.create_generic_testcase()

  def test_no_minimized_arguments(self):
    """Test that None is returned when minimized arguments is not set."""
    self.testcase.minimized_arguments = ''
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        None,
        setup._get_application_arguments(self.testcase, 'linux_asan_chrome',
                                         'minimize'))
    self.assertEqual(
        None,
        setup._get_application_arguments(
            self.testcase, 'linux_msan_chrome_variant', 'variant'))

  def test_minimized_arguments_for_non_variant_task(self):
    """Test that minimized arguments are returned for non-variant tasks."""
    self.testcase.minimized_arguments = '--orig-arg2'
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--orig-arg2',
        setup._get_application_arguments(self.testcase, 'linux_asan_chrome',
                                         'minimize'))

  def test_no_unique_minimized_arguments_for_variant_task(self):
    """Test that only APP_ARGS is returned if minimized arguments have no
    unique arguments, for variant task."""
    self.testcase.minimized_arguments = '--arg2'
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--arg1 --arg2 --arg3="--flag1 --flag2"',
        setup._get_application_arguments(
            self.testcase, 'linux_msan_chrome_variant', 'variant'))

  def test_some_duplicate_minimized_arguments_for_variant_task(self):
    """Test that both minimized arguments and APP_ARGS are returned with
    duplicate args stripped from minimized arguments for variant task."""
    self.testcase.minimized_arguments = '--arg3="--flag1 --flag2" --arg4'
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--arg4 --arg1 --arg2 --arg3="--flag1 --flag2"',
        setup._get_application_arguments(
            self.testcase, 'linux_msan_chrome_variant', 'variant'))

  def test_unique_minimized_arguments_for_variant_task(self):
    """Test that both minimized arguments and APP_ARGS are returned when they
    don't have common args for variant task."""
    self.testcase.minimized_arguments = '--arg5'
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--arg5 --arg1 --arg2 --arg3="--flag1 --flag2"',
        setup._get_application_arguments(
            self.testcase, 'linux_msan_chrome_variant', 'variant'))

  def test_no_job_app_args_for_variant_task(self):
    """Test that only minimized arguments is returned when APP_ARGS is not set
    in job definition."""
    self.testcase.minimized_arguments = '--arg5'
    self.testcase.job_type = 'libfuzzer_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--arg5',
        setup._get_application_arguments(
            self.testcase, 'libfuzzer_msan_chrome_variant', 'variant'))

  def test_afl_job_for_variant_task(self):
    """Test that we use a different argument list if this is an afl variant
    task."""
    self.testcase.minimized_arguments = '--arg5'
    self.testcase.job_type = 'libfuzzer_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '%TESTCASE%',
        setup._get_application_arguments(self.testcase,
                                         'afl_asan_chrome_variant', 'variant'))


# pylint: disable=protected-access
class ClearOldDataBundlesIfNeededTest(fake_filesystem_unittest.TestCase):
  """Tests _clear_old_data_bundles_if_needed."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    helpers.patch_environ(self)

    self.data_bundles_dir = '/data-bundles'
    os.mkdir(self.data_bundles_dir)
    environment.set_value('DATA_BUNDLES_DIR', self.data_bundles_dir)

  def test_evict(self):
    """Tests that eviction works when more than certain number of bundles."""
    for i in range(1, 15):
      os.mkdir(os.path.join(self.data_bundles_dir, str(i)))

    setup._clear_old_data_bundles_if_needed()
    self.assertEqual([str(i) for i in range(5, 15)],
                     sorted(os.listdir(self.data_bundles_dir), key=int))

  def test_no_evict(self):
    """Tests that no eviction is required when less than certain number of
    bundles."""
    for i in range(1, 5):
      os.mkdir(os.path.join(self.data_bundles_dir, str(i)))

    setup._clear_old_data_bundles_if_needed()
    self.assertEqual([str(i) for i in range(1, 5)],
                     sorted(os.listdir(self.data_bundles_dir), key=int))


@test_utils.with_cloud_emulators('datastore')
class PreprocessGetDataBundlesTest(unittest.TestCase):
  """Tests for preprocess_get_data_bundles."""

  def setUp(self):
    self.setup_input = uworker_msg_pb2.SetupInput()
    helpers.patch_environ(self)
    environment.set_value('TASK_NAME', 'fuzz')
    environment.set_value('JOB_NAME', 'libfuzzer_chrome_asan')

  def test_no_bundles(self):
    """Tests that preprocess_get_data_bundles works when there are no data
    bundles."""
    setup.preprocess_get_data_bundles('fake', self.setup_input)
    self.assertEqual(list(self.setup_input.data_bundle_corpuses), [])

  def test_bundles(self):
    """Tests that preprocess_get_data_bundles works when there are bundles."""
    bundles_name = 'mybundle'
    bundles = [
        data_types.DataBundle(name=bundles_name),
        data_types.DataBundle(name=bundles_name)
    ]
    for bundle in bundles:
      bundle.put()
    setup.preprocess_get_data_bundles(bundles_name, self.setup_input)
    saved_bundles = [
        uworker_io.entity_from_protobuf(corpus.data_bundle,
                                        data_types.DataBundle)
        for corpus in self.setup_input.data_bundle_corpuses
    ]
    self.assertEqual(bundles, saved_bundles)


@test_utils.with_cloud_emulators('datastore')
class TestPreprocessUpdateFuzzerAndDataBundles(unittest.TestCase):
  """Tests for preprocess_update_fuzzer_and_data_bundles."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.get_signed_upload_url',
        'clusterfuzz._internal.google_cloud_utils.blobs.get_signed_download_url',
        'clusterfuzz._internal.bot.tasks.task_types.is_remote_utask',
        'clusterfuzz._internal.bot.tasks.setup._update_fuzzer',
        'clusterfuzz._internal.bot.tasks.setup._clear_old_data_bundles_if_needed',
        'clusterfuzz._internal.bot.tasks.setup.update_data_bundle',
    ])
    self.mock.get_signed_upload_url.return_value = 'https://fake/upload'
    self.mock.get_signed_download_url.return_value = 'https://fake/download'
    self.fuzzer_name = 'fuzzer'
    data_bundle_name = 'data_bundle_name'
    data_types.Fuzzer(
        name=self.fuzzer_name, data_bundle_name=data_bundle_name).put()
    self.data_bundle = data_types.DataBundle(name=data_bundle_name)
    self.data_bundle.put()
    data_types.DataBundle(name=data_bundle_name).put()
    helpers.patch_environ(self)
    environment.set_value('FUZZERS_DIR', '/fuzzer')

  def test_data_bundles(self):
    """Tests that data bundles are set properly in preprocess."""
    self.mock.is_remote_utask.return_value = False
    setup_input = setup.preprocess_update_fuzzer_and_data_bundles(
        self.fuzzer_name)
    setup.update_fuzzer_and_data_bundles(setup_input)
    self.assertEqual(self.mock.update_data_bundle.call_count, 2)


class SetupLocalFuzzerTest(unittest.TestCase):
  """Tests for the setup_local_fuzzer function."""

  def setUp(self):
    super().setUp()
    helpers.patch_environ(self)
    self.addCleanup(unittest.mock.patch.stopall)

    self.mock_logs = unittest.mock.patch.multiple(
        'local.butler.reproduce.logs',
        error=unittest.mock.DEFAULT,
        info=unittest.mock.DEFAULT,
        warning=unittest.mock.DEFAULT).start()

    helpers.patch(self, [
        'clusterfuzz._internal.datastore.data_types.Fuzzer.query',
        'clusterfuzz._internal.system.environment.set_value',
        'clusterfuzz._internal.bot.tasks.setup.get_fuzzer_directory',
        'clusterfuzz._internal.system.shell.remove_directory',
        'clusterfuzz._internal.google_cloud_utils.blobs.read_blob_to_disk',
        'clusterfuzz._internal.system.archive.open',
        'clusterfuzz._internal.system.shell.remove_file',
        'os.path.exists',
        'os.chmod',
    ])

    # Alias for clarity
    self.mock_fuzzer_query = self.mock.query
    self.mock_get = self.mock_fuzzer_query.return_value.get

    # Default return values for success paths
    self.mock.get_fuzzer_directory.return_value = '/tmp/fuzzer_dir'
    self.mock.remove_directory.return_value = True
    self.mock.read_blob_to_disk.return_value = True

    self.mock_archive_reader = unittest.mock.create_autospec(
        spec=archive.ArchiveReader, instance=True, spec_set=True)
    self.mock.open.return_value.__enter__.return_value = self.mock_archive_reader

    # Common fuzzer object
    self.fuzzer = data_types.Fuzzer(
        name='test_fuzzer',
        builtin=False,
        data_bundle_name='test_bundle',
        launcher_script=None,
        filename='fuzzer.zip',
        executable_path='fuzzer_exe',
        blobstore_key='some_key')
    self.mock_get.return_value = self.fuzzer

  def test_setup_fuzzer_builtin_success(self):
    """Test successful setup of a builtin fuzzer."""
    self.fuzzer.builtin = True
    self.assertTrue(setup.setup_local_fuzzer('builtin_fuzzer'))
    self.mock.set_value.assert_called_once()
    self.mock.remove_directory.assert_not_called()
    self.mock_logs['info'].assert_any_call(
        'Fuzzer builtin_fuzzer is builtin, no setup required.')

  def test_setup_fuzzer_external_success(self):
    """Test successful setup of an external fuzzer."""
    self.mock.exists.side_effect = [True, True]  # archive, executable
    self.assertTrue(setup.setup_local_fuzzer('external_fuzzer'))
    self.mock.remove_directory.assert_called_once_with(
        '/tmp/fuzzer_dir', recreate=True)
    self.mock.read_blob_to_disk.assert_called_once_with(
        'some_key', '/tmp/fuzzer_dir/fuzzer.zip')
    self.mock.open.assert_called_once_with('/tmp/fuzzer_dir/fuzzer.zip')
    self.mock_archive_reader.extract_all.assert_called_once_with(
        '/tmp/fuzzer_dir')
    self.mock.remove_file.assert_called_once_with('/tmp/fuzzer_dir/fuzzer.zip')
    self.mock.chmod.assert_called_once_with('/tmp/fuzzer_dir/fuzzer_exe',
                                            setup._EXECUTABLE_PERMISSIONS)

  def test_fuzzer_not_found(self):
    """Test when the fuzzer is not found in the database."""
    self.mock_get.return_value = None
    self.assertFalse(setup.setup_local_fuzzer('nonexistent_fuzzer'))
    self.mock_logs['error'].assert_called_with(
        'Fuzzer nonexistent_fuzzer not found.')

  def test_launcher_script_unsupported(self):
    """Test that fuzzers with launcher scripts are not supported."""
    self.fuzzer.launcher_script = 'launcher.sh'
    self.assertFalse(setup.setup_local_fuzzer('launcher_fuzzer'))
    self.mock_logs['error'].assert_called_with(
        'Fuzzers with launch script not supported yet.')

  def test_remove_directory_fails(self):
    """Test failure when clearing the fuzzer directory."""
    self.mock.remove_directory.return_value = False
    self.assertFalse(setup.setup_local_fuzzer('external_fuzzer'))
    self.mock_logs['error'].assert_called_with(
        'Failed to clear fuzzer directory: /tmp/fuzzer_dir')

  def test_remove_directory_exception(self):
    """Test exception when clearing the fuzzer directory."""
    self.mock.remove_directory.side_effect = Exception('mock remove error')
    self.assertFalse(setup.setup_local_fuzzer('external_fuzzer'))
    self.mock_logs['error'].assert_called_with(
        'Error clearing fuzzer directory /tmp/fuzzer_dir: mock remove error')

  def test_download_archive_fails(self):
    """Test failure when downloading the fuzzer archive."""
    self.mock.read_blob_to_disk.return_value = False
    self.assertFalse(setup.setup_local_fuzzer('external_fuzzer'))
    self.mock_logs['error'].assert_called_with(
        'Failed to download fuzzer archive from blobstore: some_key')

  def test_unpack_archive_fails_archiveerror(self):
    """Test failure when unpacking the fuzzer archive with ArchiveError."""
    self.mock.open.side_effect = archive.ArchiveError('mock unpack error')
    self.assertFalse(setup.setup_local_fuzzer('external_fuzzer'))
    self.mock_logs['error'].assert_called_with(
        'Failed to unpack fuzzer archive fuzzer.zip: mock unpack error')

  def test_unpack_archive_fails_exception(self):
    """Test failure when unpacking with a generic exception."""
    self.mock.open.side_effect = Exception('mock generic error')
    self.assertFalse(setup.setup_local_fuzzer('external_fuzzer'))
    self.mock_logs['error'].assert_called_with(
        'Unexpected error unpacking fuzzer archive fuzzer.zip: mock generic error'
    )

  def test_executable_not_found(self):
    """Test when the executable is not found after unpacking."""
    self.mock.exists.side_effect = [True, False]  # archive, executable
    self.assertFalse(setup.setup_local_fuzzer('external_fuzzer'))
    self.mock_logs['error'].assert_called_with(
        'Fuzzer executable fuzzer_exe not found in archive. Check fuzzer configuration.'
    )

  def test_chmod_fails(self):
    """Test failure when setting permissions on the executable."""
    self.mock.exists.side_effect = [True, True]
    self.mock.chmod.side_effect = OSError('mock chmod error')
    self.assertFalse(setup.setup_local_fuzzer('external_fuzzer'))
    self.mock_logs['error'].assert_called_with(
        'Failed to set permissions on fuzzer executable /tmp/fuzzer_dir/fuzzer_exe: mock chmod error'
    )


class SetupLocalTestcaseTest(unittest.TestCase):
  """Tests for the setup_local_testcase function."""

  def setUp(self):
    super().setUp()
    self.addCleanup(unittest.mock.patch.stopall)
    self.mock_logs = unittest.mock.patch.multiple(
        'local.butler.reproduce.logs',
        error=unittest.mock.DEFAULT,
        info=unittest.mock.DEFAULT,
        warning=unittest.mock.DEFAULT).start()

    helpers.patch(self, [
        'clusterfuzz._internal.system.shell.clear_testcase_directories',
        'clusterfuzz._internal.bot.tasks.setup._get_testcase_file_and_path',
        'clusterfuzz._internal.google_cloud_utils.blobs.read_blob_to_disk',
        'clusterfuzz._internal.bot.tasks.setup.prepare_environment_for_testcase'
    ])

    self.testcase = data_types.Testcase(
        fuzzed_keys='testcase_key', minimized_keys=None)

  def test_success_fuzzed_keys(self):
    """Test successful local setup of a testcase."""
    self.mock._get_testcase_file_and_path.return_value = (unittest.mock.ANY,
                                                          '/tmp/testcase')
    self.mock.read_blob_to_disk.return_value = True

    path = setup.setup_local_testcase(self.testcase)
    self.assertEqual(path, '/tmp/testcase')
    self.mock.clear_testcase_directories.assert_called_once()
    self.mock.read_blob_to_disk.assert_called_once_with('testcase_key',
                                                        '/tmp/testcase')
    self.mock.prepare_environment_for_testcase.assert_called_once_with(
        self.testcase)

  def test_success_minimized_keys(self):
    """Test successful local setup of a testcase with minimized keys."""
    self.testcase.minimized_keys = 'minimized_key'
    self.mock._get_testcase_file_and_path.return_value = (unittest.mock.ANY,
                                                          '/tmp/testcase')
    self.mock.read_blob_to_disk.return_value = True

    path = setup.setup_local_testcase(self.testcase)
    self.assertEqual(path, '/tmp/testcase')
    self.mock.clear_testcase_directories.assert_called_once()
    self.mock.read_blob_to_disk.assert_called_once_with('minimized_key',
                                                        '/tmp/testcase')
    self.mock.prepare_environment_for_testcase.assert_called_once_with(
        self.testcase)

  def test_clear_directories_fails(self):
    """Test handling an exception from clear_testcase_directories."""
    self.mock.clear_testcase_directories.side_effect = Exception(
        'mock clear error')
    path = setup.setup_local_testcase(self.testcase)
    self.assertIsNone(path)
    self.mock_logs['error'].assert_called_with(
        'Error clearing testcase directories: mock clear error')

  def test_download_fails_fuzzed_keys(self):
    """Test handling a download failure from read_blob_to_disk."""
    self.mock._get_testcase_file_and_path.return_value = (unittest.mock.ANY,
                                                          '/tmp/testcase')
    self.mock.read_blob_to_disk.return_value = False
    path = setup.setup_local_testcase(self.testcase)
    self.assertIsNone(path)
    self.mock_logs['error'].assert_called_with(
        'Failed to download testcase from blobstore: testcase_key')

  def test_download_fails_minimized_keys(self):
    """Test handling a download failure from read_blob_to_disk with minimized keys."""
    self.testcase.minimized_keys = 'minimized_key'
    self.mock._get_testcase_file_and_path.return_value = (unittest.mock.ANY,
                                                          '/tmp/testcase')
    self.mock.read_blob_to_disk.return_value = False
    path = setup.setup_local_testcase(self.testcase)
    self.assertIsNone(path)
    self.mock_logs['error'].assert_called_with(
        'Failed to download testcase from blobstore: minimized_key')

  def test_prepare_env_fails(self):
    """Test handling an exception from prepare_environment_for_testcase."""
    self.mock._get_testcase_file_and_path.return_value = (unittest.mock.ANY,
                                                          '/tmp/testcase')
    self.mock.read_blob_to_disk.return_value = True
    self.mock.prepare_environment_for_testcase.side_effect = Exception(
        'mock prepare error')
    path = setup.setup_local_testcase(self.testcase)
    self.assertIsNone(path)
    self.mock_logs['error'].assert_called_with(
        'Error setting up testcase locally: mock prepare error')

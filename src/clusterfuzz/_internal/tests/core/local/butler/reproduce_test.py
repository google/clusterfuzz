# Copyright 2025 Google LLC
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

import argparse
import os
import tempfile
import unittest
from unittest import mock

from local.butler import reproduce

from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore.data_types import Fuzzer, Job, Testcase
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.bot.tasks.commands import update_environment_for_job

class SetupFuzzerTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        helpers.patch_environ(self)
        self.mock_logs = mock.patch.multiple(
            'local.butler.reproduce.logs',
            error=mock.DEFAULT,
            info=mock.DEFAULT,
            warning=mock.DEFAULT).start()

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

        self.mock_fuzzer_query = self.mock.query
        self.mock_get = self.mock_fuzzer_query.return_value.get
        self.mock.get_fuzzer_directory.return_value = '/tmp/fuzzer_dir'
        self.mock.remove_directory.return_value = True
        self.mock.read_blob_to_disk.return_value = True

        self.mock_archive_reader = mock.MagicMock()
        self.mock.open.return_value.__enter__.return_value = self.mock_archive_reader

        self.mock_fuzzer = mock.MagicMock(spec=Fuzzer)
        self.mock_fuzzer.name = 'test_fuzzer'
        self.mock_fuzzer.builtin = False
        self.mock_fuzzer.data_bundle_name = 'test_bundle'
        self.mock_fuzzer.launcher_script = None
        self.mock_fuzzer.filename = 'fuzzer.zip'
        self.mock_fuzzer.executable_path = 'fuzzer_exe'
        self.mock_fuzzer.blobstore_key = 'some_key'
        self.mock_get.return_value = self.mock_fuzzer

    def test_setup_fuzzer_builtin_success(self):
        """Test successful setup of a builtin fuzzer."""
        self.mock_fuzzer.builtin = True
        self.assertTrue(reproduce._setup_fuzzer('builtin_fuzzer'))
        self.mock.set_value.assert_called_once()
        self.mock.remove_directory.assert_not_called()
        self.mock_logs['info'].assert_any_call(
            'Fuzzer builtin_fuzzer is builtin, no setup required.')

    def test_setup_fuzzer_external_success(self):
        """Test successful setup of an external fuzzer."""
        self.mock.exists.side_effect = [True, True]  # archive, executable
        self.assertTrue(reproduce._setup_fuzzer('external_fuzzer'))
        self.mock.remove_directory.assert_called_once_with(
            '/tmp/fuzzer_dir', recreate=True)
        self.mock.read_blob_to_disk.assert_called_once_with(
            'some_key', '/tmp/fuzzer_dir/fuzzer.zip')
        self.mock.open.assert_called_once_with('/tmp/fuzzer_dir/fuzzer.zip')
        self.mock_archive_reader.extract_all.assert_called_once_with('/tmp/fuzzer_dir')
        self.mock.remove_file.assert_called_once_with('/tmp/fuzzer_dir/fuzzer.zip')
        self.mock.chmod.assert_called_once_with('/tmp/fuzzer_dir/fuzzer_exe',
                                                reproduce._EXECUTABLE_PERMISSIONS)

    def test_fuzzer_not_found(self):
        """Test when the fuzzer is not found in the database."""
        self.mock_get.return_value = None
        self.assertFalse(reproduce._setup_fuzzer('nonexistent_fuzzer'))
        self.mock_logs['error'].assert_called_with(
            'Fuzzer nonexistent_fuzzer not found.')

    def test_launcher_script_unsupported(self):
        """Test that fuzzers with launcher scripts are not supported."""
        self.mock_fuzzer.launcher_script = 'launcher.sh'
        self.assertFalse(reproduce._setup_fuzzer('launcher_fuzzer'))
        self.mock_logs['error'].assert_called_with(
            'Fuzzers with launch script not supported yet.')

    def test_remove_directory_fails(self):
        """Test failure when clearing the fuzzer directory."""
        self.mock.remove_directory.return_value = False
        self.assertFalse(reproduce._setup_fuzzer('external_fuzzer'))
        self.mock_logs['error'].assert_called_with(
            'Failed to clear fuzzer directory: /tmp/fuzzer_dir')

    def test_remove_directory_exception(self):
        """Test exception when clearing the fuzzer directory."""
        self.mock.remove_directory.side_effect = Exception('mock remove error')
        self.assertFalse(reproduce._setup_fuzzer('external_fuzzer'))
        self.mock_logs['error'].assert_called_with(
            'Error clearing fuzzer directory /tmp/fuzzer_dir: mock remove error'
        )

    def test_download_archive_fails(self):
        """Test failure when downloading the fuzzer archive."""
        self.mock.read_blob_to_disk.return_value = False
        self.assertFalse(reproduce._setup_fuzzer('external_fuzzer'))
        self.mock_logs['error'].assert_called_with(
            'Failed to download fuzzer archive from blobstore: some_key')

    def test_unpack_archive_fails_archiveerror(self):
        """Test failure when unpacking the fuzzer archive with ArchiveError."""
        self.mock.open.side_effect = archive.ArchiveError('mock unpack error')
        self.assertFalse(reproduce._setup_fuzzer('external_fuzzer'))
        self.mock_logs['error'].assert_called_with(
            'Failed to unpack fuzzer archive fuzzer.zip: mock unpack error')

    def test_unpack_archive_fails_exception(self):
        """Test failure when unpacking with a generic exception."""
        self.mock.open.side_effect = Exception('mock generic error')
        self.assertFalse(reproduce._setup_fuzzer('external_fuzzer'))
        self.mock_logs['error'].assert_called_with(
            'Unexpected error unpacking fuzzer archive fuzzer.zip: mock generic error'
        )

    def test_executable_not_found(self):
        """Test when the executable is not found after unpacking."""
        self.mock.exists.side_effect = [True, False]  # archive, executable
        self.assertFalse(reproduce._setup_fuzzer('external_fuzzer'))
        self.mock_logs['error'].assert_called_with(
            'Fuzzer executable fuzzer_exe not found in archive. Check fuzzer configuration.'
        )

    def test_chmod_fails(self):
        """Test failure when setting permissions on the executable."""
        self.mock.exists.side_effect = [True, True]
        self.mock.chmod.side_effect = OSError('mock chmod error')
        self.assertFalse(reproduce._setup_fuzzer('external_fuzzer'))
        self.mock_logs['error'].assert_called_with(
            'Failed to set permissions on fuzzer executable /tmp/fuzzer_dir/fuzzer_exe: mock chmod error'
        )

class SetupTestcaseLocallyTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.mock_logs = mock.patch.multiple(logs, error=mock.DEFAULT, info=mock.DEFAULT, warning=mock.DEFAULT).start()
        self.addCleanup(mock.patch.stopall)

        helpers.patch(self, [
            'clusterfuzz._internal.system.shell.clear_testcase_directories',
            'clusterfuzz._internal.bot.tasks.setup._get_testcase_file_and_path',
            'clusterfuzz._internal.google_cloud_utils.blobs.read_blob_to_disk',
            'clusterfuzz._internal.bot.tasks.setup.prepare_environment_for_testcase'
        ])

        self.mock_testcase = mock.MagicMock(spec=Testcase)
        self.mock_testcase.fuzzed_keys = 'testcase_key'

    def test_success(self):
        self.mock._get_testcase_file_and_path.return_value = (mock.ANY, '/tmp/testcase')
        self.mock.read_blob_to_disk.return_value = True

        ok, path = reproduce._setup_testcase_locally(self.mock_testcase)
        self.assertTrue(ok)
        self.assertEqual(path, '/tmp/testcase')
        self.mock.clear_testcase_directories.assert_called_once()
        self.mock.read_blob_to_disk.assert_called_once_with('testcase_key', '/tmp/testcase')
        self.mock.prepare_environment_for_testcase.assert_called_once_with(self.mock_testcase)


    def test_clear_directories_fails(self):
        """Test that it handles an exception from clear_testcase_directories."""
        self.mock.clear_testcase_directories.side_effect = Exception(
            'mock clear error')
        ok, path = reproduce._setup_testcase_locally(self.mock_testcase)
        self.assertFalse(ok)
        self.assertIsNone(path)

        self.mock_logs['error'].assert_called_with(
            'Error clearing testcase directories: mock clear error')

    def test_download_fails(self):
        """Test that it handles a download failure from read_blob_to_disk."""
        self.mock._get_testcase_file_and_path.return_value = (mock.ANY, '/tmp/testcase')
        self.mock.read_blob_to_disk.return_value = False
        ok, path = reproduce._setup_testcase_locally(self.mock_testcase)
        self.assertFalse(ok)
        self.assertIsNone(path)
        self.mock_logs['error'].assert_called_with(
            'Failed to download testcase from blobstore: testcase_key')

    def test_prepare_env_fails(self):
        """Test that it handles an exception from prepare_environment_for_testcase."""
        self.mock._get_testcase_file_and_path.return_value = (mock.ANY, '/tmp/testcase')
        self.mock.read_blob_to_disk.return_value = True
        self.mock.prepare_environment_for_testcase.side_effect = Exception('mock prepare error')
        ok, path = reproduce._setup_testcase_locally(self.mock_testcase)
        self.assertFalse(ok)
        self.assertIsNone(path)
        self.mock_logs['error'].assert_called_with(
            'Error setting up testcase locally: mock prepare error')

class ReproduceTestcaseTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.mock_logs = mock.patch.multiple(
            'local.butler.reproduce.logs',
            error=mock.DEFAULT,
            info=mock.DEFAULT,
            warning=mock.DEFAULT).start()
        self.addCleanup(mock.patch.stopall)

        helpers.patch(self, [
            'clusterfuzz._internal.datastore.data_handler.get_testcase_by_id',
            'clusterfuzz._internal.datastore.data_types.Job.query',
            'clusterfuzz._internal.system.environment.set_value',
            'clusterfuzz._internal.system.environment.get_value',
            'clusterfuzz._internal.bot.tasks.commands.update_environment_for_job',
            'local.butler.reproduce._setup_fuzzer',
            'local.butler.reproduce._setup_testcase_locally',
            'clusterfuzz._internal.build_management.build_manager.setup_build',
            'clusterfuzz._internal.bot.testcase_manager.check_for_bad_build',
            'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
            'clusterfuzz._internal.bot.testcase_manager.test_for_reproducibility',
        ])

        self.mock_testcase = mock.MagicMock(spec=Testcase)
        self.mock_job = mock.MagicMock(spec=Job)
        self.mock.get_testcase_by_id.return_value = self.mock_testcase
        self.mock.query.return_value.get.return_value = self.mock_job

        self.mock._setup_fuzzer.return_value = True
        self.mock._setup_testcase_locally.return_value = (True, '/tmp/testcase')

        mock_build_result = mock.MagicMock(spec=uworker_msg_pb2.BuildData)
        mock_build_result.is_bad_build = False
        self.mock.check_for_bad_build.return_value = mock_build_result

        mock_crash_result = mock.MagicMock()
        mock_crash_result.is_crash.return_value = True
        self.mock.test_for_crash_with_retries.return_value = mock_crash_result

        self.mock.test_for_reproducibility.return_value = True

        self.mock.get_value.return_value = str(reproduce._DEFAULT_TEST_TIMEOUT)
        self.args = argparse.Namespace(testcase_id=123, config_dir='/foo')

    def test_success_crash_reproduces(self):
        """Test the full success path where the crash reproduces."""
        reproduce._reproduce_testcase(self.args)

        self.mock.get_testcase_by_id.assert_called_once_with(123)
        self.mock._setup_fuzzer.assert_called_once()
        self.mock._setup_testcase_locally.assert_called_once()
        self.mock.setup_build.assert_called_once()
        self.mock.check_for_bad_build.assert_called_once()
        self.mock.test_for_crash_with_retries.assert_called_once()
        self.mock.test_for_reproducibility.assert_called_once()
        self.mock_logs['info'].assert_any_call('The testcase reliably reproduces.')

    def test_success_crash_not_reproduces(self):
        """Test the success path where the crash does not reproduce."""
        self.mock.test_for_reproducibility.return_value = False
        reproduce._reproduce_testcase(self.args)
        self.mock.test_for_reproducibility.assert_called_once()
        self.mock_logs['info'].assert_any_call(
            'The testcase does not reliably reproduce.')

    def test_testcase_not_found(self):
        """Test that it exits when the testcase is not found."""
        self.mock.get_testcase_by_id.return_value = None
        reproduce._reproduce_testcase(self.args)
        self.mock_logs['error'].assert_called_with(
            'Testcase with ID 123 not found.')
        self.mock._setup_fuzzer.assert_not_called()

    def test_job_not_found(self):
        """Test that it exits when the job is not found."""
        self.mock.query.return_value.get.return_value = None
        reproduce._reproduce_testcase(self.args)
        self.mock_logs['error'].assert_called_with(
            f'Job type {self.mock_testcase.job_type} not found for testcase.')
        self.mock._setup_fuzzer.assert_not_called()

    def test_setup_fuzzer_fails(self):
        """Test that it exits when fuzzer setup fails."""
        self.mock._setup_fuzzer.return_value = False
        reproduce._reproduce_testcase(self.args)
        self.mock_logs['error'].assert_called_with(
            f'Failed to setup fuzzer {self.mock_testcase.fuzzer_name}. Exiting.')
        self.mock._setup_testcase_locally.assert_not_called()

    def test_setup_testcase_fails(self):
        """Test that it exits when testcase setup fails."""
        self.mock._setup_testcase_locally.return_value = (False, None)
        reproduce._reproduce_testcase(self.args)
        self.mock_logs['error'].assert_called_with(
            'Could not setup testcase locally. Exiting.')
        self.mock.setup_build.assert_not_called()

    def test_setup_build_fails(self):
        """Test that it exits when build setup fails."""
        self.mock.setup_build.side_effect = Exception('mock build error')
        reproduce._reproduce_testcase(self.args)
        self.mock_logs['error'].assert_called_with(
            f'Error setting up build for revision '
            f'{self.mock_testcase.crash_revision}: mock build error')
        self.mock.check_for_bad_build.assert_not_called()

    def test_bad_build(self):
        """Test that it exits when a bad build is detected."""
        self.mock.check_for_bad_build.return_value.is_bad_build = True
        reproduce._reproduce_testcase(self.args)
        self.mock_logs['error'].assert_called_with('Bad build detected. Exiting.')
        self.mock.test_for_crash_with_retries.assert_not_called()

    def test_no_crash(self):
        """Test that it exits when the initial crash does not occur."""
        self.mock.test_for_crash_with_retries.return_value.is_crash.return_value = False
        reproduce._reproduce_testcase(self.args)
        self.mock_logs['info'].assert_called_with('No crash occurred. Exiting.')
        self.mock.test_for_reproducibility.assert_not_called()

if __name__ == '__main__':
    unittest.main()

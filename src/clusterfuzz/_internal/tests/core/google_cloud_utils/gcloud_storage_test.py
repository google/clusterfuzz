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
"""Tests for gcloud storage."""

import os

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.google_cloud_utils import gcloud_storage
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class GCloudStorageRunnerTest(fake_filesystem_unittest.TestCase):
  """GCloudStorageRunner tests."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(
        self,
        ['clusterfuzz._internal.system.new_process.ProcessRunner.run_and_wait'])
    test_utils.set_up_pyfakefs(self)
    self.gcloud_runner_obj = gcloud_storage.GCloudStorageRunner()

  def _default_args(self, verbose=True, quiet=True):
    additional_args = ['--user-output-enabled'] if verbose else [
        '--no-user-output-enabled'
    ]
    additional_args += ['-q'] if quiet else []
    return additional_args

  def test_rsync(self):
    """Test remote rsync."""
    self.gcloud_runner_obj.rsync('gs://source_bucket/source_path',
                                 'gs://target_bucket/target_path')
    expected_args = [
        'rsync', 'gs://source_bucket/source_path',
        'gs://target_bucket/target_path', '--recursive',
        '--delete-unmatched-destination-objects'
    ]
    expected_args = self._default_args(verbose=False) + expected_args
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=18000)

  def test_rsync_local_gcs(self):
    """Test rsync locally."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/source_bucket')
    self.fs.create_dir('/local/target_bucket')
    self.gcloud_runner_obj.rsync('gs://source_bucket/source_path',
                                 'gs://target_bucket/target_path')

    expected_args = [
        'rsync', '/local/source_bucket/objects/source_path',
        '/local/target_bucket/objects/target_path', '--recursive',
        '--delete-unmatched-destination-objects'
    ]
    expected_args = self._default_args(verbose=False) + expected_args
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=18000)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_rsync_with_timeout(self):
    """Test remote rsync with timeout."""
    self.gcloud_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337)
    expected_args = [
        'rsync', 'gs://source_bucket/source_path',
        'gs://target_bucket/target_path', '--recursive',
        '--delete-unmatched-destination-objects'
    ]
    expected_args = self._default_args(verbose=False) + expected_args
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=1337)

  def test_rsync_local_gcs_with_timeout(self):
    """Test rsync locally with timeout."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/source_bucket')
    self.fs.create_dir('/local/target_bucket')
    self.gcloud_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337)

    expected_args = [
        'rsync', '/local/source_bucket/objects/source_path',
        '/local/target_bucket/objects/target_path', '--recursive',
        '--delete-unmatched-destination-objects'
    ]
    expected_args = self._default_args(verbose=False) + expected_args
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=1337)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_rsync_no_delete(self):
    """Test remote rsync without delete."""
    self.gcloud_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        delete=False)
    expected_args = [
        'rsync', 'gs://source_bucket/source_path',
        'gs://target_bucket/target_path', '--recursive'
    ]
    expected_args = self._default_args(verbose=False) + expected_args
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=18000)

  def test_rsync_local_gcs_without_delete(self):
    """Test rsync locally without delete."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/source_bucket')
    self.fs.create_dir('/local/target_bucket')
    self.gcloud_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        delete=False)

    expected_args = [
        'rsync', '/local/source_bucket/objects/source_path',
        '/local/target_bucket/objects/target_path', '--recursive'
    ]
    expected_args = self._default_args(verbose=False) + expected_args
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=18000)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_rsync_with_exclusion(self):
    """Test remote rsync with exclusion pattern."""
    self.gcloud_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        exclusion_pattern='"*.txt$"')
    expected_args = [
        'rsync', 'gs://source_bucket/source_path',
        'gs://target_bucket/target_path', '--recursive',
        '--delete-unmatched-destination-objects', '--exclude', '"*.txt$"'
    ]
    expected_args = self._default_args(verbose=False) + expected_args
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=18000)

  def test_download_file(self):
    """Test remote download_file."""
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        self.gcloud_runner_obj.download_file('gs://source_bucket/source_path',
                                             '/target_path'))
    expected_args = self._default_args() + [
        'cp', 'gs://source_bucket/source_path', '/target_path'
    ]
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=None)

  def test_download_file_local_gcs(self):
    """Test download_file locally."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        self.gcloud_runner_obj.download_file('gs://source_bucket/source_path',
                                             '/target_path'))
    expected_args = self._default_args() + [
        'cp', '/local/source_bucket/objects/source_path', '/target_path'
    ]
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=None)

  def test_upload_file(self):
    """Test remote upload_file."""
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        self.gcloud_runner_obj.upload_file('/source_path',
                                           'gs://target_bucket/target_path'))
    expected_args = self._default_args() + [
        'cp', '/source_path', 'gs://target_bucket/target_path'
    ]
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=None)

  def test_upload_file_local_gcs(self):
    """Test upload_file locally."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/target_bucket')

    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        self.gcloud_runner_obj.upload_file('/source_path',
                                           'gs://target_bucket/target_path'))
    expected_args = self._default_args() + [
        'cp', '/source_path', '/local/target_bucket/objects/target_path'
    ]
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=None)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_upload_file_with_metadata(self):
    """Test remote upload_file with metadata, gzip and timeout."""
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)

    header_metadata = {'content-type': '"new-type"'}
    custom_metadata = {'key1': 'value1', 'key2': 'value2'}
    self.assertTrue(
        self.gcloud_runner_obj.upload_file(
            '/source_path',
            'gs://target_bucket/target_path',
            metadata=header_metadata,
            custom_metadata=custom_metadata,
            gzip=True,
            timeout=1337))
    self.assertEqual(2, self.mock.run_and_wait.call_count)

    # gcloud storage cp call
    expected_args = self._default_args() + [
        'cp', '--gzip-local-all', '/source_path',
        'gs://target_bucket/target_path'
    ]
    self.mock.run_and_wait.assert_any_call(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=1337)

    # gcloud storage objects update call (metadata)
    expected_args = self._default_args() + [
        'objects', 'update', 'gs://target_bucket/target_path',
        '--content-type="new-type"',
        '--update-custom-metadata=key1=value1,key2=value2'
    ]
    self.mock.run_and_wait.assert_any_call(
        self.gcloud_runner_obj.gcloud_runner, expected_args, timeout=1337)

  def test_upload_files_to_url(self):
    """Test remote upload_files_to_url."""
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        self.gcloud_runner_obj.upload_files_to_url(
            ['/source_path1', '/source_path2'],
            'gs://target_bucket/target_path'))
    expected_args = self._default_args() + [
        'cp', '--read-paths-from-stdin', 'gs://target_bucket/target_path'
    ]
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner,
        expected_args,
        input_data=b'/source_path1\n/source_path2',
        timeout=None)

  def test_upload_files_to_url_local_gcs(self):
    """Test upload_files_to_url locally."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/target_bucket')
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        self.gcloud_runner_obj.upload_files_to_url(
            ['/source_path1', '/source_path2'],
            'gs://target_bucket/target_path',
            timeout=1337))
    expected_args = self._default_args() + [
        'cp', '--read-paths-from-stdin',
        '/local/target_bucket/objects/target_path'
    ]
    self.mock.run_and_wait.assert_called_with(
        self.gcloud_runner_obj.gcloud_runner,
        expected_args,
        input_data=b'/source_path1\n/source_path2',
        timeout=1337)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_upload_files_to_url_empty(self):
    """Test upload_files_to_url with empty file list."""
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertFalse(
        self.gcloud_runner_obj.upload_files_to_url(
            [], 'gs://target_bucket/target_path'))
    self.assertEqual(0, self.mock.run_and_wait.call_count)

  def test_rsync_failure(self):
    """Test rsync failure."""
    mock_result = new_process.ProcessResult(return_code=1, output='Fake error')
    self.mock.run_and_wait.return_value = mock_result
    result = self.gcloud_runner_obj.rsync('gs://source_bucket/source_path',
                                          'gs://target_bucket/target_path')
    self.assertEqual(mock_result, result)

  def test_download_file_failure(self):
    """Test download_file failure."""
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=1, output='Fake error')
    self.assertFalse(
        self.gcloud_runner_obj.download_file('gs://source_bucket/source_path',
                                             '/target_path'))

  def test_upload_file_failure(self):
    """Test upload_file failure."""
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=1, output='Fake error')
    self.assertFalse(
        self.gcloud_runner_obj.upload_file('/source_path',
                                           'gs://target_bucket/target_path'))

  def test_upload_files_to_url_failure(self):
    """Test upload_files_to_url failure."""
    self.mock.run_and_wait.return_value = new_process.ProcessResult(
        return_code=1, output='Fake error')
    self.assertFalse(
        self.gcloud_runner_obj.upload_files_to_url(
            ['/source_path1', '/source_path2'],
            'gs://target_bucket/target_path'))

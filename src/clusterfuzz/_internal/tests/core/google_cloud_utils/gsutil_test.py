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
"""Tests for gsutil."""

import os
from unittest import mock

from parameterized import parameterized
from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.google_cloud_utils import gsutil
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class GSUtilRunnerTest(fake_filesystem_unittest.TestCase):
  """GSUtilRunner tests."""

  def setUp(self):
    test_helpers.patch_environ(self)
    patcher = mock.patch(
        'clusterfuzz._internal.system.new_process.ProcessRunner.run_and_wait')
    self.mock_run_and_wait = patcher.start()
    self.addCleanup(patcher.stop)

    test_utils.set_up_pyfakefs(self)

  @parameterized.expand([(True,), (False,)])
  def test_rsync(self, use_gcloud_storage):
    """Test rsync."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    gsutil_runner_obj.rsync('gs://source_bucket/source_path',
                            'gs://target_bucket/target_path')
    if use_gcloud_storage:
      expected_args = [
          'rsync', '--delete-unmatched-destination-objects',
          'gs://source_bucket/source_path', 'gs://target_bucket/target_path'
      ]
    else:
      expected_args = [
          '-q', 'rsync', '-r', '-d', 'gs://source_bucket/source_path',
          'gs://target_bucket/target_path'
      ]
    self.mock_run_and_wait.assert_called_with(
        expected_args, timeout=18000, env=mock.ANY)

  @parameterized.expand([(True,), (False,)])
  def test_rsync_local_gcs(self, use_gcloud_storage):
    """Test rsync."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/source_bucket')
    self.fs.create_dir('/local/target_bucket')
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    gsutil_runner_obj.rsync('gs://source_bucket/source_path',
                            'gs://target_bucket/target_path')
    if use_gcloud_storage:
      expected_args = [
          'rsync', '--delete-unmatched-destination-objects',
          '/local/source_bucket/objects/source_path',
          '/local/target_bucket/objects/target_path'
      ]
    else:
      expected_args = [
          '-q', 'rsync', '-r', '-d',
          '/local/source_bucket/objects/source_path',
          '/local/target_bucket/objects/target_path'
      ]
    self.mock_run_and_wait.assert_called_with(
        expected_args, timeout=18000, env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  @parameterized.expand([(True,), (False,)])
  def test_rsync_with_timeout(self, use_gcloud_storage):
    """Test rsync."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337)
    if use_gcloud_storage:
      expected_args = [
          'rsync', '--delete-unmatched-destination-objects',
          'gs://source_bucket/source_path', 'gs://target_bucket/target_path'
      ]
    else:
      expected_args = [
          '-q', 'rsync', '-r', '-d', 'gs://source_bucket/source_path',
          'gs://target_bucket/target_path'
      ]
    self.mock_run_and_wait.assert_called_with(
        expected_args, timeout=1337, env=mock.ANY)

  @parameterized.expand([(True,), (False,)])
  def test_rsync_no_delete(self, use_gcloud_storage):
    """Test rsync."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        delete=False)
    if use_gcloud_storage:
      expected_args = [
          'rsync', 'gs://source_bucket/source_path',
          'gs://target_bucket/target_path'
      ]
    else:
      expected_args = [
          '-q', 'rsync', '-r', 'gs://source_bucket/source_path',
          'gs://target_bucket/target_path'
      ]
    self.mock_run_and_wait.assert_called_with(
        expected_args, timeout=18000, env=mock.ANY)

  @parameterized.expand([(True,), (False,)])
  def test_rsync_with_exclusion(self, use_gcloud_storage):
    """Test rsync."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337,
        delete=False,
        exclusion_pattern='"*.txt$"')
    if use_gcloud_storage:
      expected_args = [
          'rsync', '--exclude', '"*.txt$"', 'gs://source_bucket/source_path',
          'gs://target_bucket/target_path'
      ]
    else:
      expected_args = [
          '-q', 'rsync', '-r', '-x', '"*.txt$"',
          'gs://source_bucket/source_path', 'gs://target_bucket/target_path'
      ]
    self.mock_run_and_wait.assert_called_with(
        expected_args, timeout=1337, env=mock.ANY)

  @parameterized.expand([(True,), (False,)])
  def test_download_file(self, use_gcloud_storage):
    """Test download_file."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        gsutil_runner_obj.download_file('gs://source_bucket/source_path',
                                        '/target_path'))
    self.mock_run_and_wait.assert_called_with(
        ['cp', 'gs://source_bucket/source_path', '/target_path'],
        timeout=None,
        env=mock.ANY)

  @parameterized.expand([(True,), (False,)])
  def test_download_file_local_gcs(self, use_gcloud_storage):
    """Test download_file."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        gsutil_runner_obj.download_file('gs://source_bucket/source_path',
                                        '/target_path'))
    self.mock_run_and_wait.assert_called_with(
        ['cp', '/local/source_bucket/objects/source_path', '/target_path'],
        timeout=None,
        env=mock.ANY)

  @parameterized.expand([(True,), (False,)])
  def test_upload_file(self, use_gcloud_storage):
    """Test upload_file."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        gsutil_runner_obj.upload_file('/source_path',
                                      'gs://target_bucket/target_path'))
    self.mock_run_and_wait.assert_called_with(
        ['cp', '/source_path', 'gs://target_bucket/target_path'],
        timeout=None,
        env=mock.ANY)

  @parameterized.expand([(True,), (False,)])
  def test_upload_file_local_gcs(self, use_gcloud_storage):
    """Test upload_file."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/target_bucket')
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        gsutil_runner_obj.upload_file('/source_path',
                                      'gs://target_bucket/target_path'))
    self.mock_run_and_wait.assert_called_with(
        ['cp', '/source_path', '/local/target_bucket/objects/target_path'],
        timeout=None,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  @parameterized.expand([(True,), (False,)])
  def test_upload_file_with_metadata(self, use_gcloud_storage):
    """Test upload_file with metadata."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()

    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)

    metadata = {'key1': 'value1', 'key2': 'value2'}
    self.assertTrue(
        gsutil_runner_obj.upload_file(
            '/source_path',
            'gs://target_bucket/target_path',
            metadata=metadata))

    if use_gcloud_storage:
      self.assertEqual(2, self.mock_run_and_wait.call_count)
      cp_call_args = self.mock_run_and_wait.call_args_list[0].args[0]
      self.assertEqual(
          ['cp', '/source_path', 'gs://target_bucket/target_path'],
          cp_call_args)

      update_call_args = self.mock_run_and_wait.call_args_list[1].args[0]
      self.assertEqual('objects', update_call_args[0])
      self.assertEqual('update', update_call_args[1])
      self.assertEqual('gs://target_bucket/target_path', update_call_args[2])
      self.assertEqual('--update-custom-metadata', update_call_args[3])
      self.assertIn('key1=value1', update_call_args[4])
      self.assertIn('key2=value2', update_call_args[4])
      self.assertIn(',', update_call_args[4])
    else:
      self.assertEqual(1, self.mock_run_and_wait.call_count)
      called_args = self.mock_run_and_wait.call_args.args[0]
      # Can't guarantee order of -h flags, so check for presence.
      self.assertIn('-h', called_args)
      self.assertIn('key1:value1', called_args)
      self.assertIn('key2:value2', called_args)
      self.assertIn('cp', called_args)
      self.assertEqual('/source_path', called_args[-2])
      self.assertEqual('gs://target_bucket/target_path', called_args[-1])

  @parameterized.expand([(True,), (False,)])
  def test_rsync_failure(self, use_gcloud_storage):
    """Test rsync failure."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    mock_result = new_process.ProcessResult(return_code=1, output='Fake error')
    self.mock_run_and_wait.return_value = mock_result
    result = gsutil_runner_obj.rsync('gs://source_bucket/source_path',
                                     'gs://target_bucket/target_path')
    self.assertEqual(mock_result, result)

  @parameterized.expand([(True,), (False,)])
  def test_download_file_failure(self, use_gcloud_storage):
    """Test download_file failure."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=1, output='Fake error')
    self.assertFalse(
        gsutil_runner_obj.download_file('gs://source_bucket/source_path',
                                        '/target_path'))

  @parameterized.expand([(True,), (False,)])
  def test_upload_file_failure(self, use_gcloud_storage):
    """Test upload_file failure."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=1, output='Fake error')
    self.assertFalse(
        gsutil_runner_obj.upload_file('/source_path',
                                      'gs://target_bucket/target_path'))

  @parameterized.expand([(True,), (False,)])
  def test_upload_files_to_url_failure(self, use_gcloud_storage):
    """Test upload_files_to_url failure."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=1, output='Fake error')
    self.assertFalse(
        gsutil_runner_obj.upload_files_to_url(
            ['/source_path1', '/source_path2'],
            'gs://target_bucket/target_path'))

  @parameterized.expand([(True,), (False,)])
  def test_upload_files_to_url_empty(self, use_gcloud_storage):
    """Test upload_files_to_url with empty file list."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.assertFalse(
        gsutil_runner_obj.upload_files_to_url([],
                                              'gs://target_bucket/target_path'))
    self.assertEqual(0, self.mock_run_and_wait.call_count)

  @parameterized.expand([(True,), (False,)])
  def test_upload_file_with_options(self, use_gcloud_storage):
    """Test upload_file."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        gsutil_runner_obj.upload_file(
            '/source_path',
            'gs://target_bucket/target_path',
            timeout=1337,
            gzip=True,
            metadata={'a': 'b'}))

    if use_gcloud_storage:
      self.mock_run_and_wait.assert_any_call(
          ['cp', '--gzip-in-flight-all', '/source_path',
           'gs://target_bucket/target_path'],
          timeout=1337,
          env=mock.ANY)
    else:
      expected_args = [
          '-h', 'a:b', 'cp', '-Z', '/source_path',
          'gs://target_bucket/target_path'
      ]
      self.mock_run_and_wait.assert_called_with(
          expected_args, timeout=1337, env=mock.ANY)

  @parameterized.expand([(True,), (False,)])
  def test_upload_files_to_url(self, use_gcloud_storage):
    """Test upload_files_to_url."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        gsutil_runner_obj.upload_files_to_url(
            ['/source_path1', '/source_path2'],
            'gs://target_bucket/target_path'))
    if use_gcloud_storage:
      expected_args = [
          'cp', '--read-paths-from-stdin', 'gs://target_bucket/target_path'
      ]
    else:
      expected_args = ['cp', '-I', 'gs://target_bucket/target_path']
    self.mock_run_and_wait.assert_called_with(
        expected_args,
        input_data=b'/source_path1\n/source_path2',
        timeout=None,
        env=mock.ANY)

  @parameterized.expand([(True,), (False,)])
  def test_upload_files_to_url_local_gcs(self, use_gcloud_storage):
    """Test upload_files_to_url."""
    os.environ['USE_GCLOUD_STORAGE'] = '1' if use_gcloud_storage else '0'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/target_bucket')
    gsutil_runner_obj = gsutil.GSUtilRunner()
    self.mock_run_and_wait.return_value = new_process.ProcessResult(
        return_code=0)
    self.assertTrue(
        gsutil_runner_obj.upload_files_to_url(
            ['/source_path1', '/source_path2'],
            'gs://target_bucket/target_path'))
    if use_gcloud_storage:
      expected_args = [
          'cp', '--read-paths-from-stdin',
          '/local/target_bucket/objects/target_path'
      ]
    else:
      expected_args = [
          'cp', '-I', '/local/target_bucket/objects/target_path'
      ]
    self.mock_run_and_wait.assert_called_with(
        expected_args,
        input_data=b'/source_path1\n/source_path2',
        timeout=None,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

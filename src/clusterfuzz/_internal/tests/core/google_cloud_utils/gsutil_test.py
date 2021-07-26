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

import mock
from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.google_cloud_utils import gsutil
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class GSUtilRunnerTest(fake_filesystem_unittest.TestCase):
  """GSUtilRunner tests."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.new_process.ProcessRunner.run_and_wait',
    ])

    test_utils.set_up_pyfakefs(self)
    self.gsutil_runner_obj = gsutil.GSUtilRunner()

  def test_rsync_remote_gcs_1(self):
    """Test rsync."""
    self.gsutil_runner_obj.rsync('gs://source_bucket/source_path',
                                 'gs://target_bucket/target_path')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', '-d', 'gs://source_bucket/source_path',
            'gs://target_bucket/target_path'
        ],
        timeout=18000,
        env=mock.ANY)

  def test_rsync_local_gcs_1(self):
    """Test rsync."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/source_bucket')
    self.fs.create_dir('/local/target_bucket')
    self.gsutil_runner_obj.rsync('gs://source_bucket/source_path',
                                 'gs://target_bucket/target_path')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', '-d',
            '/local/source_bucket/objects/source_path',
            '/local/target_bucket/objects/target_path'
        ],
        timeout=18000,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_rsync_remote_gcs_2(self):
    """Test rsync."""
    self.gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', '-d', 'gs://source_bucket/source_path',
            'gs://target_bucket/target_path'
        ],
        timeout=1337,
        env=mock.ANY)

  def test_rsync_local_gcs_2(self):
    """Test rsync."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/source_bucket')
    self.fs.create_dir('/local/target_bucket')
    self.gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', '-d',
            '/local/source_bucket/objects/source_path',
            '/local/target_bucket/objects/target_path'
        ],
        timeout=1337,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_rsync_remote_gcs_3(self):
    """Test rsync."""
    self.gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        delete=False)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', 'gs://source_bucket/source_path',
            'gs://target_bucket/target_path'
        ],
        timeout=18000,
        env=mock.ANY)

  def test_rsync_local_gcs_3(self):
    """Test rsync."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/source_bucket')
    self.fs.create_dir('/local/target_bucket')
    self.gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        delete=False)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', '/local/source_bucket/objects/source_path',
            '/local/target_bucket/objects/target_path'
        ],
        timeout=18000,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_rsync_remote_gcs_4(self):
    """Test rsync."""
    self.gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337,
        delete=False)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', 'gs://source_bucket/source_path',
            'gs://target_bucket/target_path'
        ],
        timeout=1337,
        env=mock.ANY)

  def test_rsync_local_gcs_4(self):
    """Test rsync."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/source_bucket')
    self.fs.create_dir('/local/target_bucket')
    self.gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337,
        delete=False)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', '/local/source_bucket/objects/source_path',
            '/local/target_bucket/objects/target_path'
        ],
        timeout=1337,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_rsync_remote_gcs_5(self):
    """Test rsync."""
    self.gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337,
        delete=False,
        exclusion_pattern='"*.txt$"')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', '-x', '"*.txt$"',
            'gs://source_bucket/source_path', 'gs://target_bucket/target_path'
        ],
        timeout=1337,
        env=mock.ANY)

  def test_rsync_local_gcs_5(self):
    """Test rsync."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/source_bucket')
    self.fs.create_dir('/local/target_bucket')
    self.gsutil_runner_obj.rsync(
        'gs://source_bucket/source_path',
        'gs://target_bucket/target_path',
        timeout=1337,
        delete=False,
        exclusion_pattern='"*.txt$"')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-q', 'rsync', '-r', '-x', '"*.txt$"',
            '/local/source_bucket/objects/source_path',
            '/local/target_bucket/objects/target_path'
        ],
        timeout=1337,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_download_file_remote_gcs_1(self):
    """Test download_file."""
    self.gsutil_runner_obj.download_file('gs://source_bucket/source_path',
                                         '/target_path')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', 'gs://source_bucket/source_path', '/target_path'],
        timeout=None,
        env=mock.ANY)

  def test_download_file_local_gcs_1(self):
    """Test download_file."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.gsutil_runner_obj.download_file('gs://source_bucket/source_path',
                                         '/target_path')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', '/local/source_bucket/objects/source_path', '/target_path'],
        timeout=None,
        env=mock.ANY)

  def test_download_file_remote_gcs_2(self):
    """Test download_file."""
    self.gsutil_runner_obj.download_file(
        'gs://source_bucket/source_path', '/target_path', timeout=1337)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', 'gs://source_bucket/source_path', '/target_path'],
        timeout=1337,
        env=mock.ANY)

  def test_download_file_local_gcs_2(self):
    """Test download_file."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.gsutil_runner_obj.download_file(
        'gs://source_bucket/source_path', '/target_path', timeout=1337)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', '/local/source_bucket/objects/source_path', '/target_path'],
        timeout=1337,
        env=mock.ANY)

  def test_upload_file_remote_gcs_1(self):
    """Test upload_file."""
    self.gsutil_runner_obj.upload_file('/source_path',
                                       'gs://target_bucket/target_path')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', '/source_path', 'gs://target_bucket/target_path'],
        timeout=None,
        env=mock.ANY)

  def test_upload_file_local_gcs_1(self):
    """Test upload_file."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/target_bucket')
    self.gsutil_runner_obj.upload_file('/source_path',
                                       'gs://target_bucket/target_path')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', '/source_path', '/local/target_bucket/objects/target_path'],
        timeout=None,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_upload_file_remote_gcs_2(self):
    """Test upload_file."""
    self.gsutil_runner_obj.upload_file(
        '/source_path',
        'gs://target_bucket/target_path',
        timeout=1337,
        gzip=True,
        metadata={'a': 'b'})
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-h', 'a:b', 'cp', '-Z', '/source_path',
            'gs://target_bucket/target_path'
        ],
        timeout=1337,
        env=mock.ANY)

  def test_upload_file_local_gcs_2(self):
    """Test upload_file."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/target_bucket')
    self.gsutil_runner_obj.upload_file(
        '/source_path',
        'gs://target_bucket/target_path',
        timeout=1337,
        gzip=True,
        metadata={'a': 'b'})
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner, [
            '-h', 'a:b', 'cp', '-Z', '/source_path',
            '/local/target_bucket/objects/target_path'
        ],
        timeout=1337,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_upload_files_to_url_remote_gcs_1(self):
    """Test upload_files_to_url."""
    self.gsutil_runner_obj.upload_files_to_url(
        ['/source_path1', '/source_path2'], 'gs://target_bucket/target_path')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', '-I', 'gs://target_bucket/target_path'],
        input_data=b'/source_path1\n/source_path2',
        timeout=None,
        env=mock.ANY)

  def test_upload_files_local_gcs_1(self):
    """Test upload_files_to_url."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/target_bucket')
    self.gsutil_runner_obj.upload_files_to_url(
        ['/source_path1', '/source_path2'], 'gs://target_bucket/target_path')
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', '-I', '/local/target_bucket/objects/target_path'],
        input_data=b'/source_path1\n/source_path2',
        timeout=None,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_upload_files_remote_gcs_2(self):
    """Test upload_files_to_url."""
    self.gsutil_runner_obj.upload_files_to_url(
        ['/source_path1', '/source_path2'],
        'gs://target_bucket/target_path',
        timeout=1337)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', '-I', 'gs://target_bucket/target_path'],
        input_data=b'/source_path1\n/source_path2',
        timeout=1337,
        env=mock.ANY)

  def test_upload_files_to_url_local_gcs_2(self):
    """Test upload_files_to_url."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    self.fs.create_dir('/local/target_bucket')
    self.gsutil_runner_obj.upload_files_to_url(
        ['/source_path1', '/source_path2'],
        'gs://target_bucket/target_path',
        timeout=1337)
    self.mock.run_and_wait.assert_called_with(
        self.gsutil_runner_obj.gsutil_runner,
        ['cp', '-I', '/local/target_bucket/objects/target_path'],
        input_data=b'/source_path1\n/source_path2',
        timeout=1337,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

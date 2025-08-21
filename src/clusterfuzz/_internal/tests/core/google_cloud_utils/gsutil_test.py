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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive',
            '--delete-unmatched-destination-objects',
            'gs://source_bucket/source_path', 'gs://target_bucket/target_path'
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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive',
            '--delete-unmatched-destination-objects',
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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive',
            '--delete-unmatched-destination-objects',
            'gs://source_bucket/source_path', 'gs://target_bucket/target_path'
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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive',
            '--delete-unmatched-destination-objects',
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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive',
            'gs://source_bucket/source_path', 'gs://target_bucket/target_path'
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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive',
            '/local/source_bucket/objects/source_path',
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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive',
            'gs://source_bucket/source_path', 'gs://target_bucket/target_path'
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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive',
            '/local/source_bucket/objects/source_path',
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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive', '--exclude',
            '"*.txt$"', 'gs://source_bucket/source_path',
            'gs://target_bucket/target_path'
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
        self.gsutil_runner_obj.gcloud_runner, [
            '--quiet', 'storage', 'rsync', '--recursive', '--exclude',
            '"*.txt$"', '/local/source_bucket/objects/source_path',
            '/local/target_bucket/objects/target_path'
        ],
        timeout=1337,
        env=mock.ANY)
    self.assertTrue(os.path.exists('/local/target_bucket/objects'))

  def test_download_file(self):
    """Test download_file."""
    for use_gcloud in [False, True]:
      with self.subTest(use_gcloud=use_gcloud):
        os.environ['USE_GCLOUD_STORAGE'] = str(use_gcloud).lower()
        self.mock.run_and_wait.reset_mock()

        self.gsutil_runner_obj.download_file('gs://source/path', '/target')
        if use_gcloud:
          runner = self.gsutil_runner_obj.gcloud_runner
          expected_args = ['storage', 'cp', 'gs://source/path', '/target']
        else:
          runner = self.gsutil_runner_obj.gsutil_runner
          expected_args = ['cp', 'gs://source/path', '/target']

        self.mock.run_and_wait.assert_called_once_with(
            runner, expected_args, timeout=None, env=mock.ANY)

  def test_download_file_local(self):
    """Test download_file with local GCS."""
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = '/local'
    for use_gcloud in [False, True]:
      with self.subTest(use_gcloud=use_gcloud):
        os.environ['USE_GCLOUD_STORAGE'] = str(use_gcloud).lower()
        self.mock.run_and_wait.reset_mock()

        self.gsutil_runner_obj.download_file('gs://source/path', '/target')
        if use_gcloud:
          runner = self.gsutil_runner_obj.gcloud_runner
          expected_args = [
              'storage', 'cp', '/local/source/objects/path', '/target'
          ]
        else:
          runner = self.gsutil_runner_obj.gsutil_runner
          expected_args = ['cp', '/local/source/objects/path', '/target']

        self.mock.run_and_wait.assert_called_once_with(
            runner, expected_args, timeout=None, env=mock.ANY)

  def test_upload_file(self):
    """Test upload_file."""
    for use_gcloud in [False, True]:
      with self.subTest(use_gcloud=use_gcloud):
        os.environ['USE_GCLOUD_STORAGE'] = str(use_gcloud).lower()
        self.mock.run_and_wait.reset_mock()

        self.gsutil_runner_obj.upload_file('/source', 'gs://target/path')

        if use_gcloud:
          runner = self.gsutil_runner_obj.gcloud_runner
          expected_args = ['storage', 'cp', '/source', 'gs://target/path']
        else:
          runner = self.gsutil_runner_obj.gsutil_runner
          expected_args = ['cp', '/source', 'gs://target/path']

        self.mock.run_and_wait.assert_called_once_with(
            runner, expected_args, timeout=None, env=mock.ANY)

  def test_upload_file_with_metadata_and_gzip(self):
    """Test upload_file with metadata and gzip."""
    metadata = {
        'Content-Type': 'text/html',
        'x-goog-meta-foo': 'bar',
    }

    for use_gcloud in [False, True]:
      with self.subTest(use_gcloud=use_gcloud):
        os.environ['USE_GCLOUD_STORAGE'] = str(use_gcloud).lower()
        self.mock.run_and_wait.reset_mock()
        self.mock.run_and_wait.return_value.return_code = 0

        self.gsutil_runner_obj.upload_file(
            '/source', 'gs://target/path', gzip=True, metadata=metadata)

        if use_gcloud:
          self.mock.run_and_wait.assert_has_calls([
              mock.call(
                  self.gsutil_runner_obj.gcloud_runner, [
                      'storage', 'cp', '--gzip-local-all', '/source',
                      'gs://target/path'
                  ],
                  timeout=None,
                  env=mock.ANY),
              mock.call(
                  self.gsutil_runner_obj.gcloud_runner, [
                      'storage', 'objects', 'update', '--content-type',
                      'text/html', '--update-custom-metadata', 'foo=bar',
                      'gs://target/path'
                  ],
                  timeout=None,
                  env=mock.ANY)
          ])
        else:
          self.mock.run_and_wait.assert_called_once_with(
              self.gsutil_runner_obj.gsutil_runner, [
                  '-h', 'Content-Type:text/html', '-h', 'x-goog-meta-foo:bar',
                  'cp', '-Z', '/source', 'gs://target/path'
              ],
              timeout=None,
              env=mock.ANY)

  def test_upload_files_to_url(self):
    """Test upload_files_to_url."""
    file_paths = ['/source_path1', '/source_path2']
    for use_gcloud in [False, True]:
      with self.subTest(use_gcloud=use_gcloud):
        os.environ['USE_GCLOUD_STORAGE'] = str(use_gcloud).lower()
        self.mock.run_and_wait.reset_mock()

        self.gsutil_runner_obj.upload_files_to_url(file_paths,
                                                   'gs://target/path')

        if use_gcloud:
          runner = self.gsutil_runner_obj.gcloud_runner
          expected_args = ['storage', 'cp', '-I', 'gs://target/path']
        else:
          runner = self.gsutil_runner_obj.gsutil_runner
          expected_args = ['cp', '-I', 'gs://target/path']

        self.mock.run_and_wait.assert_called_once_with(
            runner,
            expected_args,
            input_data=b'/source_path1\n/source_path2',
            timeout=None,
            env=mock.ANY)

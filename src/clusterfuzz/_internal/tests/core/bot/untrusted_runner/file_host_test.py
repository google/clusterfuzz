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
"""Tests for remote_process."""

import os

import mock
from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.bot.untrusted_runner import config
from clusterfuzz._internal.bot.untrusted_runner import file_host
from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class FileHostTest(fake_filesystem_unittest.TestCase):
  """FileHost tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.untrusted_runner.host.stub',
    ])

    test_helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)

  def test_create_directory(self):
    """Test file_host.create_directory."""
    result = untrusted_runner_pb2.CreateDirectoryResponse(result=True)
    self.mock.stub().CreateDirectory.return_value = result
    self.assertTrue(file_host.create_directory('/path', True))

    result = untrusted_runner_pb2.CreateDirectoryResponse(result=False)
    self.mock.stub().CreateDirectory.return_value = result
    self.assertFalse(file_host.create_directory('/path', True))

  def test_remove_directory(self):
    """Test file_host.remove_directory."""
    result = untrusted_runner_pb2.RemoveDirectoryResponse(result=True)
    self.mock.stub().RemoveDirectory.return_value = result
    self.assertTrue(file_host.remove_directory('/path', True))

    result = untrusted_runner_pb2.RemoveDirectoryResponse(result=False)
    self.mock.stub().RemoveDirectory.return_value = result
    self.assertFalse(file_host.remove_directory('/path', True))

  def test_copy_file_to_worker(self):
    """Test file_host.copy_file_to_worker."""
    contents = (b'A' * config.FILE_TRANSFER_CHUNK_SIZE +
                b'B' * config.FILE_TRANSFER_CHUNK_SIZE +
                b'C' * config.FILE_TRANSFER_CHUNK_SIZE)

    self.fs.create_file('/file', contents=contents)

    def mock_copy_file_to(iterator, metadata):
      """Mock copy file to."""
      chunks = [chunk.data for chunk in iterator]
      self.assertEqual(3, len(chunks))

      self.assertEqual([('path-bin', b'/file')], metadata)

      data = b''.join(chunks)
      self.assertEqual(data, contents)

      return untrusted_runner_pb2.CopyFileToResponse(result=True)

    self.mock.stub().CopyFileTo.side_effect = mock_copy_file_to
    self.assertTrue(file_host.copy_file_to_worker('/file', '/file'))

  def test_write_data_to_worker(self):
    """Test file_host.write_data_to_worker."""
    contents = (b'A' * config.FILE_TRANSFER_CHUNK_SIZE +
                b'B' * config.FILE_TRANSFER_CHUNK_SIZE +
                b'C' * config.FILE_TRANSFER_CHUNK_SIZE)

    result = untrusted_runner_pb2.CopyFileToResponse(result=True)
    self.mock.stub().CopyFileTo.return_value = result

    self.assertTrue(file_host.write_data_to_worker(contents, '/file'))
    call_args = self.mock.stub().CopyFileTo.call_args
    self.assertEqual(call_args[1], {'metadata': [('path-bin', b'/file')]})

    chunks = [chunk.data for chunk in call_args[0][0]]
    self.assertEqual(len(chunks), 3)

    data = b''.join(chunks)
    self.assertEqual(data, contents)

  def test_copy_file_from_worker(self):
    """Test file_host.copy_file_from_worker."""
    mock_response = mock.MagicMock()
    mock_response.trailing_metadata.return_value = (('result', 'ok'),)
    mock_response.__iter__.return_value = iter([
        untrusted_runner_pb2.FileChunk(data=b'A'),
        untrusted_runner_pb2.FileChunk(data=b'B'),
        untrusted_runner_pb2.FileChunk(data=b'C'),
    ])

    self.mock.stub().CopyFileFrom.return_value = mock_response

    self.assertTrue(file_host.copy_file_from_worker('/file', '/file'))
    with open('/file') as f:
      self.assertEqual(f.read(), 'ABC')

  def test_copy_file_from_worker_failure(self):
    """Test file_host.copy_file_from_worker (failure)."""
    mock_response = mock.MagicMock()
    mock_response.trailing_metadata.return_value = (('result', 'invalid-path'),)
    self.mock.stub().CopyFileFrom.return_value = mock_response

    self.assertFalse(file_host.copy_file_from_worker('/file', '/file'))
    self.assertFalse(os.path.exists('/file'))

  def test_stat(self):
    """Test file_host.stat."""
    result = untrusted_runner_pb2.StatResponse(
        result=True, st_mode=0, st_size=1, st_atime=2, st_mtime=3, st_ctime=4)

    self.mock.stub().Stat.return_value = result
    self.assertEqual(result, file_host.stat('/path'))

  def test_stat_error(self):
    """Test file_host.stat error."""
    result = untrusted_runner_pb2.StatResponse(
        result=False, st_mode=0, st_size=1, st_atime=2, st_mtime=3, st_ctime=4)

    self.mock.stub().Stat.return_value = result
    self.assertIsNone(file_host.stat('/path'))

  @mock.patch(
      'clusterfuzz._internal.bot.untrusted_runner.file_host.remove_directory')
  @mock.patch(
      'clusterfuzz._internal.bot.untrusted_runner.file_host.copy_file_to_worker'
  )
  def test_copy_directory_to_worker(self, mock_copy_file_to_worker,
                                    mock_remove_directory):
    """Test file_host.copy_directory_to_worker."""
    mock_copy_file_to_worker.return_value = True

    self.fs.create_file('/host/dir/file1')
    self.fs.create_file('/host/dir/file2')
    self.fs.create_file('/host/dir/dir2/file3')
    self.fs.create_file('/host/dir/dir2/file4')
    self.fs.create_file('/host/dir/dir2/dir3/file5')

    self.assertTrue(
        file_host.copy_directory_to_worker('/host/dir', '/worker/copied_dir'))
    mock_copy_file_to_worker.assert_has_calls(
        [
            mock.call('/host/dir/file1', '/worker/copied_dir/file1'),
            mock.call('/host/dir/file2', '/worker/copied_dir/file2'),
            mock.call('/host/dir/dir2/file3', '/worker/copied_dir/dir2/file3'),
            mock.call('/host/dir/dir2/file4', '/worker/copied_dir/dir2/file4'),
            mock.call('/host/dir/dir2/dir3/file5',
                      '/worker/copied_dir/dir2/dir3/file5'),
        ],
        any_order=True)

    self.assertTrue(
        file_host.copy_directory_to_worker(
            '/host/dir', '/worker/copied_dir', replace=True))
    mock_copy_file_to_worker.assert_has_calls(
        [
            mock.call('/host/dir/file1', '/worker/copied_dir/file1'),
            mock.call('/host/dir/file2', '/worker/copied_dir/file2'),
            mock.call('/host/dir/dir2/file3', '/worker/copied_dir/dir2/file3'),
            mock.call('/host/dir/dir2/file4', '/worker/copied_dir/dir2/file4'),
            mock.call('/host/dir/dir2/dir3/file5',
                      '/worker/copied_dir/dir2/dir3/file5'),
        ],
        any_order=True)
    mock_remove_directory.assert_called_with(
        '/worker/copied_dir', recreate=True)

    mock_copy_file_to_worker.return_value = False
    self.assertFalse(
        file_host.copy_directory_to_worker('/host/dir', '/worker/copied_dir2'))

  @mock.patch('clusterfuzz._internal.bot.untrusted_runner.file_host.list_files')
  @mock.patch(
      'clusterfuzz._internal.bot.untrusted_runner.file_host.copy_file_from_worker'
  )
  def test_copy_directory_from_worker(self, mock_copy_file_from_worker,
                                      mock_list_files):
    """Test file_host.copy_directory_from_worker."""
    mock_copy_file_from_worker.return_value = True

    mock_list_files.return_value = [
        '/worker/abc',
        '/worker/def',
        '/worker/dir/ghi',
    ]

    self.assertTrue(file_host.copy_directory_from_worker('/worker', '/host'))
    mock_copy_file_from_worker.assert_has_calls(
        [
            mock.call('/worker/abc', '/host/abc'),
            mock.call('/worker/def', '/host/def'),
            mock.call('/worker/dir/ghi', '/host/dir/ghi'),
        ],
        any_order=True)

    mock_list_files.return_value = [
        '/escape',
    ]
    self.assertFalse(file_host.copy_directory_from_worker('/worker', '/host'))

    mock_list_files.return_value = [
        '/worker/../escape',
    ]
    self.assertFalse(file_host.copy_directory_from_worker('/worker', '/host'))

    mock_list_files.return_value = [
        '../escape',
    ]
    self.assertFalse(file_host.copy_directory_from_worker('/worker', '/host'))

  def test_get_cf_worker_path(self):
    """Test get worker path."""
    os.environ['WORKER_ROOT_DIR'] = '/worker'
    local_path = os.path.join(os.environ['ROOT_DIR'], 'a', 'b', 'c')

    self.assertEqual(
        file_host.rebase_to_worker_root(local_path), '/worker/a/b/c')

    local_path = os.environ['ROOT_DIR']
    self.assertEqual(file_host.rebase_to_worker_root(local_path), '/worker')

  def test_get_cf_host_path(self):
    """Test get host path."""
    os.environ['ROOT_DIR'] = '/host'
    os.environ['WORKER_ROOT_DIR'] = '/worker'
    worker_path = os.path.join(os.environ['WORKER_ROOT_DIR'], 'a', 'b', 'c')

    self.assertEqual(file_host.rebase_to_host_root(worker_path), '/host/a/b/c')

    worker_path = os.environ['WORKER_ROOT_DIR']
    self.assertEqual(file_host.rebase_to_host_root(worker_path), '/host')

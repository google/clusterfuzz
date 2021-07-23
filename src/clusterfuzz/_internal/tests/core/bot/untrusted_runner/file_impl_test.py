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
from clusterfuzz._internal.bot.untrusted_runner import file_impl
from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz._internal.tests.test_libs import test_utils


class FileImplTest(fake_filesystem_unittest.TestCase):
  """FileImpl tests."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)

  def test_create_directory(self):
    """Test file_impl.create_directory."""
    request = untrusted_runner_pb2.CreateDirectoryRequest(
        path='/dir', create_intermediates=False)
    response = file_impl.create_directory(request, None)
    self.assertTrue(response.result)
    self.assertTrue(os.path.isdir('/dir'))

    request = untrusted_runner_pb2.CreateDirectoryRequest(
        path='/dir2/dir2', create_intermediates=False)
    response = file_impl.create_directory(request, None)
    self.assertFalse(response.result)
    self.assertFalse(os.path.isdir('/dir2/dir2'))

    request = untrusted_runner_pb2.CreateDirectoryRequest(
        path='/dir3/dir3', create_intermediates=True)
    response = file_impl.create_directory(request, None)
    self.assertTrue(response.result)
    self.assertTrue(os.path.isdir('/dir3/dir3'))

  def test_remove_directory(self):
    """Test file_impl.remove_directory."""
    os.mkdir('/dir')
    request = untrusted_runner_pb2.RemoveDirectoryRequest(
        path='/dir', recreate=False)
    response = file_impl.remove_directory(request, None)
    self.assertTrue(response.result)
    self.assertFalse(os.path.isdir('/dir'))

    os.mkdir('/dir')
    request = untrusted_runner_pb2.RemoveDirectoryRequest(
        path='/dir', recreate=True)
    response = file_impl.remove_directory(request, None)
    self.assertTrue(response.result)
    self.assertTrue(os.path.isdir('/dir'))

  def test_copy_file_to_worker(self):
    """Test file_impl.copy_file_to_worker."""
    request_iterator = (
        untrusted_runner_pb2.FileChunk(data=b'A'),
        untrusted_runner_pb2.FileChunk(data=b'B'),
        untrusted_runner_pb2.FileChunk(data=b'C'),
    )

    context = mock.MagicMock()
    context.invocation_metadata.return_value = (('path-bin', b'/file'),)

    response = file_impl.copy_file_to_worker(request_iterator, context)
    self.assertTrue(response.result)
    self.assertTrue(os.path.exists('/file'))
    with open('/file') as f:
      self.assertEqual('ABC', f.read())

  def test_stat(self):
    """Test file_impl.stat."""
    self.fs.create_file('/file')
    request = untrusted_runner_pb2.StatRequest(path='/file')
    response = file_impl.stat(request, None)

    expected = os.stat('/file')
    self.assertTrue(response.result)
    self.assertEqual(expected.st_mode, response.st_mode)
    self.assertEqual(expected.st_size, response.st_size)
    self.assertEqual(expected.st_atime, response.st_atime)
    self.assertEqual(expected.st_ctime, response.st_ctime)
    self.assertEqual(expected.st_mtime, response.st_mtime)

  def test_stat_does_not_exist(self):
    """Test file_impl.stat (does not exist)."""
    request = untrusted_runner_pb2.StatRequest(path='/file')
    response = file_impl.stat(request, None)

    self.assertFalse(response.result)

  def test_copy_file_to_worker_create_intermediate(self):
    """Test file_impl.copy_file_to_worker (create intermediates)."""
    request_iterator = (
        untrusted_runner_pb2.FileChunk(data=b'A'),
        untrusted_runner_pb2.FileChunk(data=b'B'),
        untrusted_runner_pb2.FileChunk(data=b'C'),
    )

    context = mock.MagicMock()
    context.invocation_metadata.return_value = (('path-bin', b'/new_dir/file'),)

    response = file_impl.copy_file_to_worker(request_iterator, context)
    self.assertTrue(response.result)
    self.assertTrue(os.path.exists('/new_dir/file'))
    with open('/new_dir/file') as f:
      self.assertEqual('ABC', f.read())

  def test_copy_file_to_worker_create_dir_is_a_file(self):
    """Test file_impl.copy_file_to_worker when the directory is an existing
    file."""
    request_iterator = (
        untrusted_runner_pb2.FileChunk(data=b'A'),
        untrusted_runner_pb2.FileChunk(data=b'B'),
        untrusted_runner_pb2.FileChunk(data=b'C'),
    )

    self.fs.create_file('/file')

    context = mock.MagicMock()
    context.invocation_metadata.return_value = (('path-bin', b'/file/file'),)

    response = file_impl.copy_file_to_worker(request_iterator, context)
    self.assertFalse(response.result)
    self.assertTrue(os.path.isfile('/file'))

  def test_copy_file_to_worker_create_dir_error(self):
    """Test file_impl.copy_file_to_worker when we fail to create intermediate
    dirs."""
    request_iterator = (
        untrusted_runner_pb2.FileChunk(data=b'A'),
        untrusted_runner_pb2.FileChunk(data=b'B'),
        untrusted_runner_pb2.FileChunk(data=b'C'),
    )

    self.fs.create_file('/file')

    context = mock.MagicMock()
    context.invocation_metadata.return_value = (('path-bin',
                                                 b'/file/dir/file'),)

    response = file_impl.copy_file_to_worker(request_iterator, context)
    self.assertFalse(response.result)
    self.assertTrue(os.path.isfile('/file'))

  def test_copy_file_from_worker(self):
    """Test file_impl.copy_file_from_worker."""
    contents = (b'A' * config.FILE_TRANSFER_CHUNK_SIZE +
                b'B' * config.FILE_TRANSFER_CHUNK_SIZE +
                b'C' * config.FILE_TRANSFER_CHUNK_SIZE)

    self.fs.create_file('/file', contents=contents)

    request = untrusted_runner_pb2.CopyFileFromRequest(path='/file')
    context = mock.MagicMock()
    response = file_impl.copy_file_from_worker(request, context)

    chunks = [chunk.data for chunk in response]
    self.assertEqual(len(chunks), 3)
    self.assertEqual(contents, b''.join(chunks))
    context.set_trailing_metadata.assert_called_with([('result', 'ok')])

  def test_copy_file_from_worker_failed(self):
    """Test file_impl.copy_file_from_worker."""
    request = untrusted_runner_pb2.CopyFileFromRequest(path='/file')
    context = mock.MagicMock()
    response = file_impl.copy_file_from_worker(request, context)

    self.assertEqual(0, len(list(response)))
    context.set_trailing_metadata.assert_called_with([('result',
                                                       'invalid-path')])

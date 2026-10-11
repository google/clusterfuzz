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
"""archive tests."""
import io
import os
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers

TESTDATA_PATH = os.path.join(os.path.dirname(__file__), 'archive_data')


def _create_test_zip(zip_path, file_entries):
  """Helper to create a test zip file with specified attributes."""
  with zipfile.ZipFile(zip_path, 'w') as zip_file:
    for filename, content, external_attr in file_entries:
      info = zipfile.ZipInfo(filename)
      info.create_system = 3
      info.external_attr = external_attr
      zip_file.writestr(info, content)


class UnpackTest(unittest.TestCase):
  """Unpack tests."""

  def test_unpack_file_with_cwd_prefix(self):
    """Test unpack with trusted=False passes with file having './' prefix."""
    tgz_path = os.path.join(TESTDATA_PATH, 'cwd-prefix.tgz')
    output_directory = tempfile.mkdtemp(prefix='cwd-prefix')
    self.addCleanup(shell.remove_directory, output_directory)
    with archive.open(tgz_path) as reader:
      reader.extract_all(output_directory, trusted=False)

    test_file_path = os.path.join(output_directory, 'test')
    self.assertTrue(os.path.exists(test_file_path))
    self.assertEqual(open(test_file_path).read(), 'abc\n')

  def test_extract(self):
    tar_xz_path = os.path.join(TESTDATA_PATH, 'archive.tar.xz')
    with archive.open(tar_xz_path) as reader:
      self.assertEqual(reader.extracted_size(), 7)

  def test_file_list(self):
    tar_xz_path = os.path.join(TESTDATA_PATH, 'archive.tar.xz')
    with archive.open(tar_xz_path) as reader:
      self.assertCountEqual(
          [f.name for f in reader.list_members()],
          ["archive_dir", "archive_dir/bye", "archive_dir/hi"])

  def test_unpack_absolute_path_traversal(self):
    """Test that unpacking an archive with an absolute path fails."""
    # Create a temporary TAR archive file on disk.
    with tempfile.NamedTemporaryFile(suffix='.tar') as tmp_tar_file:
      malicious_archive_path = tmp_tar_file.name

      # Create a malicious archive with an absolute path payload.
      with tarfile.open(malicious_archive_path, 'w') as tar:
        file_data = b'malicious content'
        # Creating a TarInfo object with an absolute path.
        tarinfo = tarfile.TarInfo(name='/tmp/pwned')
        tarinfo.size = len(file_data)
        tar.addfile(tarinfo, io.BytesIO(file_data))

      output_directory = tempfile.mkdtemp()
      self.addCleanup(shell.remove_directory, output_directory)

      # The function should return False, indicating an error occurred.
      with archive.open(malicious_archive_path) as reader:
        result = reader.extract_all(output_directory, trusted=False)
        self.assertFalse(result)

  def test_zip_extract_permissions_mocked_chmod(self):
    """Test zip extraction only calls chmod when permissions change or execute bit is set."""
    helpers.patch(self, ['os.chmod'])
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip_file:
      zip_path = tmp_zip_file.name
      _create_test_zip(zip_path, [
          ('exe.sh', b'echo hi', 0o100755 << 16),
          ('reg_644.txt', b'hello', 0o100644 << 16),
          ('reg_640.txt', b'world', 0o100640 << 16),
          ('reg_600.txt', b'secret', 0o100600 << 16),
          ('reg_444.txt', b'read only', 0o100444 << 16),
      ])

      output_directory = tempfile.mkdtemp(prefix='zip-chmod-test')
      self.addCleanup(shell.remove_directory, output_directory)
      with archive.open(zip_path) as reader:
        reader.extract_all(output_directory, trusted=True)

      expected_calls = [
          mock.call(os.path.join(output_directory, 'exe.sh'), 0o750),
          mock.call(os.path.join(output_directory, 'reg_600.txt'), 0o640),
      ]
      self.mock.chmod.assert_has_calls(expected_calls, any_order=True)
      self.assertEqual(self.mock.chmod.call_count, 2)

  def test_zip_extract_permissions_filesystem(self):
    """Test actual filesystem execution bits when extracting a zip archive."""
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip_file:
      zip_path = tmp_zip_file.name
      _create_test_zip(zip_path, [
          ('exe.sh', b'echo hi', 0o100755 << 16),
          ('reg.txt', b'hello', 0o100644 << 16),
      ])

      output_directory = tempfile.mkdtemp(prefix='zip-fs-test')
      self.addCleanup(shell.remove_directory, output_directory)
      with archive.open(zip_path) as reader:
        reader.extract_all(output_directory, trusted=True)

      exe_path = os.path.join(output_directory, 'exe.sh')
      reg_path = os.path.join(output_directory, 'reg.txt')

      self.assertTrue(os.access(exe_path, os.X_OK))
      self.assertFalse(os.access(reg_path, os.X_OK))
      self.assertEqual(os.stat(exe_path).st_mode & 0o777, 0o750)

  def test_zip_unpack_absolute_path_traversal(self):
    """Test that unpacking a zip archive with an absolute path fails when untrusted."""
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip_file:
      malicious_archive_path = tmp_zip_file.name

      with zipfile.ZipFile(malicious_archive_path, 'w') as zip_file:
        info = zipfile.ZipInfo('/tmp/pwned')
        zip_file.writestr(info, b'malicious content')

      output_directory = tempfile.mkdtemp()
      self.addCleanup(shell.remove_directory, output_directory)

      with archive.open(malicious_archive_path) as reader:
        result = reader.extract_all(output_directory, trusted=False)
        self.assertFalse(result)


class ArchiveReaderTest(unittest.TestCase):
  """Tests for the archive.iterator function."""

  def test_tar_xz(self):
    """Test that a .tar.xz file is handled properly by iterator()."""
    tar_xz_path = os.path.join(TESTDATA_PATH, 'archive.tar.xz')
    expected_results = {'archive_dir/hi': b'hi\n', 'archive_dir/bye': b'bye\n'}
    with archive.open(tar_xz_path) as reader:
      actual_results = {}
      for member in reader.list_members():
        if not member.is_dir:
          with reader.open(member.name) as f:
            actual_results[member.name] = f.read()
      self.assertEqual(actual_results, expected_results)

  def test_cwd_prefix(self):
    """Test that a .tgz file with cwd prefix is handled."""
    tgz_path = os.path.join(TESTDATA_PATH, 'cwd-prefix.tgz')
    expected_results = {'./test': b'abc\n'}
    with archive.open(tgz_path) as reader:
      actual_results = {}
      for member in reader.list_members():
        if not member.is_dir:
          with reader.open(member.name) as f:
            actual_results[member.name] = f.read()
      self.assertEqual(actual_results, expected_results)

  def test_tar_xz_broken_links(self):
    """Test that a .tar file with broken links is handled properly by
    iterator()."""
    helpers.patch(self, ['clusterfuzz._internal.metrics.logs.warning'])

    archive_name = 'broken-links.tar.xz'
    archive_path = os.path.join(TESTDATA_PATH, archive_name)
    with archive.open(archive_path) as reader:

      # Get the results we expect from iterator().
      actual_results = []
      for file in reader.list_members():
        # This means we can read the file.
        handle = reader.try_open(file.name)
        if handle is not None:
          actual_results.append((file.name, file.size_bytes, handle.read()))
          handle.close()
        else:
          actual_results.append((file.name, file.size_bytes, None))

      # Check that iterator returns what we expect it to.
      expected_results = [
          ('testdir', 0, None),
          ('testdir/1', 0, None),
          ('testdir/1/a', 12, b'hello world\n'),
          ('testdir/2', 0, None),
          ('testdir/2/c', 0, b'hello world\n'),  # Working link
          ('testdir/2/a', 0, None),
          ('testdir/2/b', 0, None)
      ]

      self.assertEqual(expected_results, actual_results)

  def test_zip(self):
    """Test that a .zip file is handled properly by list_members() and open()."""
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip_file:
      zip_path = tmp_zip_file.name
      _create_test_zip(zip_path, [
          ('archive_dir/hi', b'hi\n', 0o100644 << 16),
          ('archive_dir/bye', b'bye\n', 0o100644 << 16),
      ])

      expected_results = {
          'archive_dir/hi': b'hi\n',
          'archive_dir/bye': b'bye\n'
      }
      with archive.open(zip_path) as reader:
        actual_results = {}
        for member in reader.list_members():
          self.assertEqual(member.mode, 0o644)
          if not member.is_dir:
            with reader.open(member.name) as f:
              actual_results[member.name] = f.read()
        self.assertEqual(actual_results, expected_results)

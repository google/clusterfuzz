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
import os
import tempfile
import unittest

from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers

TESTDATA_PATH = os.path.join(os.path.dirname(__file__), 'archive_data')


class UnpackTest(unittest.TestCase):
  """Unpack tests."""

  def test_unpack_file_with_cwd_prefix(self):
    """Test unpack with trusted=False passes with file having './' prefix."""
    tgz_path = os.path.join(TESTDATA_PATH, 'cwd-prefix.tgz')
    output_directory = tempfile.mkdtemp(prefix='cwd-prefix')
    archive.unpack(tgz_path, output_directory, trusted=False)

    test_file_path = os.path.join(output_directory, 'test')
    self.assertTrue(os.path.exists(test_file_path))
    self.assertEqual(open(test_file_path).read(), 'abc\n')

    shell.remove_directory(output_directory)

  def test_extract(self):
    tar_xz_path = os.path.join(TESTDATA_PATH, 'archive.tar.xz')
    reader = archive.get_archive_reader(tar_xz_path)
    self.assertEqual(reader.extracted_size(), 7)

  def test_file_list(self):
    tar_xz_path = os.path.join(TESTDATA_PATH, 'archive.tar.xz')
    reader = archive.get_archive_reader(tar_xz_path)
    self.assertIsNotNone(reader)
    self.assertCountEqual([f.filename for f in reader.list_files()],
                          ["archive_dir", "archive_dir/bye", "archive_dir/hi"])


class IteratorTest(unittest.TestCase):
  """Tests for the archive.iterator function."""

  def test_tar_xz(self):
    """Test that a .tar.xz file is handled properly by iterator()."""
    tar_xz_path = os.path.join(TESTDATA_PATH, 'archive.tar.xz')
    expected_results = {'archive_dir/hi': b'hi\n', 'archive_dir/bye': b'bye\n'}
    reader = archive.get_archive_reader(tar_xz_path)
    self.assertIsNotNone(reader)
    actual_results = {
        f.filename: reader.open(f.filename).read()
        for f in reader.list_files()
        if not f.is_dir()
    }
    self.assertEqual(actual_results, expected_results)

  def test_cwd_prefix(self):
    """Test that a .tgz file with cwd prefix is handled."""
    tgz_path = os.path.join(TESTDATA_PATH, 'cwd-prefix.tgz')
    expected_results = {'./test': b'abc\n'}
    reader = archive.get_archive_reader(tgz_path)
    self.assertIsNotNone(reader)
    actual_results = {
        f.filename: reader.open(f.filename).read()
        for f in reader.list_files()
        if not f.is_dir()
    }
    self.assertEqual(actual_results, expected_results)

  def test_tar_xz_broken_links(self):
    """Test that a .tar file with broken links is handled properly by
    iterator()."""
    helpers.patch(self, ['clusterfuzz._internal.metrics.logs.log_warn'])

    archive_name = 'broken-links.tar.xz'
    archive_path = os.path.join(TESTDATA_PATH, archive_name)
    reader = archive.get_archive_reader(archive_path)
    self.assertIsNotNone(reader)

    # Get the results we expect from iterator().
    actual_results = []
    for file in reader.list_files():
      # This means we can read the file.
      handle = reader.try_open(file.filename)
      if handle is not None:
        actual_results.append((file.filename, file.file_size, handle.read()))
      else:
        actual_results.append((file.filename, file.file_size, None))

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

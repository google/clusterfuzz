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
"""Tests for fuzzers.utils."""

import os
import shutil
import tempfile
import unittest

from clusterfuzz._internal.bot.fuzzers import utils
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class IsFuzzTargetLocalTest(unittest.TestCase):
  """is_fuzz_target_local tests."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.temp_dir = tempfile.mkdtemp()

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def _create_file(self, name, contents=b''):
    path = os.path.join(self.temp_dir, name)
    with open(path, 'wb') as f:
      f.write(contents)

    return path

  def test_not_a_fuzzer_invalid_name(self):
    path = self._create_file('abc$_fuzzer', contents=b'LLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target_local(path))

  def test_not_a_fuzzer_blocklisted_name(self):
    path = self._create_file(
        'jazzer_driver', contents=b'LLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target_local(path))

  def test_not_a_fuzzer_without_extension(self):
    path = self._create_file('abc', contents=b'anything')
    self.assertFalse(utils.is_fuzz_target_local(path))

  def test_not_a_fuzzer_with_extension(self):
    path = self._create_file('abc.dict', contents=b'LLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target_local(path))

  def test_not_a_fuzzer_with_extension_and_suffix(self):
    path = self._create_file(
        'abc_fuzzer.dict', contents=b'LLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target_local(path))

  def test_fuzzer_posix(self):
    path = self._create_file('abc_fuzzer', contents=b'anything')
    self.assertTrue(utils.is_fuzz_target_local(path))

  def test_fuzzer_win(self):
    path = self._create_file('abc_fuzzer.exe', contents=b'anything')
    self.assertTrue(utils.is_fuzz_target_local(path))

  def test_fuzzer_py(self):
    path = self._create_file('abc_fuzzer.par', contents=b'anything')
    self.assertTrue(utils.is_fuzz_target_local(path))

  def test_fuzzer_not_exist(self):
    self.assertFalse(utils.is_fuzz_target_local('/not_exist_fuzzer'))

  def test_fuzzer_without_suffix(self):
    path = self._create_file(
        'abc', contents=b'anything\nLLVMFuzzerTestOneInput')
    self.assertTrue(utils.is_fuzz_target_local(path))

  def test_fuzzer_with_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    path = self._create_file('a_custom', contents=b'anything')
    self.assertTrue(utils.is_fuzz_target_local(path))

  def test_fuzzer_with_file_string_and_without_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    path = self._create_file(
        'nomatch', contents=b'anything\nLLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target_local(path))

  def test_fuzzer_without_file_string_and_without_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    path = self._create_file('nomatch', contents=b'anything')
    self.assertFalse(utils.is_fuzz_target_local(path))

  def test_fuzzer_with_fuzzer_name_and_without_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    path = self._create_file(
        'a_fuzzer', contents=b'anything\nLLVMFuzzerTestOneInput')
    self.assertTrue(utils.is_fuzz_target_local(path))

  def test_file_handle(self):
    """Test with a file handle."""
    path = self._create_file(
        'abc', contents=b'anything\nLLVMFuzzerTestOneInput')
    with open(path, 'rb') as f:
      self.assertTrue(utils.is_fuzz_target_local('name', f))


class GetSupportingFileTest(unittest.TestCase):
  """Tests for get_supporting_file."""

  def test_no_extension(self):
    """Test no extension."""
    self.assertEqual('/a/b.labels', utils.get_supporting_file(
        '/a/b', '.labels'))

  def test_unknown_extension(self):
    """Test unknown extension."""
    self.assertEqual('/a/b.c.labels',
                     utils.get_supporting_file('/a/b.c', '.labels'))

  def test_exe(self):
    """Test exe extension."""
    self.assertEqual('/a/b.labels',
                     utils.get_supporting_file('/a/b.exe', '.labels'))

  def test_par(self):
    """Test par extension."""
    self.assertEqual('/a/b.labels',
                     utils.get_supporting_file('/a/b.par', '.labels'))

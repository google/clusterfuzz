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

import json
import os
import shutil
import tempfile
import unittest

from clusterfuzz._internal.bot.fuzzers import utils
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class IsFuzzTargetLocalTest(unittest.TestCase):
  """is_fuzz_target tests."""

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
    self.assertFalse(utils.is_fuzz_target(path))

  def test_not_a_fuzzer_blocklisted_name(self):
    path = self._create_file(
        'jazzer_driver', contents=b'LLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target(path))

  def test_not_a_fuzzer_jazzerjs(self):
    path = self._create_file('jazzerjs', contents=b'LLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target(path))

  def test_not_a_fuzzer_without_extension(self):
    path = self._create_file('abc', contents=b'anything')
    self.assertFalse(utils.is_fuzz_target(path))

  def test_not_a_fuzzer_with_extension(self):
    path = self._create_file('abc.dict', contents=b'LLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target(path))

  def test_not_a_fuzzer_with_extension_and_suffix(self):
    path = self._create_file(
        'abc_fuzzer.dict', contents=b'LLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target(path))

  def test_fuzzer_posix(self):
    path = self._create_file('abc_fuzzer', contents=b'anything')
    self.assertTrue(utils.is_fuzz_target(path))

  def test_fuzzer_win(self):
    path = self._create_file('abc_fuzzer.exe', contents=b'anything')
    self.assertTrue(utils.is_fuzz_target(path))

  def test_fuzzer_py(self):
    path = self._create_file('abc_fuzzer.par', contents=b'anything')
    self.assertTrue(utils.is_fuzz_target(path))

  def test_fuzzer_not_exist(self):
    self.assertFalse(utils.is_fuzz_target('/not_exist_fuzzer'))

  def test_fuzzer_without_suffix(self):
    path = self._create_file(
        'abc', contents=b'anything\nLLVMFuzzerTestOneInput')
    self.assertTrue(utils.is_fuzz_target(path))

  def test_fuzzer_with_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    path = self._create_file('a_custom', contents=b'anything')
    self.assertTrue(utils.is_fuzz_target(path))

  def test_fuzzer_with_file_string_and_without_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    path = self._create_file(
        'nomatch', contents=b'anything\nLLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target(path))

  def test_fuzzer_without_file_string_and_without_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    path = self._create_file('nomatch', contents=b'anything')
    self.assertFalse(utils.is_fuzz_target(path))

  def test_fuzzer_with_fuzzer_name_and_without_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    path = self._create_file(
        'a_fuzzer', contents=b'anything\nLLVMFuzzerTestOneInput')
    self.assertTrue(utils.is_fuzz_target(path))

  def test_file_handle(self):
    """Test with a file handle."""

    class MockFileOpener:

      def __init__(self, fileobj):
        self.fileobj = fileobj

      def __call__(self, _):
        return self.fileobj

    path = self._create_file(
        'abc', contents=b'anything\nLLVMFuzzerTestOneInput')
    f_opener = MockFileOpener(open(path, 'rb'))
    self.assertTrue(utils.is_fuzz_target('name', f_opener))
    self.assertTrue(f_opener.fileobj.closed)


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


class GetFuzzTargetsLocalTest(unittest.TestCase):
  """Tests for get_fuzz_targets_local."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.temp_dir = tempfile.mkdtemp()

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def _create_file(self, name, contents=b''):
    path = os.path.join(self.temp_dir, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
      f.write(contents)
    return path

  def test_manifest_targets_used(self):
    """Test that clusterfuzz_manifest.json is used to find targets."""
    target_a = self._create_file('target_a', contents=b'LLVMFuzzerTestOneInput')
    self._create_file('run_target_a_fuzzer', contents=b'LLVMFuzzerTestOneInput')
    manifest_contents = json.dumps({
        'archive_schema_version': 1,
        'fuzz_targets': ['target_a']
    }).encode('utf-8')
    self._create_file('clusterfuzz_manifest.json', contents=manifest_contents)

    targets = utils.get_fuzz_targets_local(self.temp_dir)
    self.assertEqual([target_a], targets)

  def test_manifest_missing_fallback(self):
    """Test fallback to scanning when manifest is missing."""
    target_a = self._create_file(
        'target_a_fuzzer', contents=b'LLVMFuzzerTestOneInput')
    target_b = self._create_file(
        'target_b_fuzzer', contents=b'LLVMFuzzerTestOneInput')

    targets = utils.get_fuzz_targets_local(self.temp_dir)
    self.assertCountEqual([target_a, target_b], targets)

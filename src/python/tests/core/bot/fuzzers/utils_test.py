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
from pyfakefs import fake_filesystem_unittest

from bot.fuzzers import utils
from system import environment
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


class IsFuzzTargetLocalTest(fake_filesystem_unittest.TestCase):
  """is_fuzz_target_local tests."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)

  def test_not_a_fuzzer_invalid_name(self):
    self.fs.CreateFile('/abc$_fuzzer', contents='anything')
    self.assertFalse(utils.is_fuzz_target_local('/abc$_fuzzer'))

  def test_not_a_fuzzer_without_extension(self):
    self.fs.CreateFile('/abc', contents='anything')
    self.assertFalse(utils.is_fuzz_target_local('/abc'))

  def test_not_a_fuzzer_with_extension(self):
    self.fs.CreateFile('/abc.dict', contents='anything')
    self.assertFalse(utils.is_fuzz_target_local('/abc.dict'))

  def test_not_a_fuzzer_with_extension_and_suffix(self):
    self.fs.CreateFile('/abc_fuzzer.dict', contents='anything')
    self.assertFalse(utils.is_fuzz_target_local('/abc_fuzzer.dict'))

  def test_fuzzer_posix(self):
    self.fs.CreateFile('/abc_fuzzer', contents='anything')
    self.assertTrue(utils.is_fuzz_target_local('/abc_fuzzer'))

  def test_fuzzer_win(self):
    self.fs.CreateFile('/abc_fuzzer.exe', contents='anything')
    self.assertTrue(utils.is_fuzz_target_local('/abc_fuzzer.exe'))

  def test_fuzzer_not_exist(self):
    self.assertFalse(utils.is_fuzz_target_local('/not_exist_fuzzer'))

  def test_fuzzer_without_suffix(self):
    self.fs.CreateFile('/abc', contents='anything\nLLVMFuzzerTestOneInput')
    self.assertTrue(utils.is_fuzz_target_local('/abc'))

  def test_fuzzer_with_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    self.fs.CreateFile('/a_custom', contents='anything')
    self.assertTrue(utils.is_fuzz_target_local('/a_custom'))

  def test_fuzzer_with_file_string_and_without_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    self.fs.CreateFile('/nomatch', contents='anything\nLLVMFuzzerTestOneInput')
    self.assertFalse(utils.is_fuzz_target_local('/nomatch'))

  def test_fuzzer_without_file_string_and_without_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    self.fs.CreateFile('/nomatch', contents='anything')
    self.assertFalse(utils.is_fuzz_target_local('/nomatch'))

  def test_fuzzer_with_fuzzer_name_and_without_name_regex_match(self):
    environment.set_value('FUZZER_NAME_REGEX', '.*_custom$')
    self.fs.CreateFile('/a_fuzzer', contents='anything\nLLVMFuzzerTestOneInput')
    self.assertTrue(utils.is_fuzz_target_local('/a_fuzzer'))

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
"""Tests for leaks functions."""

import os
import shutil
import tempfile
import unittest

import mock

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import leak_blacklist
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class LeaksTest(unittest.TestCase):
  """Base class for leaks test cases."""

  def setUp(self):
    self.data_directory = os.path.join(
        os.path.dirname(__file__), 'leak_blacklist_data')
    self.temp_directory = tempfile.mkdtemp()

  def tearDown(self):
    shutil.rmtree(self.temp_directory)

  def _read_test_data(self, filename):
    """Helper function to read files."""
    with open(os.path.join(self.data_directory, filename)) as file_handle:
      return file_handle.read()

  def _add_dummy_leak_testcase(self):
    """Helper function to add a dummy testcase to Testcase database."""
    testcase_item = data_types.Testcase(
        crash_type='Direct-leak', crash_state='test_foo\ntest_bar\n')
    testcase_item.put()
    return testcase_item

  def test_single_leak(self):
    """Test highlighting for report with single direct leak."""
    data = self._read_test_data('single_direct_leak.txt')
    actual_data = leak_blacklist.highlight_first_direct_leak(data)
    expected_data = data
    self.assertEqual(expected_data, actual_data)

  def test_indirect_before_direct_leak(self):
    """Test highlighting when indirect leak precedes first direct leak."""
    data = self._read_test_data('indirect_before_direct_leak.txt')
    actual_data = leak_blacklist.highlight_first_direct_leak(data)
    expected_data = self._read_test_data(
        'indirect_before_direct_leak_highlighted.txt')
    self.assertEqual(expected_data, actual_data)

  def test_multi_direct_leaks(self):
    """Test highlighting for report with multiple direct leaks."""
    data = self._read_test_data('multi_direct_leak.txt')
    actual_data = leak_blacklist.highlight_first_direct_leak(data)
    expected_data = self._read_test_data('multi_direct_leak_expected.txt')
    self.assertEqual(expected_data, actual_data)

  def test_add_to_global_blacklist(self):
    """Test adding element to global blacklist."""
    testcase = self._add_dummy_leak_testcase()
    blacklist_item = leak_blacklist.add_crash_to_global_blacklist_if_needed(
        testcase)
    self.assertTrue(blacklist_item.key.get())

  @mock.patch(
      'clusterfuzz._internal.fuzzing.leak_blacklist.get_local_blacklist_file_path'
  )
  def test_copy_global_to_local_blacklist(self,
                                          mock_get_local_blacklist_file_path):
    """Test copying of global to local blacklist."""
    local_blacklist_file_path = os.path.join(self.temp_directory,
                                             'lsan_suppressions.txt')
    mock_get_local_blacklist_file_path.return_value = local_blacklist_file_path

    testcase = self._add_dummy_leak_testcase()
    blacklist_item = leak_blacklist.add_crash_to_global_blacklist_if_needed(
        testcase)
    self.assertTrue(blacklist_item.key.get())

    # Test that a reproducible leak gets copied to local blacklist file.
    leak_blacklist.copy_global_to_local_blacklist()
    blacklist_function = leak_blacklist.get_leak_function_for_blacklist(
        testcase)
    expected_lsan_suppression_line = (
        leak_blacklist.LSAN_SUPPRESSION_LINE.format(function=blacklist_function)
    )
    self.assertTrue(os.path.isfile(local_blacklist_file_path))
    self.assertIn(expected_lsan_suppression_line,
                  self._read_test_data(local_blacklist_file_path))

    # Test that an excluded reproducible leak is not copied to blacklist file.
    leak_blacklist.copy_global_to_local_blacklist(excluded_testcase=testcase)
    self.assertTrue(os.path.isfile(local_blacklist_file_path))
    self.assertNotIn(expected_lsan_suppression_line,
                     self._read_test_data(local_blacklist_file_path))

  def test_clean_up_global_blacklist(self):
    """Test cleaning of global blacklist."""
    # Test that a reproducible leak is not cleared from blacklist cleanup.
    testcase = self._add_dummy_leak_testcase()
    blacklist_item = leak_blacklist.add_crash_to_global_blacklist_if_needed(
        testcase)
    leak_blacklist.cleanup_global_blacklist()
    self.assertTrue(blacklist_item.key.get())

    # Test that an unreproducible leak is cleared from blacklist cleanup.
    testcase.one_time_crasher_flag = True
    testcase.put()
    leak_blacklist.cleanup_global_blacklist()
    self.assertFalse(blacklist_item.key.get())

    # Flip reproducibility flag and verify that testcase is in blacklist.
    testcase.one_time_crasher_flag = False
    testcase.put()
    blacklist_item = leak_blacklist.add_crash_to_global_blacklist_if_needed(
        testcase)
    self.assertTrue(blacklist_item.key.get())

    # Delete testcase and make sure it is removed from blacklist.
    testcase.key.delete()
    leak_blacklist.cleanup_global_blacklist()
    self.assertFalse(blacklist_item.key.get())


if __name__ == '__main__':
  unittest.main()

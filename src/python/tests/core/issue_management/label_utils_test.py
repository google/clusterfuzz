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
"""Tests for the label_utils module."""

import os
import unittest

from issue_management import label_utils

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'label_utils_data')


class LabelUtilsTest(unittest.TestCase):
  """Label utils tests."""

  @staticmethod
  def _read_test_data(name):
    """Helper function to read test data."""
    with open(os.path.join(DATA_DIRECTORY, name)) as handle:
      return handle.read()

  def test_memory_tools_labels_asan(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Stability-Memory-AddressSanitizer']
    data = self._read_test_data('memory_tools_asan.txt')
    actual_labels = label_utils.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_asan_afl(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Stability-Memory-AddressSanitizer', 'Stability-AFL']
    data = self._read_test_data('memory_tools_asan_afl.txt')
    actual_labels = label_utils.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_asan_libfuzzer(self):
    """Run memory tools detection with test data."""
    expected_labels = [
        'Stability-Memory-AddressSanitizer', 'Stability-LibFuzzer'
    ]
    data = self._read_test_data('memory_tools_asan_libfuzzer.txt')
    actual_labels = label_utils.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_asan_lsan(self):
    """Run memory tools detection with test data."""
    expected_labels = [
        'Stability-Memory-AddressSanitizer', 'Stability-Memory-LeakSanitizer'
    ]
    data = self._read_test_data('memory_tools_asan_lsan.txt')
    actual_labels = label_utils.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_msan(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Stability-Memory-MemorySanitizer']
    data = self._read_test_data('memory_tools_msan.txt')
    actual_labels = label_utils.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_msan_libfuzzer(self):
    """Run memory tools detection with test data."""
    expected_labels = [
        'Stability-Memory-MemorySanitizer', 'Stability-LibFuzzer'
    ]
    data = self._read_test_data('memory_tools_msan_libfuzzer.txt')
    actual_labels = label_utils.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_tsan(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Stability-ThreadSanitizer']
    data = self._read_test_data('memory_tools_tsan.txt')
    actual_labels = label_utils.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_ubsan(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Stability-UndefinedBehaviorSanitizer']
    data = self._read_test_data('memory_tools_ubsan.txt')
    actual_labels = label_utils.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

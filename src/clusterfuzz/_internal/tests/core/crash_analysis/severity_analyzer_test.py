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
"""Tests for the severity analyzer module."""

import os
import unittest

from clusterfuzz._internal.crash_analysis import severity_analyzer
from clusterfuzz._internal.datastore.data_types import SecuritySeverity

DATA_DIRECTORY = os.path.join(
    os.path.dirname(__file__), 'stack_parsing', 'stack_analyzer_data')


class SeverityAnalyzerTest(unittest.TestCase):
  """Severity analyzer tests."""

  def _read_test_data(self, name):
    """Helper function to read test data."""
    with open(os.path.join(DATA_DIRECTORY, name)) as handle:
      return handle.read()

  def test_manual_severity_marker(self):
    """Tests that manual severity markers in uncaught exceptions are
    recognized."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Uncaught exception',
            self._read_test_data('java_severity_medium_exception.txt'), False),
        SecuritySeverity.MEDIUM)

  def test_asan_uaf(self):
    """Tests severity analysis of a use after free report."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Heap-use-after-free\nREAD 8', self._read_test_data('asan_uaf.txt'),
            False), SecuritySeverity.HIGH)

  def test_asan_uaf_gestures(self):
    """Tests severity analysis of a use after free report that requires
    gestures."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Heap-use-after-free\nREAD 8', self._read_test_data('asan_uaf.txt'),
            True), SecuritySeverity.MEDIUM)

  def test_asan_heap_overflow_read(self):
    """Tests severity analysis of a heap overflow read."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Heap-buffer-overflow\nREAD 4',
            self._read_test_data('asan_heap_overflow_read.txt'), False),
        SecuritySeverity.MEDIUM)

  def test_asan_heap_overflow_read_gestures(self):
    """Tests severity analysis of a heap overflow read that requires
    gestures."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Heap-buffer-overflow\nREAD 4',
            self._read_test_data('asan_heap_overflow_read.txt'), True),
        SecuritySeverity.LOW)

  def test_asan_heap_overflow_write(self):
    """Tests severity analysis of a heap overflow write."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Heap-buffer-overflow\nWRITE 16',
            self._read_test_data('asan_heap_overflow_write.txt'), False),
        SecuritySeverity.HIGH)

  def test_asan_heap_overflow_write_gestures(self):
    """Tests severity analysis of a heap overflow write that requires
    gestures."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Heap-buffer-overflow\nWRITE 16',
            self._read_test_data('asan_heap_overflow_write.txt'), True),
        SecuritySeverity.MEDIUM)

  def test_asan_container_overflow_read(self):
    """Tests severity analysis of a container overflow read."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Container-overflow\nREAD 4',
            self._read_test_data('asan_container_overflow_read.txt'), False),
        SecuritySeverity.MEDIUM)

  def test_asan_container_overflow_write(self):
    """Tests severity analysis of a container overflow write."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Container-overflow\nWRITE 4',
            self._read_test_data('asan_container_overflow_read.txt'), False),
        SecuritySeverity.HIGH)

  def test_sanitizer_chrome_renderer_uaf(self):
    """Tests severity analysis of a use after free in the renderer."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_chrome').analyze(
            'Heap-use-after-free\nREAD 8', self._read_test_data('asan_uaf.txt'),
            False), SecuritySeverity.HIGH)

  def test_asan_unknown_read(self):
    """Tests severity analysis of a SEGV read."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'UNKNOWN READ', self._read_test_data('asan_unknown_read.txt'),
            False), SecuritySeverity.MEDIUM)

  def test_asan_unknown_write(self):
    """Tests severity analysis of a SEGV write."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'UNKNOWN WRITE', self._read_test_data('asan_unknown_write.txt'),
            False), SecuritySeverity.HIGH)

  def test_tsan_uaf(self):
    """Tests severity analysis of a use after free report given by TSan."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Heap-use-after-free READ 1',
            self._read_test_data('tsan_use_after_free.txt'), False),
        SecuritySeverity.HIGH)

  def test_ubsan_bad_cast(self):
    """Tests severity analysis of a bad cast report given by UBSan vtpr."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Bad-cast', self._read_test_data('ubsan_bad_cast_downcast.txt'),
            False), SecuritySeverity.HIGH)

  def test_ubsan_incorrect_function_pointer_type(self):
    """Tests severity analysis of an incorrect function pointer type report
    given by UBSan function."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Incorrect-function-pointer-type',
            self._read_test_data('ubsan_incorrect_function_pointer_type.txt'),
            False), SecuritySeverity.MEDIUM)

  def test_ubsan_non_positive_vla_bound_value(self):
    """Tests severity analysis of a non-positive variable length array bound
    report given by UBSan function."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Non-positive-vla-bound-value',
            self._read_test_data('ubsan_non_positive_vla_bound_value.txt'),
            False), SecuritySeverity.MEDIUM)

  def test_ubsan_object_size(self):
    """Tests severity analysis of a object-size report given by UBSan
    function."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Object-size', self._read_test_data('ubsan_object_size.txt'),
            False), SecuritySeverity.MEDIUM)

  def test_cfi_bad_cast(self):
    """Tests severity analysis of a bad cast report given by CFI."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_generic').analyze(
            'Bad-cast', self._read_test_data('cfi_bad_cast.txt'), False),
        SecuritySeverity.HIGH)

  def test_msan_renderer(self):
    """Tests severity analysis of a MSan report in the renderer process."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_chrome').analyze(
            'Use-of-uninitialized-value',
            self._read_test_data('msan_renderer.txt'), False),
        SecuritySeverity.MEDIUM)

  def test_msan_browser(self):
    """Tests severity analysis of a MSan report in the browser process."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_chrome').analyze(
            'Use-of-uninitialized-value',
            self._read_test_data('msan_browser.txt'), False),
        SecuritySeverity.MEDIUM)

  def test_find_process_type_browser(self):
    """Tests a browser process bug is recognized as such."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_chrome').analyze(
            'Heap-use-after-free\nREAD 8',
            self._read_test_data('browser_uaf.txt'), False),
        SecuritySeverity.CRITICAL)

  def test_find_process_type_browser_2(self):
    """Tests a browser process bug is recognized as such (second variant)."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_chrome').analyze(
            'Heap-use-after-free\nREAD 8',
            self._read_test_data('browser_uaf2.txt'), False),
        SecuritySeverity.CRITICAL)

  def test_find_process_type_browser_3(self):
    """Tests a browser process bug is recognized as such (third variant)."""
    self.assertEqual(
        severity_analyzer.get_analyzer('sanitizer_chrome').analyze(
            'Heap-use-after-free\nREAD 8',
            self._read_test_data('browser_uaf3.txt'), False),
        SecuritySeverity.CRITICAL)

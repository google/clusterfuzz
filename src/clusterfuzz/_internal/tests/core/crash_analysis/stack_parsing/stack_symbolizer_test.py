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
"""Tests for the stack symbolizer module."""

import unittest

from clusterfuzz._internal.crash_analysis.stack_parsing import stack_symbolizer


class ChromeDsymHintsTests(unittest.TestCase):
  """Tests chrome_dsym_hints."""

  def test_standalone_executable(self):
    """Tests that standalone executable work as expected."""
    self.assertEqual([], stack_symbolizer.chrome_dsym_hints('/build/binary'))

  def test_standalone_framework_or_app(self):
    """Tests that standalone frame or app bundle work as expected."""
    self.assertEqual(
        ['/build/Content Shell.dSYM'],
        stack_symbolizer.chrome_dsym_hints('/build/Content Shell.app'))
    self.assertEqual(
        ['/build/Content Shell.dSYM'],
        stack_symbolizer.chrome_dsym_hints('/build/Content Shell.framework'))

  def test_nested_bundles(self):
    """Tests that two or three nested bundles work as expected."""
    self.assertEqual(
        ['/build/Content Shell Helper.dSYM'],
        stack_symbolizer.chrome_dsym_hints(
            '/build/Content Shell.app/Contents'
            '/Frameworks/Content Shell Framework.framework/Versions/C/Helpers'
            '/Content Shell Helper.app/Contents/MacOS/Content Shell Helper'))
    self.assertEqual(
        ['/build/Content Shell Helper.dSYM'],
        stack_symbolizer.chrome_dsym_hints(
            '/build/Content Shell.app/Contents'
            '/Versions/C/Helpers'
            '/Content Shell Helper.app/Contents/MacOS/Content Shell Helper'))

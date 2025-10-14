# Copyright 2025 Google LLC
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
"""Unicode minimizer unit tests."""

import re
import unittest

from clusterfuzz._internal.bot.minimizer import unicode_minimizer


def replace_unicode(data):

  def replacer(match):
    hex_code = match.group(1)
    code_point = int(hex_code, 16)
    # JS engines require UTF-8 encoded input.
    return chr(code_point).encode('utf-8')

  pattern = rb'\\u([0-9a-fA-F]{4})'
  return re.sub(pattern, replacer, data)


class UnicodeMinimizerTest(unittest.TestCase):
  """Helper class for unicode minimization"""

  def setUp(self):
    self.crash_programs = []
    self.no_crash_programs = []
    self._minimizer = unicode_minimizer.UnicodeMinimizer(
        self._mock_test_function)

  def _mock_test_function(self, data_file):
    data = open(data_file, 'rb').read()
    if data in self.crash_programs:
      return False
    if data in self.no_crash_programs:
      return True
    self.fail("Unreachable code")
    return True

  def test_minimize_simple_string(self):
    """Minimizer does not break on simple data."""
    data = b'simple'
    self.no_crash_programs.append(data)

    result = self._minimizer.minimize(data)

    self.assertEqual(result, data)

  def test_minimize_buggy_unicode_escape(self):
    """Program crashes because of \\u0045."""
    data = b'text \\u0045 text'
    self.crash_programs.append(data)
    self.no_crash_programs.append(replace_unicode(data))

    result = self._minimizer.minimize(data)

    self.assertEqual(result, b'text \\u0045 text')

  def test_minimize_not_buggy_unicode_escape(self):
    """Program crashes not because of \\u0047."""
    data = b'text \\u0047 text'
    self.crash_programs.append(data)
    self.crash_programs.append(replace_unicode(data))

    result = self._minimizer.minimize(data)

    self.assertEqual(result, b'text G text')

  def test_minimize_not_buggy_unicode_escape_not_ascii(self):
    """Program crashes not because of \\u0444."""
    data = b'text \\u0444 text'
    self.crash_programs.append(data)
    self.crash_programs.append(replace_unicode(data))

    result = self._minimizer.minimize(data)

    self.assertEqual(result.decode('utf-8'), 'text ф text')

  def test_minimize_buggy_unicode_escape_multi_unicode(self):
    """Program crashes because of \\u0045."""
    data = b'text \\u0045 text \\u0047 some text \\u0048 some other text \\u0049 yet another text'
    self.crash_programs.append(data)
    self.no_crash_programs.append(replace_unicode(data))

    result = self._minimizer.minimize(data)

    self.assertEqual(result, data)

  def test_minimize_not_buggy_unicode_escape_multi_unicode(self):
    """Program doesn't crash because of unicode"""
    data = b'text \\u0045 text \\u0047 some text \\u0048 some other text \\u0049 yet another text'
    self.crash_programs.append(data)
    self.crash_programs.append(replace_unicode(data))

    result = self._minimizer.minimize(data)

    self.assertEqual(
        result, b'text E text G some text H some other text I yet another text')

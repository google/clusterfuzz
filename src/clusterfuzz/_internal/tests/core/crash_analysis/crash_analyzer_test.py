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
"""crash_analyzer tests."""

import os
import unittest

from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class IgnoreStacktraceTest(unittest.TestCase):
  """Tests CrashComparer."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def test_search_excludes(self):
    """Test SEARCH_EXCLUDES env var works."""
    crash_stacktrace = ('aaa\nbbbbbbb\nccc\nddd\n\n')
    self.assertFalse(crash_analyzer.ignore_stacktrace(crash_stacktrace))

    os.environ['SEARCH_EXCLUDES'] = r'eeee'
    self.assertFalse(crash_analyzer.ignore_stacktrace(crash_stacktrace))

    os.environ['SEARCH_EXCLUDES'] = r'ccc'
    self.assertTrue(crash_analyzer.ignore_stacktrace(crash_stacktrace))

  def test_stack_blacklist_regexes(self):
    """Test stacktrace.stack_blacklist_regexes in project.yaml works."""

    def _mock_config_get(_, param):
      """Handle test configuration options."""
      if param == 'stacktrace.stack_blacklist_regexes':
        return [r'.*[c]{3}']
      return None

    test_helpers.patch(
        self, ['clusterfuzz._internal.config.local_config.ProjectConfig.get'])
    self.mock.get.side_effect = _mock_config_get

    crash_stacktrace = ('aaa\nbbbbbbb\nzzzccc\nddd\n\n')
    self.assertTrue(crash_analyzer.ignore_stacktrace(crash_stacktrace))

    crash_stacktrace = ('aaa\nbbbbbbb\nddd\n\n')
    self.assertFalse(crash_analyzer.ignore_stacktrace(crash_stacktrace))

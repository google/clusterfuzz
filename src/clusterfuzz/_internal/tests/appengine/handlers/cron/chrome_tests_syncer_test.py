# Copyright 2026 Google LLC
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
"""Tests for chrome_tests_syncer HTTP alias directory verification."""

import os

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.bot.webserver import http_server
from clusterfuzz._internal.cron import chrome_tests_syncer
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class VerifyHttpAliasTargetsTest(fake_filesystem_unittest.TestCase):
  """Tests for verify_http_alias_targets."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    helpers.patch(self, ['clusterfuzz._internal.metrics.logs.error'])
    self.targets = sorted(
        {t for _, targets in http_server.HTTP_ALIASES for t in targets})
    for target in self.targets:
      os.makedirs(os.path.join('/tests_dir', target), exist_ok=True)

  def test_valid_targets(self):
    """Ensure nothing is logged when all target directories exist."""
    chrome_tests_syncer.verify_http_alias_targets('/tests_dir')
    self.mock.error.assert_not_called()

  def test_missing_target_logs_error(self):
    """Ensure a missing alias target is logged as an error, not raised."""
    missing_target = max(self.targets, key=len)
    os.rmdir(os.path.join('/tests_dir', missing_target))
    chrome_tests_syncer.verify_http_alias_targets('/tests_dir')
    self.mock.error.assert_called_once()
    self.assertIn(missing_target, self.mock.error.call_args[0][0])

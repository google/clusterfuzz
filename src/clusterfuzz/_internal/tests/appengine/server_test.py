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
"""Tests for server module."""
import unittest

from clusterfuzz._internal.tests.test_libs import helpers


class ServerTest(unittest.TestCase):
  """Test server module is loaded."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs._is_running_on_app_engine',
    ])
    self.mock._is_running_on_app_engine.return_value = True  # pylint: disable=protected-access

  # pylint: disable=protected-access
  def test(self):
    import server
    self.assertIsNotNone(server.handlers)
    self.assertIsNotNone(server.cron_routes)
    self.assertIsNotNone(server.app)

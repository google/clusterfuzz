# Copyright 2024 Google LLC
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
"""Tests for wifi functions."""

import unittest

from clusterfuzz._internal.platforms.android import wifi
from clusterfuzz._internal.tests.test_libs import helpers


class ConfigureTest(unittest.TestCase):
  """Tests for wifi.configure."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.is_uworker',
        'clusterfuzz._internal.platforms.android.wifi.disable_airplane_mode',
        'clusterfuzz._internal.config.db_config.get',
    ])

  def test_uworker_bypass(self):
    """Test that uworker environment skips wifi setup."""
    self.mock.is_uworker.return_value = True

    wifi.configure()

    # Ensure none of the subsequent functions that crash/hit Datastore are called.
    self.mock.disable_airplane_mode.assert_not_called()
    self.mock.get.assert_not_called()

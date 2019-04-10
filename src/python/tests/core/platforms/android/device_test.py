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
"""Tests for device functions."""

from platforms.android import device
from tests.test_libs import android_helpers


class GetBatteryInformationTest(android_helpers.AndroidTest):
  """Tests get_battery_information."""

  def test(self):
    battery_info = device.get_battery_information()
    self.assertTrue(isinstance(battery_info, dict))
    self.assertTrue('level' in battery_info)
    self.assertTrue('temperature' in battery_info)
    self.assertTrue(battery_info['level'] > 0)
    self.assertTrue(battery_info['temperature'] > 0)

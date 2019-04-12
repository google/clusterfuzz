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

import os
import unittest

from platforms.android import device
from tests.test_libs import android_helpers
from tests.test_libs import helpers as test_helpers

DATA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'device_data')


def _read_data_file(filename):
  return open(os.path.join(DATA_PATH, filename)).read()


class GetBatteryInformationTest(android_helpers.AndroidTest):
  """Tests get_battery_information."""

  def test(self):
    """Ensure that get_battery_information returns data in the expected form."""
    battery_info = device.get_battery_information()
    self.assertTrue(isinstance(battery_info, dict))
    self.assertTrue('level' in battery_info)
    self.assertTrue('temperature' in battery_info)
    self.assertTrue(battery_info['level'] > 0)
    self.assertTrue(battery_info['temperature'] > 0)


class InitializeEnvironmentTest(android_helpers.AndroidTest):
  """Tests for """

  def test(self):
    """Ensure that initialize_environment throws no exceptions."""
    device.initialize_environment()


class GetCodenameTest(unittest.TestCase):
  """Tests for get_codename."""

  def setUp(self):
    test_helpers.patch(self, ['platforms.android.adb.run_adb_command'])
    test_helpers.patch_environ(self)

    output = _read_data_file('get_codename_output.txt')
    self.mock.run_adb_command.return_value = output

  def test_by_serial(self):
    """Ensure that we report the correct codename for serial number."""
    os.environ['ANDROID_SERIAL'] = '123456789012'
    self.assertEquals(device.get_codename(), 'device1')

  def test_by_usb(self):
    """Ensure that we report the correct codename for a usb device."""
    os.environ['ANDROID_SERIAL'] = 'usb:2-4.2'
    self.assertEquals(device.get_codename(), 'device2')

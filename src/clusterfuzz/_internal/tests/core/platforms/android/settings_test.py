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
"""Tests for app functions."""

import os
import unittest

from clusterfuzz._internal.platforms.android import settings
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

DATA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'settings_data')


def _read_data_file(filename):
  return open(os.path.join(DATA_PATH, filename)).read()


class GetDeviceCodenameTest(unittest.TestCase):
  """Tests for get_device_codename."""

  def setUp(self):
    test_helpers.patch(
        self, ['clusterfuzz._internal.platforms.android.adb.run_command'])
    test_helpers.patch_environ(self)

    output = _read_data_file('get_device_codename_output.txt')
    self.mock.run_command.return_value = output

  def test_by_serial(self):
    """Ensure that we report the correct codename for serial number."""
    os.environ['ANDROID_SERIAL'] = '123456789012'
    self.assertEqual(settings.get_device_codename(), 'device1')

  def test_by_usb(self):
    """Ensure that we report the correct codename for a usb device."""
    os.environ['ANDROID_SERIAL'] = 'usb:2-4.2'
    self.assertEqual(settings.get_device_codename(), 'device2')

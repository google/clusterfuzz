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
"""Tests for the Linux initialization script."""

import unittest

from bot.init_scripts import linux
from tests.test_libs import helpers


class RunTest(unittest.TestCase):
  """Test run."""

  def setUp(self):
    helpers.patch(self, [
        'distutils.spawn.find_executable',
        'bot.init_scripts.init_runner.run',
        'system.process_handler.terminate_processes_matching_names',
        'system.shell.start_dbus_daemon',
    ])

  def test_with_dbus(self):
    """Test init with dbus installed."""
    self.mock.find_executable.return_value = '/dbus-launch'
    linux.run()
    self.assertEqual(1, self.mock.run.call_count)
    self.mock.terminate_processes_matching_names.assert_called_with(
        ['dbus-daemon'])
    self.assertEqual(1, self.mock.start_dbus_daemon.call_count)

  def test_without_dbus(self):
    """Test init without dbus installed."""
    self.mock.find_executable.return_value = None
    linux.run()
    self.assertEqual(1, self.mock.run.call_count)
    self.assertEqual(0, self.mock.terminate_processes_matching_names.call_count)
    self.assertEqual(0, self.mock.start_dbus_daemon.call_count)

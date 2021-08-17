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
"""Tests for init_runner."""

import unittest

from clusterfuzz._internal.bot.init_scripts import init_runner
from clusterfuzz._internal.tests.test_libs import helpers


class InitRunnerTest(unittest.TestCase):
  """Tests for init_runner."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.platform',
        'clusterfuzz._internal.system.process_handler.run_process',
    ])

  def test_windows(self):
    """Test windows."""
    self.mock.platform.return_value = 'WINDOWS'
    init_runner.run()
    self.mock.run_process.assert_called_with(
        'powershell.exe ./configs/test/bot/init/windows.ps1',
        ignore_children=True,
        need_shell=True,
        testcase_run=False,
        timeout=1800)

  def test_posix(self):
    """Test posix."""
    self.mock.platform.return_value = 'LINUX'
    init_runner.run()
    self.mock.run_process.assert_called_with(
        './configs/test/bot/init/linux.bash',
        ignore_children=True,
        need_shell=True,
        testcase_run=False,
        timeout=1800)

  def test_nonexistent_platform(self):
    """Test posix."""
    self.mock.platform.return_value = 'FAKE'
    init_runner.run()
    self.assertEqual(0, self.mock.run_process.call_count)

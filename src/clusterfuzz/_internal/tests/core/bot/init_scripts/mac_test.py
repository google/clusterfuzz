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
"""Tests for the Mac initialization script."""

import unittest

import mock

from clusterfuzz._internal.bot.init_scripts import mac
from clusterfuzz._internal.tests.test_libs import helpers


class RunTest(unittest.TestCase):
  """Test run."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.init_scripts.init_runner.run',
        'os.path.expanduser',
        'clusterfuzz._internal.system.shell.remove_directory',
        'shutil.rmtree',
        'subprocess.Popen',
        'os.path.exists',
    ])
    self.popen = mock.Mock()
    self.stdout = []

    def readline():
      return self.stdout.pop(0)

    self.popen.stdout.readline = readline
    self.mock.Popen.return_value = self.popen

    def expanduser(path):
      return path.replace('~', '/Users/chrome-bot')

    self.mock.expanduser.side_effect = expanduser

  def test_run(self):
    """Test run."""
    self.stdout = [
        b'aaaa\n', b'bbbb\n',
        (b'Path: /var/folders/bg/tn9j_qb532s4fz11rzz7m6sc0000gm/0'
         b'//com.apple.LaunchServices-134500.csstore\n'), b'cccc\n', b''
    ]
    mac.run()

    self.mock.exists.return_value = True
    self.mock.rmtree.assert_has_calls([
        mock.call(
            '/var/folders/bg/tn9j_qb532s4fz11rzz7m6sc0000gm/0',
            ignore_errors=True),
        mock.call(
            '/var/folders/bg/tn9j_qb532s4fz11rzz7m6sc0000gm/T',
            ignore_errors=True)
    ])

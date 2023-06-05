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
"""Tests for the Windows initialization script."""

import unittest

from unittest import mock

from clusterfuzz._internal.bot.init_scripts import windows
from clusterfuzz._internal.tests.test_libs import helpers


class CleanTempDirectoriesTest(unittest.TestCase):
  """Test clean_temp_directories."""

  def setUp(self):
    helpers.patch(self, [
        'os.path.abspath',
        'os.path.expandvars',
        'os.path.join',
        'clusterfuzz._internal.system.shell.remove_directory',
    ])

    def abspath(path):
      return path

    def expandvars(path):
      path = path.replace('%TEMP%', r'C:\Users\clusterfuzz\AppData\Local\Temp')
      path = path.replace('%USERPROFILE%', r'C:\Users\clusterfuzz')
      path = path.replace('%WINDIR%', r'C:\WINDOWS')
      return path

    def join(path1, path2):
      """Windows specific os.path.join"""
      return r'%s\%s' % (path1.rstrip('\\'), path2)

    self.mock.abspath.side_effect = abspath
    self.mock.expandvars.side_effect = expandvars
    self.mock.join.side_effect = join

  def test(self):
    windows.clean_temp_directories()

    self.mock.remove_directory.assert_has_calls([
        mock.call(
            r'C:\Users\clusterfuzz\AppData\Local\Temp',
            recreate=True,
            ignore_errors=True),
        mock.call(
            r'C:\Users\clusterfuzz\AppVerifierLogs',
            recreate=True,
            ignore_errors=True),
        mock.call(
            r'C:\Users\clusterfuzz\Downloads',
            recreate=True,
            ignore_errors=True),
        mock.call(r'C:\WINDOWS\Temp', recreate=True, ignore_errors=True),
        mock.call(
            r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\sym',
            recreate=True,
            ignore_errors=True),
        mock.call(
            r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym',
            recreate=True,
            ignore_errors=True)
    ])

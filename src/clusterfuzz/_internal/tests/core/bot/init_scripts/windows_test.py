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

import mock

from clusterfuzz._internal.bot.init_scripts import windows
from clusterfuzz._internal.system import environment
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


class RemountIfNeededTest(unittest.TestCase):
  """Test remount_if_needed."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.log_error',
        'clusterfuzz._internal.base.retry.sleep',
        'clusterfuzz._internal.base.utils.write_data_to_file',
        'os.path.exists',
        'os.path.join',
        'subprocess.call',
        'subprocess.check_call',
    ])

    def join(path1, path2):
      """Windows specific os.path.join"""
      return r'%s\%s' % (path1.rstrip('\\'), path2)

    self.mock.join.side_effect = join

    environment.set_value('NFS_HOST', 'clusterfuzz-windows-0001')
    environment.set_value('NFS_VOLUME', 'cfvolume')
    environment.set_value('NFS_ROOT', 'X:\\')

  def test_with_mount_and_with_check_file(self):
    """Test remount_if_needed when mount works and check file already exists."""
    self.mock.exists.return_value = True
    windows.remount_if_needed()

    self.assertEqual(0, self.mock.call.call_count)
    self.assertEqual(0, self.mock.check_call.call_count)
    self.assertEqual(0, self.mock.write_data_to_file.call_count)

  def test_without_mount_and_without_check_file_no_retry(self):
    """Test remount_if_needed when mount and check file do not exist and gets
    created later on successful remount."""
    self.mock.exists.side_effect = [False, False, True]
    windows.remount_if_needed()

    self.mock.call.assert_called_once_with(['umount', '-f', 'X:\\'])
    self.mock.check_call.assert_called_once_with([
        'mount', '-o', 'anon', '-o', 'nolock', '-o', 'retry=10',
        'clusterfuzz-windows-0001:/cfvolume', 'X:\\'
    ])
    self.mock.write_data_to_file.assert_called_once_with('ok', r'X:\check')

  def test_without_mount_and_with_check_file_no_retry(self):
    """Test remount_if_needed when mount does not exist, but check file does and
    check file does not get recreated later on successful remount."""
    self.mock.exists.side_effect = [False, True]
    windows.remount_if_needed()

    self.mock.call.assert_called_once_with(['umount', '-f', 'X:\\'])
    self.mock.check_call.assert_called_once_with([
        'mount', '-o', 'anon', '-o', 'nolock', '-o', 'retry=10',
        'clusterfuzz-windows-0001:/cfvolume', 'X:\\'
    ])
    self.assertEqual(0, self.mock.write_data_to_file.call_count)

  def test_without_mount_and_without_check_file_retry(self):
    """Test remount_if_needed when check file does not exist and gets created
    later on second remount try."""
    self.mock.exists.side_effect = [False, False, False, False, True]
    windows.remount_if_needed()

    self.mock.call.assert_has_calls([mock.call(['umount', '-f', 'X:\\'])] * 2)
    self.mock.check_call.assert_has_calls([
        mock.call([
            'mount', '-o', 'anon', '-o', 'nolock', '-o', 'retry=10',
            'clusterfuzz-windows-0001:/cfvolume', 'X:\\'
        ])
    ] * 2)
    self.mock.write_data_to_file.assert_called_once_with('ok', r'X:\check')

  def test_without_check_file_fail(self):
    """Test remount_if_needed when check file does not exist and does not get
    recreated due to remount failure."""
    self.mock.exists.side_effect = [False, False, False] * 6

    with self.assertRaises(Exception):
      windows.remount_if_needed()

    self.mock.call.assert_has_calls([mock.call(['umount', '-f', 'X:\\'])] * 6)
    self.mock.check_call.assert_has_calls([
        mock.call([
            'mount', '-o', 'anon', '-o', 'nolock', '-o', 'retry=10',
            'clusterfuzz-windows-0001:/cfvolume', 'X:\\'
        ])
    ] * 6)
    self.mock.write_data_to_file.assert_has_calls(
        [mock.call('ok', r'X:\check')] * 6)

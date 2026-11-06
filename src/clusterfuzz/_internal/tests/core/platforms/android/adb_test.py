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
"""Tests for adb functions."""

import os
import tempfile
import unittest
from unittest import mock

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.platforms.android import constants
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import android_helpers
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class CopyLocalDirectoryToRemoteTest(android_helpers.AndroidTest):
  """Tests copy_local_directory_to_remote."""

  def setUp(self):
    super().setUp()

    # Clear and create temporary directory on device.
    self.device_temp_dir = constants.DEVICE_TMP_DIR
    adb.remove_directory(self.device_temp_dir, recreate=True)

    # Create local temp directory.
    self.local_temp_dir = tempfile.mkdtemp()

  def tearDown(self):
    adb.remove_directory(self.device_temp_dir)
    shell.remove_directory(self.local_temp_dir)

  def test(self):
    """Tests copy_local_directory_to_remote."""
    utils.write_data_to_file('a', os.path.join(self.local_temp_dir, 'a'))
    shell.create_directory(os.path.join(self.local_temp_dir, 'b'))
    utils.write_data_to_file('c', os.path.join(self.local_temp_dir, 'b', 'c'))

    adb.copy_local_directory_to_remote(self.local_temp_dir,
                                       self.device_temp_dir)

    self.assertTrue(adb.file_exists(os.path.join(self.device_temp_dir, 'a')))
    self.assertFalse(
        adb.directory_exists(os.path.join(self.device_temp_dir, 'a')))
    self.assertEqual(
        adb.get_file_size(os.path.join(self.device_temp_dir, 'a')), 1)

    self.assertTrue(
        adb.directory_exists(os.path.join(self.device_temp_dir, 'b')))
    self.assertFalse(adb.file_exists(os.path.join(self.device_temp_dir, 'b')))

    self.assertTrue(
        adb.file_exists(os.path.join(self.device_temp_dir, 'b', 'c')))
    self.assertFalse(
        adb.directory_exists(os.path.join(self.device_temp_dir, 'b', 'c')))
    self.assertEqual(
        adb.get_file_size(os.path.join(self.device_temp_dir, 'b', 'c')), 1)


class CopyRemoteDirectoryToLocalTest(android_helpers.AndroidTest):
  """Tests copy_remote_directory_to_local."""

  def setUp(self):
    super().setUp()

    # Clear and create temporary directory on device.
    self.device_temp_dir = constants.DEVICE_TMP_DIR
    adb.remove_directory(self.device_temp_dir, recreate=True)

    # Create local temp directory.
    self.local_temp_dir = tempfile.mkdtemp()

  def tearDown(self):
    adb.remove_directory(self.device_temp_dir)
    shell.remove_directory(self.local_temp_dir)

  def test(self):
    """Tests copy_remote_directory_to_local."""
    adb.write_data_to_file('a', os.path.join(self.device_temp_dir, 'a'))
    adb.create_directory_if_needed(os.path.join(self.device_temp_dir, 'b'))
    adb.write_data_to_file('c', os.path.join(self.device_temp_dir, 'b', 'c'))

    adb.copy_remote_directory_to_local(self.device_temp_dir,
                                       self.local_temp_dir)

    self.assertTrue(os.path.exists(os.path.join(self.local_temp_dir, 'a')))
    self.assertTrue(os.path.isfile(os.path.join(self.local_temp_dir, 'a')))
    self.assertEqual(os.path.getsize(os.path.join(self.local_temp_dir, 'a')), 1)

    self.assertTrue(os.path.exists(os.path.join(self.local_temp_dir, 'b')))
    self.assertTrue(os.path.isdir(os.path.join(self.local_temp_dir, 'b')))

    self.assertTrue(os.path.exists(os.path.join(self.local_temp_dir, 'b', 'c')))
    self.assertTrue(os.path.isfile(os.path.join(self.local_temp_dir, 'b', 'c')))
    self.assertEqual(
        os.path.getsize(os.path.join(self.local_temp_dir, 'b', 'c')), 1)


class ReadDataFromFileTest(android_helpers.AndroidTest):
  """Tests read_data_from_file."""

  def setUp(self):
    super().setUp()

    # Clear and create temporary directory on device.
    self.device_temp_dir = constants.DEVICE_TMP_DIR
    adb.remove_directory(self.device_temp_dir, recreate=True)

  def tearDown(self):
    adb.remove_directory(self.device_temp_dir)

  def test_non_existent_file(self):
    """Test that we return None when file does not exist."""
    non_existent_file_path = os.path.join(self.device_temp_dir, 'non-existent')
    self.assertEqual(adb.read_data_from_file(non_existent_file_path), None)

  def test_regular_file(self):
    """Test that file data is read from regular file."""
    test_file_path = os.path.join(self.device_temp_dir, 'a')
    adb.write_data_to_file('a' * 5000, test_file_path)
    self.assertEqual(adb.read_data_from_file(test_file_path), 'a' * 5000)


class WriteDataToFileTest(android_helpers.AndroidTest):
  """Tests write_data_to_file."""

  def setUp(self):
    super().setUp()

    # Clear and create temporary directory on device.
    self.device_temp_dir = constants.DEVICE_TMP_DIR
    adb.remove_directory(self.device_temp_dir, recreate=True)

  def tearDown(self):
    adb.remove_directory(self.device_temp_dir)

  def test_regular_file(self):
    """Test that file data is written."""
    test_file_path = os.path.join(self.device_temp_dir, 'a')
    adb.write_data_to_file('a' * 5000, test_file_path)
    self.assertEqual(adb.read_data_from_file(test_file_path), 'a' * 5000)


class GetFileSizeTest(android_helpers.AndroidTest):
  """Tests get_file_size."""

  def test_nonexistent_file(self):
    """Tests that file size is None for a non-existent file."""
    self.assertFalse(adb.file_exists('/sdcard/non-existent'))
    self.assertIsNone(adb.get_file_size('/sdcard/non-existent'))

  def test_regular_file(self):
    """Test that file size is properly calculated for regular files."""
    adb.write_data_to_file('abcd', '/sdcard/file1')
    self.assertTrue(adb.file_exists('/sdcard/file1'))
    self.assertEqual(adb.get_file_size('/sdcard/file1'), 4)


class GetFileChecksumTest(android_helpers.AndroidTest):
  """Tests get_file_checksum."""

  def test_nonexistent_file(self):
    """Tests that checksum is None for a non-existent file."""
    self.assertFalse(adb.file_exists('/sdcard/non-existent'))
    self.assertIsNone(adb.get_file_checksum('/sdcard/non-existent'))

  def test_regular_file(self):
    """Test that checksum is properly calculated for regular files."""
    adb.write_data_to_file('abcd', '/sdcard/file1')
    self.assertTrue(adb.file_exists('/sdcard/file1'))
    self.assertEqual(
        adb.get_file_checksum('/sdcard/file1'),
        'e2fc714c4727ee9395f324cd2e7f331f')


class GetPSOutputTest(android_helpers.AndroidTest):
  """Tests get_ps_output."""

  def test(self):
    """Test that ps output is parseable for pid and ppids."""
    ps_output = adb.get_ps_output()
    ps_output_lines = ps_output.splitlines()[1:]  # Skip column line.
    for line in ps_output_lines:
      values = line.split()
      self.assertTrue(values[1].isdigit())  # PID.
      self.assertTrue(values[2].isdigit())  # PPID


class WaitForDeviceTest(android_helpers.AndroidTest):
  """Tests for wait_for_device."""

  def test_state_correct_after_wait(self):
    """Ensure that the function works correctly when a device is connected."""
    adb.wait_for_device()
    self.assertEqual(adb.get_device_state(), 'device')


class ResetUsbTest(android_helpers.AndroidTest):
  """Tests for reset_usb."""

  def setUp(self):
    super().setUp()
    test_helpers.patch(self, ['fcntl.ioctl'])

  def test_with_device(self):
    """Tests reset_usb with a connected device if available."""
    self.assertTrue(adb.reset_usb())


class ResetSafetyTest(unittest.TestCase):
  """Unit tests for hard_reset and factory_reset."""

  def setUp(self):
    super().setUp()
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.adb.bad_state_reached',
        'clusterfuzz._internal.platforms.android.adb.execute_command',
        'clusterfuzz._internal.platforms.android.adb.execute_command_with_return_code',
        'clusterfuzz._internal.platforms.android.adb.get_adb_command_line',
        'clusterfuzz._internal.platforms.android.adb.revert_asan_device_setup_if_needed',
        'clusterfuzz._internal.platforms.android.adb.run_as_root',
        'clusterfuzz._internal.platforms.android.adb.run_shell_command',
        'clusterfuzz._internal.system.environment.is_android_cuttlefish',
        'clusterfuzz._internal.system.environment.is_android_emulator',
        'time.sleep',
    ])
    self.mock.bad_state_reached.side_effect = SystemExit
    self.mock.is_android_cuttlefish.return_value = False
    self.mock.is_android_emulator.return_value = False
    self.mock.get_adb_command_line.side_effect = lambda cmd: f'adb -s ser {cmd}'

  def test_hard_reset_skips_sysrq_when_graceful_reboot_succeeds(self):
    """Test that hard_reset syncs then reboots and skips sysrq-trigger on 0."""
    self.mock.execute_command_with_return_code.return_value = (
        0, '* daemon not running\n* daemon started successfully')
    call_order = mock.Mock()
    call_order.attach_mock(self.mock.execute_command, 'execute_command')
    call_order.attach_mock(self.mock.execute_command_with_return_code,
                           'execute_command_with_return_code')

    adb.hard_reset()

    self.assertEqual(call_order.mock_calls, [
        mock.call.execute_command(
            'adb -s ser shell sync', timeout=adb.GET_DEVICE_STATE_TIMEOUT),
        mock.call.execute_command_with_return_code(
            'adb -s ser reboot', timeout=adb.RECOVERY_CMD_TIMEOUT),
    ])
    self.mock.run_shell_command.assert_not_called()

  def test_hard_reset_falls_back_to_root_sysrq_when_reboot_fails(self):
    """Test fallback to root sysrq-trigger on non-zero exit, timeout, or error."""
    failure_results = [
        (1, 'error: device offline'),
        (None, None),
        (0, 'reboot (adb) failed'),
        (0, 'reboot: Connection timed out'),
    ]
    for result in failure_results:
      with self.subTest(result=result):
        self.mock.run_shell_command.reset_mock()
        self.mock.execute_command_with_return_code.return_value = result

        adb.hard_reset()

        self.mock.run_shell_command.assert_called_once_with(
            'echo b > /proc/sysrq-trigger',
            root=True,
            timeout=adb.RECOVERY_CMD_TIMEOUT,
            recover=False)

  def test_factory_reset_avoids_master_clear_on_physical_device(self):
    """Test that factory_reset calls bad_state_reached on physical devices."""
    with self.assertRaises(SystemExit):
      adb.factory_reset()

    self.mock.revert_asan_device_setup_if_needed.assert_called_once()
    self.mock.bad_state_reached.assert_called_once()
    self.mock.run_shell_command.assert_not_called()

  def test_factory_reset_runs_master_clear_on_emulator(self):
    """Test that factory_reset still broadcasts MASTER_CLEAR on emulators."""
    self.mock.is_android_emulator.return_value = True

    adb.factory_reset()

    self.mock.bad_state_reached.assert_not_called()
    self.mock.run_as_root.assert_called_once()
    self.mock.run_shell_command.assert_called_once()
    self.assertIn('android.intent.action.MASTER_CLEAR',
                  self.mock.run_shell_command.call_args[0][0])

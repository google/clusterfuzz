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
import subprocess
import tempfile
import unittest

from clusterfuzz._internal.platforms.android import device
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import android_helpers
from clusterfuzz._internal.tests.test_libs import helpers


class InitializeEnvironmentTest(android_helpers.AndroidTest):
  """Tests for the device environment initialization process (`initialize_environment`)."""

  def test(self):
    """Ensure that initialize_environment throws no exceptions."""
    device.initialize_environment()


class InitializeDeviceRebootLogicTest(unittest.TestCase):
  """Tests the reboot batching logic in initialize_device."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.is_engine_fuzzer_job',
        'clusterfuzz._internal.platforms.android.adb.setup_adb',
        'clusterfuzz._internal.platforms.android.adb.run_as_root',
        'clusterfuzz._internal.platforms.android.device.configure_system_build_properties',
        'clusterfuzz._internal.platforms.android.device.configure_device_settings',
        'clusterfuzz._internal.platforms.android.device.add_test_accounts_if_needed',
        'clusterfuzz._internal.platforms.android.sanitizer.setup_asan_if_needed',
        'clusterfuzz._internal.platforms.android.device.reboot',
        'clusterfuzz._internal.platforms.android.wifi.configure',
        'clusterfuzz._internal.platforms.android.device.setup_host_and_device_forwarder_if_needed',
        'clusterfuzz._internal.platforms.android.settings.change_se_linux_to_permissive_mode',
        'clusterfuzz._internal.platforms.android.app.wait_until_optimization_complete',
        'clusterfuzz._internal.platforms.android.ui.clear_notifications',
        'clusterfuzz._internal.platforms.android.ui.unlock_screen',
    ])
    self.mock.is_engine_fuzzer_job.return_value = False

  def test_reboot_if_asan_did_not_run(self):
    """Test that `initialize_device()` calls `reboot()` if the ASan setup
    script did not."""
    self.mock.setup_asan_if_needed.return_value = False

    device.initialize_device()
    self.mock.reboot.assert_called_once()

  def test_no_reboot_if_asan_ran(self):
    """Test that `initialize_device()` skips calling `reboot()` if the ASan
    setup script did."""
    self.mock.setup_asan_if_needed.return_value = True

    device.initialize_device()
    self.mock.reboot.assert_not_called()


class AddTestAccountsIfNeededTest(unittest.TestCase):
  """Tests for add_test_accounts_if_needed."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.is_uworker',
        'clusterfuzz._internal.base.persistent_cache.get_value',
    ])

  def test_uworker_bypass(self):
    """Test that uworker environment skips test account setup."""
    self.mock.is_uworker.return_value = True
    device.add_test_accounts_if_needed()
    self.mock.get_value.assert_not_called()


class NeedsNoStreamingForAsanTest(unittest.TestCase):
  """Tests _needs_no_streaming_for_asan."""

  # pylint: disable=protected-access

  def setUp(self):
    super().setUp()
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.settings.get_sanitizer_tool_name',
    ])
    self.mock.get_sanitizer_tool_name.return_value = None

  def test_normal_job(self):
    """Test outcome for a normal job."""
    self.assertFalse(device._needs_no_streaming_for_asan())

  def test_asan_job(self):
    """Test outcome for an ASan job."""
    environment.set_value('JOB_NAME', 'android_asan_job')
    self.assertTrue(device._needs_no_streaming_for_asan())

  def test_hwasan_job(self):
    """Test outcome for a non ASAN job like HWASan."""
    environment.set_value('JOB_NAME', 'android_hwasan_job')
    self.assertFalse(device._needs_no_streaming_for_asan())

  def test_asan_device_env(self):
    """Test outcome for an ASan device via ASAN_DEVICE_SETUP env."""
    environment.set_value('ASAN_DEVICE_SETUP', True)
    self.assertTrue(device._needs_no_streaming_for_asan())

  def test_asan_device_flavor(self):
    """Test outcome for an ASan device via settings build flavor."""
    self.mock.get_sanitizer_tool_name.return_value = 'asan'
    self.assertTrue(device._needs_no_streaming_for_asan())


class ClearTestcaseDirectoryTest(unittest.TestCase):
  """Tests clear_testcase_directory."""

  def setUp(self):
    super().setUp()
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.adb.run_shell_command',
        'clusterfuzz._internal.platforms.android.app.get_testcases_directory',
    ])

  def test_targets_the_testcases_directory_as_root(self):
    """Test that the directory reported by app.get_testcases_directory() is the
    one cleared, and that it is cleared as root. Which path that resolves to
    (APK scoped storage vs. the shared fallback) is covered by app_test."""
    self.mock.get_testcases_directory.return_value = (
        '/sdcard/Android/data/com.google.chrome/files')

    device.clear_testcase_directory()

    args, kwargs = self.mock.run_shell_command.call_args
    self.assertIn('/sdcard/Android/data/com.google.chrome/files', args[0])
    self.assertTrue(kwargs['root'])

  def test_propagates_adb_failure(self):
    """Test that an adb failure while clearing the directory is not swallowed,
    so the caller can react to a device in a bad state."""
    self.mock.get_testcases_directory.return_value = '/sdcard/fuzzer-testcases'
    self.mock.run_shell_command.side_effect = RuntimeError('device offline')

    with self.assertRaises(RuntimeError):
      device.clear_testcase_directory()


@unittest.skipUnless(
    environment.is_posix(),
    'Runs the emitted shell command against the local filesystem, which '
    'requires a POSIX shell and find command.')
class ClearTestcaseDirectorySemanticsTest(unittest.TestCase):
  """Tests what the command emitted by clear_testcase_directory actually does
  to a directory, by running it against the local filesystem."""

  def setUp(self):
    super().setUp()
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.adb.run_shell_command',
        'clusterfuzz._internal.platforms.android.app.get_testcases_directory',
    ])

  def _run_emitted_command(self):
    """Executes the shell command that was handed to adb against the local
    filesystem, mimicking the device shell, and returns its exit code."""
    self.mock.run_shell_command.assert_called_once()
    command = self.mock.run_shell_command.call_args[0][0]
    return subprocess.run(
        command, shell=True, check=False, capture_output=True).returncode

  def _populate(self, directory):
    """Fills |directory| with entries that a glob based delete would miss."""
    os.makedirs(os.path.join(directory, 'subdir'))
    os.makedirs(os.path.join(directory, '.hidden_dir'))
    for path in [
        'visible.txt',
        '.hidden.txt',
        os.path.join('subdir', 'nested.txt'),
        os.path.join('.hidden_dir', 'nested.txt'),
    ]:
      with open(os.path.join(directory, path), 'w') as handle:
        handle.write('testcase')

  def test_removes_all_contents_including_hidden_entries(self):
    """Test that every entry is removed, hidden ones included. A glob based
    `rm -rf <dir>/*` would leave dotfiles behind, leaking testcases from the
    previous run into the next one."""
    with tempfile.TemporaryDirectory() as testcases_directory:
      self.mock.get_testcases_directory.return_value = testcases_directory
      self._populate(testcases_directory)

      device.clear_testcase_directory()

      self.assertEqual(0, self._run_emitted_command())
      self.assertEqual([], os.listdir(testcases_directory))

  def test_preserves_the_directory_itself(self):
    """Test that only the contents are deleted. `-mindepth 1` keeps the
    directory in place, so the next run does not have to recreate it."""
    with tempfile.TemporaryDirectory() as testcases_directory:
      self.mock.get_testcases_directory.return_value = testcases_directory
      self._populate(testcases_directory)

      device.clear_testcase_directory()

      self.assertEqual(0, self._run_emitted_command())
      self.assertTrue(os.path.isdir(testcases_directory))

  def test_succeeds_on_empty_directory(self):
    """Test that clearing an already empty directory is a successful no-op,
    since `clear_testcase_directory` runs before every fuzzing session."""
    with tempfile.TemporaryDirectory() as testcases_directory:
      self.mock.get_testcases_directory.return_value = testcases_directory

      device.clear_testcase_directory()

      self.assertEqual(0, self._run_emitted_command())
      self.assertTrue(os.path.isdir(testcases_directory))
      self.assertEqual([], os.listdir(testcases_directory))

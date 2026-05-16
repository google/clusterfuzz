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

import unittest
from unittest import mock

from clusterfuzz._internal.platforms.android import device
from clusterfuzz._internal.tests.test_libs import android_helpers


class InitializeEnvironmentTest(android_helpers.AndroidTest):
  """Tests for """

  def test(self):
    """Ensure that initialize_environment throws no exceptions."""
    device.initialize_environment()


class InitializeDeviceRebootLogicTest(unittest.TestCase):
  """Tests the reboot batching logic in initialize_device."""

  def setUp(self):
    # Mock environment to bypass the engine fuzzer check
    mock.patch('clusterfuzz._internal.system.environment.is_engine_fuzzer_job', 
               return_value=False).start()
    
    # Mock all the setup steps so we don't actually run ADB commands
    self.mock_setup_adb = mock.patch('clusterfuzz._internal.platforms.android.adb.setup_adb').start()
    self.mock_run_as_root = mock.patch('clusterfuzz._internal.platforms.android.adb.run_as_root').start()
    self.mock_config_props = mock.patch('clusterfuzz._internal.platforms.android.device.configure_system_build_properties').start()
    self.mock_config_settings = mock.patch('clusterfuzz._internal.platforms.android.device.configure_device_settings').start()
    self.mock_add_accounts = mock.patch('clusterfuzz._internal.platforms.android.device.add_test_accounts_if_needed').start()
    self.mock_setup_asan = mock.patch('clusterfuzz._internal.platforms.android.sanitizer.setup_asan_if_needed').start()
    
    # Mock the reboot function we are trying to track
    self.mock_reboot = mock.patch('clusterfuzz._internal.platforms.android.device.reboot').start()
    
    # Mock the post-reboot steps
    mock.patch('clusterfuzz._internal.platforms.android.wifi.configure').start()
    mock.patch('clusterfuzz._internal.platforms.android.device.setup_host_and_device_forwarder_if_needed').start()
    mock.patch('clusterfuzz._internal.platforms.android.settings.change_se_linux_to_permissive_mode').start()
    mock.patch('clusterfuzz._internal.platforms.android.app.wait_until_optimization_complete').start()
    mock.patch('clusterfuzz._internal.platforms.android.ui.clear_notifications').start()
    mock.patch('clusterfuzz._internal.platforms.android.ui.unlock_screen').start()

  def tearDown(self):
    mock.patch.stopall()

  def test_reboot_if_props_changed(self):
    """Test that it reboots if build.prop changed, even if ASan didn't run."""
    self.mock_config_props.return_value = True
    self.mock_setup_asan.return_value = False
    
    device.initialize_device()
    self.mock_reboot.assert_called_once()

  def test_no_reboot_if_asan_ran(self):
    """Test that the final reboot is skipped if ASan setup performed a shell restart."""
    # If build.prop didn't change, the ASan restart handles the clean state.
    self.mock_config_props.return_value = False 
    self.mock_setup_asan.return_value = True
    
    device.initialize_device()
    self.mock_reboot.assert_not_called()

  def test_reboot_if_clean_slate_needed(self):
    """Test that it still reboots to ensure a clean state if no other steps restarted it."""
    self.mock_config_props.return_value = False
    self.mock_setup_asan.return_value = False
    
    device.initialize_device()
    self.mock_reboot.assert_called_once()


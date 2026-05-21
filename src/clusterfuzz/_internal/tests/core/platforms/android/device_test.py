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

from clusterfuzz._internal.platforms.android import device
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
    from clusterfuzz._internal.tests.test_libs import helpers
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.is_uworker',
        'clusterfuzz._internal.base.persistent_cache.get_value',
    ])

  def test_uworker_bypass(self):
    """Test that uworker environment skips test account setup."""
    self.mock.is_uworker.return_value = True
    device.add_test_accounts_if_needed()
    self.mock.get_value.assert_not_called()

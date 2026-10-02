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
from unittest import mock
from unittest import TestCase

from clusterfuzz._internal.platforms.android import app
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import android_helpers
from clusterfuzz._internal.tests.test_libs import helpers


class IsInstalledTest(android_helpers.AndroidTest):
  """Tests is_installed."""

  def test_nonexistent_package_not_installed(self):
    """Ensure that a non-existent package is not installed."""
    self.assertFalse(app.is_installed('non.existent.package'))

  def test_partial_package_name_not_installed(self):
    """Test that com.google is not recognized as an installed package."""
    self.assertFalse(app.is_installed('com.google'))

  def test_package_installed(self):
    """Ensure that gms (which should always be available) is installed."""
    self.assertTrue(app.is_installed('com.google.android.gms'))


class GetPackageNameTest(android_helpers.AndroidTest):
  """Tests get_package_name."""

  def setUp(self):
    super().setUp()

    root_dir = environment.get_value('ROOT_DIR')
    self.test_apk_path = os.path.join(root_dir, 'resources', 'platform',
                                      'android', 'wifi_util.apk')
    self.test_apk_pkg_name = 'com.android.tradefed.utils.wifi'

  def test_pkg_name_in_env(self):
    """Test package name already set in |PKG_NAME| env."""
    environment.set_value('PKG_NAME', 'a.b.c')
    self.assertEqual(app.get_package_name(), 'a.b.c')

  def test_apk_path_in_app_path_env(self):
    """Test apk path set in |APP_PATH| env variable."""
    environment.set_value('APP_PATH', self.test_apk_path)
    self.assertEqual(app.get_package_name(), self.test_apk_pkg_name)

  def test_apk_path_in_arg(self):
    """Test apk path passed as argument."""
    self.assertEqual(
        app.get_package_name(self.test_apk_path), self.test_apk_pkg_name)


class InstallTest(TestCase):
  """Tests install."""

  def setUp(self):
    super().setUp()
    helpers.patch_environ(self)
    self.run_command_patcher = mock.patch(
        'clusterfuzz._internal.platforms.android.adb.run_command')
    self.mock_run_command = self.run_command_patcher.start()
    self.addCleanup(self.run_command_patcher.stop)

  def test_install_normal(self):
    """Test normal installation without any additional flags."""
    app.install('/path/to/app.apk')
    self.mock_run_command.assert_called_once_with(
        ['install', '-r', '/path/to/app.apk'])

  def test_install_with_additional_flags(self):
    """Test installation with additional flags."""
    app.install('/path/to/app.apk', g=True, t=True)
    self.mock_run_command.assert_called_once_with(
        ['install', '-r', '-g', '-t', '/path/to/app.apk'])

  def test_install_with_valued_flags(self):
    """Test installation with flags that take string/numeric values."""
    app.install('/path/to/app.apk', abi='x86', no_streaming=True)
    self.mock_run_command.assert_called_once_with(
        ['install', '-r', '--abi', 'x86', '--no-streaming', '/path/to/app.apk'])


class GetTestcasesDirectoryTest(TestCase):
  """Tests app.get_testcases_directory."""

  def setUp(self):
    super().setUp()
    helpers.patch_environ(self)

  def test_apk_package_uses_app_scoped_storage(self):
    """Tests that, when an APK package name is resolvable, testcases are placed
    inside that package's scoped storage dir (/sdcard/Android/data/<pkg>/files),
    which is the only external location an Android 11+ app can read from."""
    environment.set_value('PKG_NAME', 'com.google.chrome')
    self.assertEqual(app.get_testcases_directory(),
                     '/sdcard/Android/data/com.google.chrome/files')

  def test_no_package_name_uses_shared_fallback_directory(self):
    """Tests that, when no package name is set (non-APK fuzzing, e.g. a native
    binary target), the shared /sdcard/fuzzer-testcases directory is returned
    instead of a malformed '/sdcard/Android/data//files' path."""
    environment.set_value('PKG_NAME', None)
    self.assertEqual(app.get_testcases_directory(), '/sdcard/fuzzer-testcases')

  def test_non_apk_app_path_uses_shared_fallback_directory(self):
    """Tests that an APP_PATH pointing at a non-APK target (from which no
    package name can be derived) also falls back to /sdcard/fuzzer-testcases,
    rather than attempting to build a scoped storage path."""
    environment.set_value('APP_PATH', '/path/to/native_fuzzer')
    self.assertEqual(app.get_testcases_directory(), '/sdcard/fuzzer-testcases')

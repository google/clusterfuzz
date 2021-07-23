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

from clusterfuzz._internal.platforms.android import app
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import android_helpers


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
    super(GetPackageNameTest, self).setUp()

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

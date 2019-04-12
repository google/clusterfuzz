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

from base import utils
from platforms.android import adb
from system import environment
from system import shell
from tests.test_libs import android_helpers
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


class CopyLocalDirectoryToRemoteTest(android_helpers.AndroidTest):
  """Tests copy_local_directory_to_remote."""

  def setUp(self):
    super(CopyLocalDirectoryToRemoteTest, self).setUp()

    # Clear and create temporary directory on device.
    self.device_temp_dir = adb.DEVICE_TMP_DIR
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
    super(CopyRemoteDirectoryToLocalTest, self).setUp()

    # Clear and create temporary directory on device.
    self.device_temp_dir = adb.DEVICE_TMP_DIR
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
    super(ReadDataFromFileTest, self).setUp()

    # Clear and create temporary directory on device.
    self.device_temp_dir = adb.DEVICE_TMP_DIR
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
    super(WriteDataToFileTest, self).setUp()

    # Clear and create temporary directory on device.
    self.device_temp_dir = adb.DEVICE_TMP_DIR
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


class IsPackageInstalledTest(android_helpers.AndroidTest):
  """Tests is_package_installed."""

  def test_nonexistent_package_not_installed(self):
    """Ensure that a non-existent package is not installed."""
    self.assertFalse(adb.is_package_installed('non.existent.package'))

  def test_partial_package_name_not_installed(self):
    """Test that com.google is not recognized as an installed package."""
    self.assertFalse(adb.is_package_installed('com.google'))

  def test_package_installed(self):
    """Ensure that gms (which should always be available) is installed."""
    self.assertTrue(adb.is_package_installed('com.google.android.gms'))


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
    self.assertEqual(adb.get_package_name(), 'a.b.c')

  def test_apk_path_in_app_path_env(self):
    """Test apk path set in |APP_PATH| env variable."""
    environment.set_value('APP_PATH', self.test_apk_path)
    self.assertEqual(adb.get_package_name(), self.test_apk_pkg_name)

  def test_apk_path_in_arg(self):
    """Test apk path passed as argument."""
    self.assertEqual(
        adb.get_package_name(self.test_apk_path), self.test_apk_pkg_name)


class ResetUsbTest(android_helpers.AndroidTest):
  """Tests for reset_usb."""

  def setUp(self):
    super(ResetUsbTest, self).setUp()
    test_helpers.patch(self, ['fcntl.ioctl'])

  def test_with_device(self):
    """Tests reset_usb with a connected device if available."""
    self.assertTrue(adb.reset_usb())

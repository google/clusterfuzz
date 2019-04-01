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

from base import utils
from platforms.android import adb
from system import environment
from system import shell
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.android_device_required
class TestFileOperations(unittest.TestCase):
  """Tests for various functions that depend on file transfer."""

  def setUp(self):
    test_helpers.patch_environ(self)

    # Set Android specific environment variables like DEVICE_TMP_DIR, etc.
    environment.set_value('OS_OVERRIDE', 'ANDROID')
    environment.set_bot_environment()

    # Clear and create temporary directory on device.
    self.device_temp_dir = adb.DEVICE_TMP_DIR
    adb.remove_directory(self.device_temp_dir, recreate=True)

    # Create local temp directory.
    self.local_temp_dir = tempfile.mkdtemp()

    # Run adb as root.
    adb.run_as_root()

  def tearDown(self):
    adb.remove_directory(self.device_temp_dir)
    shell.remove_directory(self.local_temp_dir)

  def test_directory_exists(self):
    """Tests directory_exists."""
    utils.write_data_to_file('a', os.path.join(self.local_temp_dir, 'a'))
    shell.create_directory(os.path.join(self.local_temp_dir, 'b'))
    utils.write_data_to_file('c', os.path.join(self.local_temp_dir, 'b', 'c'))

    adb.copy_local_directory_to_remote(self.local_temp_dir,
                                       self.device_temp_dir)

    existent_file_path_remote = os.path.join(self.device_temp_dir, 'a')
    existent_directory_path_remote = os.path.join(self.device_temp_dir, 'b')
    non_existent_file_path_remote = os.path.join(self.device_temp_dir, 'd')
    non_existent_directory_path_remote = os.path.join(self.device_temp_dir, 'e')

    self.assertFalse(adb.directory_exists(existent_file_path_remote))
    self.assertTrue(adb.directory_exists(existent_directory_path_remote))
    self.assertFalse(adb.directory_exists(non_existent_file_path_remote))
    self.assertFalse(adb.directory_exists(non_existent_directory_path_remote))

  def test_file_exists(self):
    """Tests file_exists."""
    utils.write_data_to_file('a', os.path.join(self.local_temp_dir, 'a'))
    shell.create_directory(os.path.join(self.local_temp_dir, 'b'))
    utils.write_data_to_file('c', os.path.join(self.local_temp_dir, 'b', 'c'))

    adb.copy_local_directory_to_remote(self.local_temp_dir,
                                       self.device_temp_dir)

    existent_file_path_remote = os.path.join(self.device_temp_dir, 'a')
    existent_directory_path_remote = os.path.join(self.device_temp_dir, 'b')
    non_existent_file_path_remote = os.path.join(self.device_temp_dir, 'd')
    non_existent_directory_path_remote = os.path.join(self.device_temp_dir, 'e')

    self.assertTrue(adb.file_exists(existent_file_path_remote))
    self.assertFalse(adb.file_exists(existent_directory_path_remote))
    self.assertFalse(adb.file_exists(non_existent_file_path_remote))
    self.assertFalse(adb.file_exists(non_existent_directory_path_remote))

  def test_copy_local_directory_to_remote(self):
    """Tests copy_local_directory_to_remote."""
    utils.write_data_to_file('a', os.path.join(self.local_temp_dir, 'a'))
    shell.create_directory(os.path.join(self.local_temp_dir, 'b'))
    utils.write_data_to_file('c', os.path.join(self.local_temp_dir, 'b', 'c'))
    adb.copy_local_directory_to_remote(self.local_temp_dir,
                                       self.device_temp_dir)

    self.assertTrue(adb.file_exists(os.path.join(self.device_temp_dir, 'a')))
    self.assertTrue(
        adb.directory_exists(os.path.join(self.device_temp_dir, 'b')))
    self.assertTrue(
        adb.file_exists(os.path.join(self.device_temp_dir, 'b', 'c')))

  def test_copy_remote_directory_to_local(self):
    """Tests copy_remote_directory_to_local."""
    adb.write_data_to_file('a', os.path.join(self.device_temp_dir, 'a'))
    adb.create_directory_if_needed(os.path.join(self.device_temp_dir, 'b'))
    adb.write_data_to_file('c', os.path.join(self.device_temp_dir, 'b', 'c'))

    adb.copy_remote_directory_to_local(self.device_temp_dir,
                                       self.local_temp_dir)

    self.assertTrue(os.path.exists(os.path.join(self.local_temp_dir, 'a')))
    self.assertTrue(os.path.isfile(os.path.join(self.local_temp_dir, 'a')))
    self.assertTrue(os.path.exists(os.path.join(self.local_temp_dir, 'b')))
    self.assertTrue(os.path.isdir(os.path.join(self.local_temp_dir, 'b')))
    self.assertTrue(os.path.exists(os.path.join(self.local_temp_dir, 'b', 'c')))
    self.assertTrue(os.path.isfile(os.path.join(self.local_temp_dir, 'b', 'c')))

  def test_read_data_from_file_and_write_data_to_file(self):
    """Tests read_data_from_file and write_data_to_file."""
    test_file_path = os.path.join(self.device_temp_dir, 'a')
    self.assertEqual(adb.read_data_from_file(test_file_path), None)
    adb.write_data_to_file('data', test_file_path)
    self.assertEqual(adb.read_data_from_file(test_file_path), 'data')


@test_utils.android_device_required
class WaitForDeviceTest(unittest.TestCase):
  """Tests for wait_for_device."""

  def test_state_correct_after_wait(self):
    """Ensures that the function works correctly when a device is connected."""
    adb.wait_for_device()
    self.assertEqual(adb.get_device_state(), 'device')


@test_utils.android_device_required
class IsPackageInstalledTest(unittest.TestCase):
  """Tests for is_package_installed."""

  def test_nonexistent_package_not_installed(self):
    """Ensure that a non-existent package is not installed."""
    self.assertFalse(adb.is_package_installed('non.existent.package'))

  def test_partial_package_name_not_installed(self):
    """Tests that com.google is not recognized as an installed package."""
    self.assertFalse(adb.is_package_installed('com.google'))

  def test_package_installed(self):
    """Ensures that gms (which should always be available) is installed."""
    self.assertTrue(adb.is_package_installed('com.google.android.gms'))

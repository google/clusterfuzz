# Copyright 2026 Google LLC
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
"""Tests local library resolution and mirrored device pull paths."""

import os
import tempfile
import unittest
from unittest import mock

from clusterfuzz._internal.platforms.android import symbols_downloader
from clusterfuzz._internal.tests.test_libs import helpers


class FilterBinaryPathTest(unittest.TestCase):
  """Tests resolving device library paths to local copies for symbolization."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.adb.run_command',
        ('fetch_artifact_get',
         'clusterfuzz._internal.platforms.android.fetch_artifact.get'),
        'clusterfuzz._internal.platforms.android.settings.is_google_device',
    ])
    temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(temp_dir.cleanup)
    self.build_dir = os.path.join(temp_dir.name, 'build')
    self.symbols_dir = os.path.join(temp_dir.name, 'symbols')

  def test_build_dir_library(self):
    """Verifies that libraries bundled with the build are resolved directly
    without device pulls or remote fetches."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['LOCAL_DEVELOPMENT'] = 'True'

    library_path = os.path.join(self.build_dir, 'lib64', 'libfoo.so')
    os.makedirs(os.path.dirname(library_path), exist_ok=True)
    with open(library_path, 'wb'):
      pass

    actual_path = symbols_downloader.filter_binary_path(
        '/system/lib64/libfoo.so')

    self.assertEqual(library_path, actual_path)
    self.mock.run_command.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()

  def test_cached_device_library(self):
    """Verifies that a previously pulled device library is reused locally
    without pulling it again."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['LOCAL_DEVELOPMENT'] = 'True'
    self.mock.is_google_device.return_value = True

    cached_path = os.path.join(self.symbols_dir, 'system/lib64/libfoo.so')
    os.makedirs(os.path.dirname(cached_path), exist_ok=True)
    with open(cached_path, 'wb'):
      pass

    actual_path = symbols_downloader.filter_binary_path(
        '/system/lib64/libfoo.so')

    self.assertEqual(cached_path, actual_path)
    self.assertTrue(os.path.exists(cached_path))
    self.mock.run_command.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()

  def test_adb_pulled_libraries(self):
    """Verifies that libraries pulled from the device keep their full paths so
    same-named libraries do not collide across frames."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['LOCAL_DEVELOPMENT'] = 'True'
    self.mock.is_google_device.return_value = True

    def create_pulled_file(cmd):
      local_path = cmd.split()[-1]
      with open(local_path, 'wb'):
        pass

    self.mock.run_command.side_effect = create_pulled_file
    expected_lib32 = os.path.join(self.symbols_dir, 'system/lib/libc.so')
    expected_lib64 = os.path.join(self.symbols_dir, 'system/lib64/libc.so')

    self.assertEqual(
        expected_lib32,
        symbols_downloader.filter_binary_path('/system/lib/libc.so'))
    self.assertEqual(
        expected_lib64,
        symbols_downloader.filter_binary_path('/system/lib64/libc.so'))
    self.assertEqual([
        mock.call('pull /system/lib/libc.so %s' % expected_lib32),
        mock.call('pull /system/lib64/libc.so %s' % expected_lib64),
    ], self.mock.run_command.call_args_list)

    # Subsequent frames reuse the pulled files without running adb pull again.
    self.mock.run_command.reset_mock()
    self.assertEqual(
        expected_lib32,
        symbols_downloader.filter_binary_path('/system/lib/libc.so'))
    self.assertEqual(
        expected_lib64,
        symbols_downloader.filter_binary_path('/system/lib64/libc.so'))
    self.mock.run_command.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()

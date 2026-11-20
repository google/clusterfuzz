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
import shlex
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
    self.temp_dir = os.path.realpath(temp_dir.name)
    self.build_dir = os.path.join(self.temp_dir, 'build')
    self.symbols_dir = os.path.join(self.temp_dir, 'symbols')

  def test_build_dir_library(self):
    """Libraries found in BUILD_DIR are returned without adb pull or remote
    symbol downloads."""
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
    """A library already at its mirrored SYMBOLS_DIR path is reused instead
    of being pulled from the device again."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['LOCAL_DEVELOPMENT'] = 'True'

    cached_path = os.path.join(self.symbols_dir, 'system/lib64/libfoo.so')
    os.makedirs(os.path.dirname(cached_path), exist_ok=True)
    with open(cached_path, 'wb'):
      pass

    actual_path = symbols_downloader.filter_binary_path(
        '/system/lib64/libfoo.so')

    self.assertEqual(cached_path, actual_path)
    self.mock.run_command.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()

  def test_adb_pulled_libraries(self):
    """Same-named libraries from different device dirs are pulled to separate
    mirrored paths instead of overwriting each other."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['LOCAL_DEVELOPMENT'] = 'True'

    def create_pulled_file(cmd):
      local_path = shlex.split(cmd)[-1]
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
        mock.call(f'pull -- /system/lib/libc.so {shlex.quote(expected_lib32)}'),
        mock.call(
            f'pull -- /system/lib64/libc.so {shlex.quote(expected_lib64)}'),
    ], self.mock.run_command.call_args_list)

  def test_unsafe_paths_are_not_pulled(self):
    """Paths with '..' segments or null bytes return '' without an adb pull or
    any file written outside SYMBOLS_DIR."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['LOCAL_DEVELOPMENT'] = 'True'

    unsafe_paths = [
        '/../../escape.so',
        '/system/../../../escape.so',
        '/system/lib64/..',
        '/system/lib64/bad\x00.so',
    ]
    for path in unsafe_paths:
      with self.subTest(path=path):
        self.assertEqual('', symbols_downloader.filter_binary_path(path))

    self.mock.run_command.assert_not_called()
    self.assertFalse(os.path.exists(self.symbols_dir))
    self.assertFalse(os.path.exists(os.path.join(self.temp_dir, 'escape.so')))

  def test_dots_inside_file_name_are_pulled(self):
    """A '..' inside a file name (libfoo..so) is not a path traversal, so the
    library is still pulled."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['LOCAL_DEVELOPMENT'] = 'True'

    def create_pulled_file(cmd):
      with open(shlex.split(cmd)[-1], 'wb'):
        pass

    self.mock.run_command.side_effect = create_pulled_file
    expected_path = os.path.join(self.symbols_dir, 'system/lib64/libfoo..so')

    self.assertEqual(
        expected_path,
        symbols_downloader.filter_binary_path('/system/lib64/libfoo..so'))
    self.mock.run_command.assert_called_once()

  def test_quotes_adb_pull_arguments(self):
    """Device paths with spaces or shell metacharacters reach adb pull as a
    single quoted argument."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['LOCAL_DEVELOPMENT'] = 'True'

    crafted_path = "/system/lib64/my lib;id$(uname)'q.so"
    expected_local_path = os.path.join(self.symbols_dir,
                                       crafted_path.lstrip('/'))

    def create_pulled_file(cmd):
      args = shlex.split(cmd)
      self.assertEqual(['pull', '--', crafted_path, expected_local_path], args)
      with open(args[-1], 'wb'):
        pass

    self.mock.run_command.side_effect = create_pulled_file
    self.assertEqual(expected_local_path,
                     symbols_downloader.filter_binary_path(crafted_path))
    self.mock.run_command.assert_called_once()

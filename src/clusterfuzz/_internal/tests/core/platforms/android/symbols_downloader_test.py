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
"""Tests for Android symbols_downloader."""

import os
import tempfile
import unittest
from unittest import mock

from clusterfuzz._internal.crash_analysis.stack_parsing import stack_symbolizer
from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.platforms.android import symbols_downloader
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class FilterBinaryPathSafetyTest(unittest.TestCase):
  """Tests binary path validation and adb pull safety in symbols_downloader."""

  def setUp(self):
    super().setUp()
    test_helpers.patch_environ(self)
    self.temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp_dir.cleanup)

    self.build_dir = os.path.join(self.temp_dir.name, 'build')
    self.symbols_dir = os.path.join(self.temp_dir.name, 'symbols dir')
    os.makedirs(self.build_dir)
    os.makedirs(self.symbols_dir)

    os.environ['ADB'] = '/usr/bin/adb'
    os.environ['ANDROID_SERIAL'] = 'emulator-5554'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir

    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.adb.execute_command',
        'clusterfuzz._internal.platforms.android.symbols_downloader.'
        'ensure_system_symbols',
        'clusterfuzz._internal.system.environment.is_android',
    ])
    self.mock.ensure_system_symbols.return_value = False
    self.mock.is_android.return_value = True
    self.mock.execute_command.return_value = ''

  def test_rejects_malicious_and_malformed_binary_paths(self):
    """Tests that metacharacters, traversals, and option-like names fail."""
    invalid_paths = [
        '',
        'relative/libfoo.so',
        '[stack:1234]',
        '/data/local/tmp/libfoo.so (deleted)',
        '/system/lib64/libc.so\n',
        '/a; id;',
        '/a $(id)',
        '/a `id`',
        '/system/lib64/lib foo.so',
        '/system/lib64/-z',
        '/data/local/tmp/.cached_build_params',
        '/system/lib64/.hidden.so',
        '//system/lib64/libc.so',
        '/system//lib64/libc.so',
        '/',
        '/system/lib64/',
        '/system/../data/misc/adb/adb_keys',
        '/system/./lib64/libc.so',
        '/system/lib64/..',
        '/system/lib64/"quoted".so',
        "/system/lib64/'quoted'.so",
    ]
    for path in invalid_paths:
      with self.subTest(path=path):
        self.assertEqual('', symbols_downloader.filter_binary_path(path))
        self.assertIsNone(
            symbols_downloader._get_binary_from_build_or_device(path))  # pylint: disable=protected-access

    self.mock.execute_command.assert_not_called()

  def test_does_not_escape_to_host_filesystem_paths(self):
    """Tests that /tmp or host binaries do not match outside symbol dirs."""
    for host_path in ('/tmp', '/bin/sh', '/etc/passwd'):
      with self.subTest(host_path=host_path):
        self.mock.execute_command.reset_mock()
        result = symbols_downloader.filter_binary_path(host_path)
        self.assertEqual('', result)
        self.mock.execute_command.assert_called_once()

  def test_pulls_valid_android_binary_with_quoted_list_args(self):
    """Tests valid Android device paths pass an explicit pull argv list."""
    device_paths = [
        '/init',
        '/system/lib64/libc++.so',
        '/apex/com.android.runtime/lib64/bionic/libc.so',
        '/data/app/~~abc_123==-XYZ==/org.chromium.chrome-1/lib/arm64/libcr.so',
        '/vendor/lib64/hw/android.hardware.graphics.mapper@4.0-impl.so',
    ]
    for device_path in device_paths:
      with self.subTest(device_path=device_path):
        self.mock.execute_command.reset_mock()
        expected_local = os.path.join(self.symbols_dir, device_path.lstrip('/'))

        def create_pulled_file(cmd, timeout=None, local_path=expected_local):
          del cmd, timeout
          with open(local_path, 'wb') as handle:
            handle.write(b'\x7fELF')
          return ''

        self.mock.execute_command.side_effect = create_pulled_file
        result = symbols_downloader.filter_binary_path(device_path)
        self.assertEqual(expected_local, result)

        host_cmd = self.mock.execute_command.call_args[0][0]
        argv = adb._build_host_command_args(  # pylint: disable=protected-access
            host_cmd,
            on_cuttlefish_host=False)
        self.assertEqual([
            '/usr/bin/adb', '-s', 'emulator-5554', 'pull', device_path,
            expected_local
        ], argv)

  def test_ignores_directory_targets(self):
    """Tests that existing directory entries skip adb pull and return empty."""
    os.makedirs(
        os.path.join(self.symbols_dir, 'data', 'local', 'tmp', 'dir_target'))
    os.makedirs(
        os.path.join(self.build_dir, 'data', 'local', 'tmp', 'dir_target'))

    result = symbols_downloader.filter_binary_path('/data/local/tmp/dir_target')
    self.assertEqual('', result)
    self.mock.execute_command.assert_not_called()

  def test_stack_symbolizer_line_with_injected_command_does_not_run_adb(self):
    """Tests the b/565097191 stack trace payload end-to-end through filter."""
    loop = stack_symbolizer.SymbolizationLoop(
        binary_path_filter=stack_symbolizer.filter_binary_path)
    _, _, binary, _, _ = loop._line_parser(  # pylint: disable=protected-access
        '    #0 0x1234 (/a; id;+0x1234)')
    self.assertEqual('/a; id;', binary)
    self.assertEqual('', stack_symbolizer.filter_binary_path(binary))
    self.mock.execute_command.assert_not_called()


class GetBinaryFromBuildOrDeviceTest(unittest.TestCase):
  """Tests resolving device library paths to local copies for symbolization."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.adb.run_command',
        ('fetch_artifact_get',
         'clusterfuzz._internal.platforms.android.fetch_artifact.get'),
        'clusterfuzz._internal.platforms.android.settings.get_build_parameters',
        'clusterfuzz._internal.platforms.android.settings.is_google_device',
    ])
    temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(temp_dir.cleanup)
    self.temp_dir = os.path.realpath(temp_dir.name)
    self.build_dir = os.path.join(self.temp_dir, 'build')
    self.symbols_dir = os.path.join(self.temp_dir, 'symbols')

  def test_build_dir_library_on_uworker(self):
    """On uworkers, libraries found in BUILD_DIR are returned without adb pull
    or remote symbol downloads."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)

    library_path = os.path.join(self.build_dir, 'lib64', 'libfoo.so')
    os.makedirs(os.path.dirname(library_path), exist_ok=True)
    with open(library_path, 'wb'):
      pass

    actual_path = symbols_downloader.filter_binary_path(
        '/system/lib64/libfoo.so')

    self.assertEqual(library_path, actual_path)
    self.mock.run_command.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()

  def test_cached_device_library_on_uworker(self):
    """On uworkers, a library already at its mirrored SYMBOLS_DIR path is
    reused instead of being pulled from the device again."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)

    cached_path = os.path.join(self.symbols_dir, 'system/lib64/libfoo.so')
    os.makedirs(os.path.dirname(cached_path), exist_ok=True)
    with open(cached_path, 'wb'):
      pass

    actual_path = symbols_downloader.filter_binary_path(
        '/system/lib64/libfoo.so')

    self.assertEqual(cached_path, actual_path)
    self.mock.run_command.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()

  def test_adb_pulled_libraries_on_uworker(self):
    """On uworkers, same-named libraries from different device dirs are pulled
    to separate mirrored paths instead of overwriting each other."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)

    def create_pulled_file(cmd):
      with open(cmd[-1], 'wb'):
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
        mock.call(['pull', '/system/lib/libc.so', expected_lib32]),
        mock.call(['pull', '/system/lib64/libc.so', expected_lib64]),
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
      with open(cmd[-1], 'wb'):
        pass

    self.mock.run_command.side_effect = create_pulled_file
    expected_path = os.path.join(self.symbols_dir, 'system/lib64/libfoo..so')

    self.assertEqual(
        expected_path,
        symbols_downloader.filter_binary_path('/system/lib64/libfoo..so'))
    self.mock.run_command.assert_called_once()

  def test_missing_library_on_uworker(self):
    """On uworkers, a library missing locally returns '' after only an adb
    pull attempt, with no remote symbol download."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)

    actual_path = symbols_downloader.filter_binary_path(
        '/system/lib64/libfoo.so')

    self.assertEqual('', actual_path)
    self.mock.run_command.assert_called_once()
    self.mock.fetch_artifact_get.assert_not_called()

  def test_missing_library_on_regular_bot(self):
    """On regular bots, a library missing locally returns '' after both a
    remote symbol download and an adb pull attempt."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ.pop('UWORKER', None)
    os.environ.pop('LOCAL_DEVELOPMENT', None)
    self.mock.is_google_device.return_value = True
    self.mock.get_build_parameters.return_value = {
        'build_id': '1234567',
        'target': 'cheetah',
        'type': 'userdebug',
    }

    actual_path = symbols_downloader.filter_binary_path(
        '/system/lib64/libfoo.so')

    self.assertEqual('', actual_path)
    self.mock.fetch_artifact_get.assert_called_once()
    self.mock.run_command.assert_called_once()

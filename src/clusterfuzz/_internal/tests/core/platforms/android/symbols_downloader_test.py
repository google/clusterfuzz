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
    self.symbols_dir = os.path.join(self.temp_dir.name, 'symbols')
    os.makedirs(self.build_dir)
    os.makedirs(self.symbols_dir)

    os.environ['ADB'] = '/usr/bin/adb'
    os.environ['ANDROID_SERIAL'] = 'emulator-5554'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir

    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.adb.execute_command',
        'clusterfuzz._internal.platforms.android.symbols_downloader.'
        'download_system_symbols_if_needed',
        'clusterfuzz._internal.system.environment.is_android',
    ])
    self.mock.is_android.return_value = True
    self.mock.execute_command.return_value = ''

  def test_rejects_malicious_and_malformed_binary_paths(self):
    """Tests that metacharacters, traversals, dotfiles, and pseudo-fs fail."""
    invalid_paths = [
        '',
        'relative/libfoo.so',
        '[stack:1234]',
        '/data/local/tmp/libfoo.so (deleted)',
        '/a; id;',
        '/a $(id)',
        '/a `id`',
        '/system/lib64/lib foo.so',
        '/system/lib64/-z',
        '/data/local/tmp/.cached_build_params',
        '/system/lib64/.hidden.so',
        '//system/lib64/libc.so',
        '/system//lib64/libc.so',
        '/dev/zero',
        '/dev/ashmem/dalvik-jit-code-cache',
        '/proc/kmsg',
        '/sys/kernel/notes',
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

  def test_resolves_build_symbols_including_apex_basename_fallback(self):
    """Tests subpath and basename lookup for extracted build symbols."""
    cached_direct = os.path.join(self.symbols_dir, 'system', 'lib64', 'libc.so')
    os.makedirs(os.path.dirname(cached_direct))
    with open(cached_direct, 'wb') as handle:
      handle.write(b'\x7fELF')

    apex_symbol = os.path.join(self.symbols_dir, 'out', 'symbols', 'apex',
                               'com.google.android.art', 'lib64', 'libart.so')
    os.makedirs(os.path.dirname(apex_symbol))
    with open(apex_symbol, 'wb') as handle:
      handle.write(b'\x7fELF')

    self.assertEqual(
        cached_direct,
        symbols_downloader.filter_binary_path('/system/lib64/libc.so'))
    # Mounted APEX / randomized /data/app paths resolve via basename fallback
    # against extracted build symbols.
    self.assertEqual(
        apex_symbol,
        symbols_downloader.filter_binary_path(
            '/apex/com.android.art/lib64/libart.so'))
    self.mock.execute_command.assert_not_called()

  def test_pulls_valid_android_binary_into_device_subdir_with_argv_list(self):
    """Tests that valid Android device paths pull into SYMBOLS_DIR/device/."""
    # Pre-create <symbols_dir>/system directory to ensure pulling a binary named
    # 'system' (e.g. /data/local/tmp/system) does not collide with it.
    os.makedirs(os.path.join(self.symbols_dir, 'system'), exist_ok=True)

    device_paths = [
        '/init',
        '/system/lib64/libc++.so',
        '/system/lib/libc++.so',
        '/data/local/tmp/system',
        '/apex/com.android.runtime/lib64/bionic/libc.so',
        '/data/app/~~abc_123==-XYZ==/org.chromium.chrome-1/lib/arm64/libcr.so',
        '/vendor/lib64/hw/android.hardware.graphics.mapper@4.0-impl.so',
    ]
    for device_path in device_paths:
      with self.subTest(device_path=device_path):
        self.mock.execute_command.reset_mock()
        expected_local = os.path.abspath(
            os.path.join(self.symbols_dir, 'device', device_path.lstrip('/')))

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

  def test_ignores_pulled_directory_target(self):
    """Tests that existing directory entries skip adb pull and return empty."""
    os.makedirs(
        os.path.join(self.symbols_dir, 'device', 'data', 'local', 'tmp',
                     'dir_target'))
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

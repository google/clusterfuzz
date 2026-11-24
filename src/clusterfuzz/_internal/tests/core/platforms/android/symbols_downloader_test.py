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
        'clusterfuzz._internal.platforms.android.adb.'
        'execute_command_with_return_code',
        'clusterfuzz._internal.platforms.android.symbols_downloader.'
        'download_system_symbols_if_needed',
        'clusterfuzz._internal.system.environment.is_android',
    ])
    self.mock.is_android.return_value = True
    self.mock.execute_command_with_return_code.return_value = (1, '')

  def test_rejects_malicious_and_malformed_binary_paths(self):
    """Tests that metacharacters, traversals, dotfiles, and bad roots fail."""
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
        '/dev/zero',
        '/dev/ashmem/dalvik-jit-code-cache',
        '/proc/kmsg',
        '/sys/kernel/notes',
        '/d/tracing/trace_pipe',
        '/data',
        '/system',
        '/vendor',
        '/data/misc/adb/adb_keys',
        '/tmp',
        '/bin/sh',
        '/etc/passwd',
        '/',
        '/system/lib64/',
        '/system/../data/misc/adb/adb_keys',
        '/system/./lib64/libc.so',
        '/system/lib64/..',
        '/system/lib64/"quoted".so',
        "/system/lib64/'quoted'.so",
        '/data/app/!libfoo.so',
        '/data/app/base.apk!',
        '/data/app/base.apk!.hidden.so',
        '/data/app/base.apk!a!b.so',
    ]
    for path in invalid_paths:
      with self.subTest(path=path):
        self.assertEqual('', symbols_downloader.filter_binary_path(path))
        self.assertIsNone(
            symbols_downloader._get_binary_from_build_or_device(path))  # pylint: disable=protected-access

    self.mock.execute_command_with_return_code.assert_not_called()

  def test_does_not_escape_to_host_filesystem_paths(self):
    """Tests that /tmp or host binaries do not match outside symbol dirs."""
    for host_path in ('/tmp', '/bin/sh', '/etc/passwd'):
      with self.subTest(host_path=host_path):
        self.mock.execute_command_with_return_code.reset_mock()
        result = symbols_downloader.filter_binary_path(host_path)
        self.assertEqual('', result)
        self.mock.execute_command_with_return_code.assert_not_called()

  def test_resolves_build_symbols_with_fast_path_and_multilib_apex(self):
    """Tests product symbols fast path and 32/64-bit APEX basename matching."""
    product_sym = os.path.join(self.symbols_dir, 'out', 'target', 'product',
                               'oriole', 'symbols', 'system', 'lib64',
                               'libframework.so')
    os.makedirs(os.path.dirname(product_sym))
    with open(product_sym, 'wb') as handle:
      handle.write(b'\x7fELF64FW')

    apex_32 = os.path.join(self.symbols_dir, 'out', 'target', 'product',
                           'oriole', 'symbols', 'apex',
                           'com.google.android.art', 'lib', 'libart.so')
    apex_64 = os.path.join(self.symbols_dir, 'out', 'target', 'product',
                           'oriole', 'symbols', 'apex',
                           'com.google.android.art', 'lib64', 'libart.so')
    os.makedirs(os.path.dirname(apex_32))
    os.makedirs(os.path.dirname(apex_64))
    with open(apex_32, 'wb') as handle:
      handle.write(b'\x7fELF32')
    with open(apex_64, 'wb') as handle:
      handle.write(b'\x7fELF64')

    self.assertEqual(
        product_sym,
        symbols_downloader.filter_binary_path('/system/lib64/libframework.so'))
    # Although 'lib' sorts before 'lib64', /lib64/ frame must pick 64-bit ELF
    # and /lib/ frame must pick 32-bit ELF.
    self.assertEqual(
        apex_64,
        symbols_downloader.filter_binary_path(
            '/apex/com.android.art/lib64/libart.so'))
    self.assertEqual(
        apex_32,
        symbols_downloader.filter_binary_path(
            '/apex/com.android.art/lib/libart.so'))
    self.mock.execute_command_with_return_code.assert_not_called()

  def test_pulls_valid_android_binary_atomically_into_device_subdir(self):
    """Tests validated atomic pulls into SYMBOLS_DIR/device/."""
    os.makedirs(os.path.join(self.symbols_dir, 'system'), exist_ok=True)

    device_paths = [
        ('/init', '/init'),
        ('/sbin/ueventd', '/sbin/ueventd'),
        ('/system/lib64/libc++.so', '/system/lib64/libc++.so'),
        ('/system/lib/libc++.so', '/system/lib/libc++.so'),
        ('/system/bin/linker64', '/apex/com.android.runtime/bin/linker64'),
        ('/data/local/tmp/system', '/data/local/tmp/system'),
        ('/data/app/~~abc_123==-XYZ==/org.chromium.chrome-1/lib/arm64/libcr.so',
         '/data/app/~~abc_123==-XYZ==/org.chromium.chrome-1/lib/arm64/libcr.so'
        ),
        ('/vendor/lib64/hw/android.hardware.graphics.mapper@4.0-impl.so',
         '/vendor/lib64/hw/android.hardware.graphics.mapper@4.0-impl.so'),
    ]
    for device_path, resolved_target in device_paths:
      with self.subTest(device_path=device_path):
        self.mock.execute_command_with_return_code.reset_mock()
        expected_local = os.path.abspath(
            os.path.join(self.symbols_dir, 'device', device_path.lstrip('/')))

        def fake_adb_exec(cmd,
                          timeout=None,
                          on_cuttlefish_host=False,
                          target=resolved_target):
          del timeout, on_cuttlefish_host
          argv = adb._build_host_command_args(  # pylint: disable=protected-access
              cmd,
              on_cuttlefish_host=False)
          if argv[3] == 'shell':
            return 0, f'{target}\n'
          self.assertEqual(['/usr/bin/adb', '-s', 'emulator-5554', 'pull'],
                           argv[:4])
          self.assertEqual(target, argv[4])
          with open(argv[5], 'wb') as handle:
            handle.write(b'\x7fELF')
          return 0, ''

        self.mock.execute_command_with_return_code.side_effect = fake_adb_exec
        result = symbols_downloader.filter_binary_path(device_path)
        self.assertEqual(expected_local, result)
        self.assertEqual(2,
                         self.mock.execute_command_with_return_code.call_count)

  def test_blocks_symlinks_resolving_to_disallowed_device_targets(self):
    """Tests that symlinks to /sys, /proc, /dev, or /data/misc do not pull."""
    disallowed_targets = [
        '/sys/kernel/debug/tracing/trace_pipe',
        '/proc/kmsg',
        '/dev/zero',
        '/data/misc/adb/adb_keys',
    ]
    for target in disallowed_targets:
      with self.subTest(target=target):
        self.mock.execute_command_with_return_code.reset_mock()
        self.mock.execute_command_with_return_code.return_value = (0, target)
        result = symbols_downloader.filter_binary_path(
            '/data/local/tmp/symlink.so')
        self.assertEqual('', result)
        # Only the shell realpath check ran; adb pull was never invoked.
        self.mock.execute_command_with_return_code.assert_called_once()

  def test_failed_or_bogus_nested_pull_does_not_poison_cache(self):
    """Tests failed pulls neither create parent dirs nor cache partial files."""
    # Step 1: Bogus nested path /system/lib64/libc.so/foo fails on device check.
    self.mock.execute_command_with_return_code.return_value = (1, '')
    self.assertEqual(
        '', symbols_downloader.filter_binary_path('/system/lib64/libc.so/foo'))
    libc_host_path = os.path.join(self.symbols_dir, 'device', 'system', 'lib64',
                                  'libc.so')
    self.assertFalse(os.path.exists(libc_host_path))

    # Step 2: Interrupted pull writes partial bytes to temp file but exits 1.
    def interrupted_pull(cmd, timeout=None, on_cuttlefish_host=False):
      del timeout, on_cuttlefish_host
      argv = adb._build_host_command_args(  # pylint: disable=protected-access
          cmd, on_cuttlefish_host=False)
      if argv[3] == 'shell':
        return 0, '/system/lib64/libc.so\n'
      with open(argv[5], 'wb') as handle:
        handle.write(b'\x7fE')
      return 1, 'adb: error: failed to copy'

    self.mock.execute_command_with_return_code.side_effect = interrupted_pull
    self.assertEqual(
        '', symbols_downloader.filter_binary_path('/system/lib64/libc.so'))
    self.assertFalse(os.path.exists(libc_host_path))

    # Step 3: Subsequent healthy pull of /system/lib64/libc.so succeeds cleanly.
    def healthy_pull(cmd, timeout=None, on_cuttlefish_host=False):
      del timeout, on_cuttlefish_host
      argv = adb._build_host_command_args(  # pylint: disable=protected-access
          cmd, on_cuttlefish_host=False)
      if argv[3] == 'shell':
        return 0, '/system/lib64/libc.so\n'
      with open(argv[5], 'wb') as handle:
        handle.write(b'\x7fELF_FULL')
      return 0, ''

    self.mock.execute_command_with_return_code.side_effect = healthy_pull
    self.assertEqual(
        os.path.abspath(libc_host_path),
        symbols_downloader.filter_binary_path('/system/lib64/libc.so'))

  def test_apk_embedded_bang_path_skips_adb_pull_and_checks_local_symbols(self):
    """Tests base.apk!libchrome.so skips adb pull and resolves local symbols."""
    apk_bang_path = (
        '/data/app/~~abc==/org.chromium.chrome-1/base.apk!libchrome.so')
    self.assertEqual('', symbols_downloader.filter_binary_path(apk_bang_path))
    self.mock.execute_command_with_return_code.assert_not_called()

    local_sym = os.path.join(self.build_dir, 'lib.unstripped', 'libchrome.so')
    os.makedirs(os.path.dirname(local_sym))
    with open(local_sym, 'wb') as handle:
      handle.write(b'\x7fELF')
    self.assertEqual(local_sym,
                     symbols_downloader.filter_binary_path(apk_bang_path))
    self.mock.execute_command_with_return_code.assert_not_called()

  def test_ignores_pulled_directory_target(self):
    """Tests that existing directory entries skip adb pull and return empty."""
    os.makedirs(
        os.path.join(self.symbols_dir, 'device', 'data', 'local', 'tmp',
                     'dir_target'))
    os.makedirs(
        os.path.join(self.build_dir, 'data', 'local', 'tmp', 'dir_target'))

    result = symbols_downloader.filter_binary_path('/data/local/tmp/dir_target')
    self.assertEqual('', result)
    self.mock.execute_command_with_return_code.assert_not_called()

  def test_stack_symbolizer_line_with_injected_command_does_not_run_adb(self):
    """Tests the b/565097191 stack trace payload end-to-end through filter."""
    loop = stack_symbolizer.SymbolizationLoop(
        binary_path_filter=stack_symbolizer.filter_binary_path)
    _, _, binary, _, _ = loop._line_parser(  # pylint: disable=protected-access
        '    #0 0x1234 (/a; id;+0x1234)')
    self.assertEqual('/a; id;', binary)
    self.assertEqual('', stack_symbolizer.filter_binary_path(binary))
    self.mock.execute_command_with_return_code.assert_not_called()

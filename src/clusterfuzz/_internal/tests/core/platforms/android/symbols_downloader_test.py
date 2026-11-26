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
import struct
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib

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
        'download_system_symbols_if_needed',
        'clusterfuzz._internal.system.environment.is_android',
    ])
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
        expected_local = os.path.join(self.symbols_dir,
                                      os.path.basename(device_path))

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
    os.makedirs(os.path.join(self.symbols_dir, 'dir_target'))
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


class DownloadRepoPropIfNeededTest(unittest.TestCase):
  """Tests for download_repo_prop_if_needed."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.fetch_artifact.get',
    ])

  def test_returns_existing_local_repo_prop_without_downloading(self):
    """Returns the local repo.prop path without fetching when already cached."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      expected_path = os.path.join(symbols_dir, 'cheetah-12345-repo.prop')
      with open(expected_path, 'w') as repo_file:
        repo_file.write('kernel/private/gs-google u\'abc123\'\n')

      result = symbols_downloader.download_repo_prop_if_needed(
          symbols_dir,
          '12345',
          'cheetah', ['kernel', 'kernel_cheetah'],
          can_download=True)

      self.assertEqual(result, expected_path)
      self.mock.get.assert_not_called()

  def test_returns_existing_local_repo_prop_when_download_disabled(self):
    """Returns the local repo.prop path even when can_download is False."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      expected_path = os.path.join(symbols_dir, 'cheetah-12345-repo.prop')
      with open(expected_path, 'w') as repo_file:
        repo_file.write('kernel/private/gs-google u\'abc123\'\n')

      result = symbols_downloader.download_repo_prop_if_needed(
          symbols_dir,
          '12345',
          'cheetah', ['kernel', 'kernel_cheetah'],
          can_download=False)

      self.assertEqual(result, expected_path)
      self.mock.get.assert_not_called()

  def test_downloads_repo_prop_when_missing_locally(self):
    """Downloads repo.prop and returns its path when absent locally."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      expected_path = os.path.join(symbols_dir, 'cheetah-12345-repo.prop')

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, artifact_name
        if target == 'kernel_cheetah':
          output_path = os.path.join(output_dir, output_filename)
          with open(output_path, 'w') as repo_file:
            repo_file.write('kernel/private/gs-google u\'abc123\'\n')
          return [output_path]
        return []

      self.mock.get.side_effect = fake_fetch

      result = symbols_downloader.download_repo_prop_if_needed(
          symbols_dir,
          '12345',
          'cheetah', ['kernel', 'kernel_cheetah'],
          can_download=True)

      self.assertEqual(result, expected_path)
      self.assertTrue(os.path.isfile(expected_path))

  def test_raises_when_missing_locally_and_download_disabled(self):
    """Raises SymbolDownloadError when absent and can_download is False."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_repo_prop_if_needed(
            symbols_dir,
            '12345',
            'cheetah', ['kernel', 'kernel_cheetah'],
            can_download=False)
      self.mock.get.assert_not_called()

  def test_raises_when_repo_prop_cannot_be_downloaded(self):
    """Raises SymbolDownloadError when repo.prop is absent and download fails."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      self.mock.get.return_value = []

      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_repo_prop_if_needed(
            symbols_dir,
            '12345',
            'cheetah', ['kernel', 'kernel_cheetah'],
            can_download=True)


class DownloadKernelRepoPropIfNeededTest(unittest.TestCase):
  """Tests for download_kernel_repo_prop_if_needed."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.fetch_artifact.get',
        'clusterfuzz._internal.platforms.android.symbols_downloader.should_download_symbols',
        'clusterfuzz._internal.system.environment.get_value',
    ])
    self.mock.should_download_symbols.return_value = True
    self.mock.get_value.return_value = None

  def test_returns_existing_local_repo_prop_even_when_download_disabled(self):
    """Returns the local repo.prop path even when symbol downloads are disabled."""
    self.mock.should_download_symbols.return_value = False
    with tempfile.TemporaryDirectory() as symbols_dir:
      expected_path = os.path.join(symbols_dir, 'cheetah-12345-repo.prop')
      with open(expected_path, 'w') as repo_file:
        repo_file.write('kernel/private/gs-google u\'abc123\'\n')

      result = symbols_downloader.download_kernel_repo_prop_if_needed(
          symbols_dir, '12345', 'cheetah')

      self.assertEqual(result, expected_path)
      self.mock.get.assert_not_called()

  def test_downloads_kernel_repo_prop_without_sanitizer_targets(self):
    """Downloads kernel repo.prop using default kernel target candidates."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      expected_path = os.path.join(symbols_dir, 'cheetah-12345-repo.prop')
      queried_targets = []

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, artifact_name
        queried_targets.append(target)
        if target == 'kernel_cheetah':
          output_path = os.path.join(output_dir, output_filename)
          with open(output_path, 'w') as repo_file:
            repo_file.write('kernel/private/gs-google u\'abc123\'\n')
          return [output_path]
        return []

      self.mock.get.side_effect = fake_fetch

      result = symbols_downloader.download_kernel_repo_prop_if_needed(
          symbols_dir, '12345', 'cheetah')

      self.assertEqual(result, expected_path)
      self.assertEqual(queried_targets, ['kernel', 'kernel_cheetah'])

  def test_downloads_kernel_repo_prop_with_sanitizer_targets(self):
    """Downloads kernel repo.prop using sanitizer-suffixed target candidates."""
    self.mock.get_value.return_value = 'kasan'
    with tempfile.TemporaryDirectory() as symbols_dir:
      expected_path = os.path.join(symbols_dir, 'cheetah-12345-repo.prop')
      queried_targets = []

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, artifact_name
        queried_targets.append(target)
        if target == 'kernel_kasan_cheetah':
          output_path = os.path.join(output_dir, output_filename)
          with open(output_path, 'w') as repo_file:
            repo_file.write('kernel/private/gs-google u\'abc123\'\n')
          return [output_path]
        return []

      self.mock.get.side_effect = fake_fetch

      result = symbols_downloader.download_kernel_repo_prop_if_needed(
          symbols_dir, '12345', 'cheetah')

      self.assertEqual(result, expected_path)
      self.assertEqual(queried_targets,
                       ['kernel_kasan', 'kernel_kasan_cheetah'])

  def test_raises_when_missing_locally_and_download_disabled(self):
    """Raises SymbolDownloadError when absent and downloads are disabled."""
    self.mock.should_download_symbols.return_value = False
    with tempfile.TemporaryDirectory() as symbols_dir:
      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_kernel_repo_prop_if_needed(
            symbols_dir, '12345', 'cheetah')
      self.mock.get.assert_not_called()

  def test_raises_when_download_fails(self):
    """Raises SymbolDownloadError when kernel repo.prop download fails."""
    self.mock.get.return_value = []
    with tempfile.TemporaryDirectory() as symbols_dir:
      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_kernel_repo_prop_if_needed(
            symbols_dir, '12345', 'cheetah')


class DownloadTrustySymbolsIfNeededTest(unittest.TestCase):
  """Tests for download_trusty_symbols_if_needed."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.fetch_artifact.get',
        'clusterfuzz._internal.platforms.android.settings.get_build_parameters',
        'clusterfuzz._internal.system.environment.get_value',
    ])
    self.mock.get_build_parameters.return_value = {'target': 'cheetah'}
    self.mock.get_value.return_value = False

  def test_returns_existing_local_symbols_without_downloading(self):
    """Returns local ELF paths without fetching when both binaries already exist."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      bid_dir = os.path.join(symbols_dir, 'trusty', '12345')
      os.makedirs(bid_dir)
      kernel_path = os.path.join(bid_dir, 'lk.elf')
      app_path = os.path.join(bid_dir, 'keymaster.syms.elf')
      with open(kernel_path, 'wb') as kernel_file:
        kernel_file.write(b'lk')
      with open(app_path, 'wb') as app_file:
        app_file.write(b'app')

      result = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '12345')

      self.assertEqual(
          result,
          symbols_downloader.TrustySymbols(
              kernel_binary=kernel_path, app_binary=app_path))
      self.mock.get_build_parameters.assert_not_called()
      self.mock.get.assert_not_called()

  def test_returns_existing_local_symbols_in_local_development(self):
    """Returns local ELF paths even when LOCAL_DEVELOPMENT is enabled."""
    self.mock.get_value.return_value = True
    with tempfile.TemporaryDirectory() as symbols_dir:
      bid_dir = os.path.join(symbols_dir, 'trusty', '12345')
      os.makedirs(bid_dir)
      kernel_path = os.path.join(bid_dir, 'lk.elf')
      app_path = os.path.join(bid_dir, 'keymaster.syms.elf')
      with open(kernel_path, 'wb') as kernel_file:
        kernel_file.write(b'lk')
      with open(app_path, 'wb') as app_file:
        app_file.write(b'app')

      result = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '12345')

      self.assertEqual(
          result,
          symbols_downloader.TrustySymbols(
              kernel_binary=kernel_path, app_binary=app_path))
      self.mock.get_build_parameters.assert_not_called()
      self.mock.get.assert_not_called()

  def test_raises_in_local_development_when_missing_locally(self):
    """Raises SymbolDownloadError without modifying symbols_dir in LOCAL_DEVELOPMENT."""
    self.mock.get_value.return_value = True
    with tempfile.TemporaryDirectory() as symbols_dir:
      sentinel_path = os.path.join(symbols_dir, 'existing.txt')
      with open(sentinel_path, 'w') as sentinel_file:
        sentinel_file.write('keep')

      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_trusty_symbols_if_needed(
            symbols_dir, 'keymaster', '12345')

      self.assertTrue(os.path.isfile(sentinel_path))
      self.mock.get_build_parameters.assert_not_called()
      self.mock.get.assert_not_called()

  def test_downloads_and_extracts_nested_symbols_for_cheetah(self):
    """Downloads and extracts ELFs into trusty/<bid> without wiping symbols_dir."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      sentinel_path = os.path.join(symbols_dir, 'system_symbols.txt')
      with open(sentinel_path, 'w') as sentinel_file:
        sentinel_file.write('keep')

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, output_filename
        archive_path = os.path.join(output_dir, artifact_name)
        with zipfile.ZipFile(archive_path, 'w') as zf:
          zf.writestr('lk.elf', b'kernel-elf')
          zf.writestr('apps/keymaster.syms.elf', b'app-elf')

      self.mock.get.side_effect = fake_fetch

      result = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '12345')

      bid_dir = os.path.join(symbols_dir, 'trusty', '12345')
      expected_kernel = os.path.join(bid_dir, 'lk.elf')
      expected_app = os.path.join(bid_dir, 'keymaster.syms.elf')
      self.assertEqual(
          result,
          symbols_downloader.TrustySymbols(
              kernel_binary=expected_kernel, app_binary=expected_app))
      self.assertTrue(os.path.isfile(expected_kernel))
      self.assertTrue(os.path.isfile(expected_app))
      self.assertTrue(os.path.isfile(sentinel_path))
      self.assertFalse(os.path.exists(os.path.join(bid_dir, 'apps')))
      self.mock.get.assert_called_once_with(
          '12345', 'cloudripper-fuzz-test-debug',
          'cloudripper-fuzz-test-debug-12345.syms.zip', mock.ANY, None)

  def test_downloads_symbols_for_oriole_target(self):
    """Selects slider-fuzz-test-debug target when device is oriole."""
    self.mock.get_build_parameters.return_value = {'target': 'oriole'}
    with tempfile.TemporaryDirectory() as symbols_dir:

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, output_filename
        archive_path = os.path.join(output_dir, artifact_name)
        with zipfile.ZipFile(archive_path, 'w') as zf:
          zf.writestr('lk.elf', b'kernel-elf')
          zf.writestr('keymaster.syms.elf', b'app-elf')

      self.mock.get.side_effect = fake_fetch

      result = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '98765')

      bid_dir = os.path.join(symbols_dir, 'trusty', '98765')
      self.assertEqual(result.kernel_binary, os.path.join(bid_dir, 'lk.elf'))
      self.assertEqual(result.app_binary,
                       os.path.join(bid_dir, 'keymaster.syms.elf'))
      self.mock.get.assert_called_once_with(
          '98765', 'slider-fuzz-test-debug',
          'slider-fuzz-test-debug-98765.syms.zip', mock.ANY, None)

  def test_extracts_app_elf_with_leading_slash_in_zip_entry(self):
    """Extracts app ELF directly into trusty/<bid> even for absolute-style zip paths."""
    with tempfile.TemporaryDirectory() as symbols_dir:

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, output_filename
        archive_path = os.path.join(output_dir, artifact_name)
        with zipfile.ZipFile(archive_path, 'w') as zf:
          zf.writestr('lk.elf', b'kernel-elf')
          zf.writestr('/apps/keymaster.syms.elf', b'app-elf')

      self.mock.get.side_effect = fake_fetch

      result = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '12345')

      bid_dir = os.path.join(symbols_dir, 'trusty', '12345')
      self.assertTrue(os.path.isfile(result.kernel_binary))
      self.assertTrue(os.path.isfile(result.app_binary))
      self.assertFalse(os.path.exists(os.path.join(bid_dir, 'apps')))
      with open(result.app_binary, 'rb') as app_file:
        self.assertEqual(app_file.read(), b'app-elf')

  def test_isolates_cached_symbols_by_bid(self):
    """Stores symbols in bid-scoped subdirectories and reuses each bid independently."""
    with tempfile.TemporaryDirectory() as symbols_dir:

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del target, output_filename
        archive_path = os.path.join(output_dir, artifact_name)
        with zipfile.ZipFile(archive_path, 'w') as zf:
          zf.writestr('lk.elf', ('lk-%s' % build_id).encode('utf-8'))
          zf.writestr('keymaster.syms.elf',
                      ('app-%s' % build_id).encode('utf-8'))

      self.mock.get.side_effect = fake_fetch

      first = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '11111')
      second = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '22222')
      third = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '22222')
      fourth = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '11111')

      self.assertNotEqual(first, second)
      self.assertEqual(second, third)
      self.assertEqual(first, fourth)
      self.assertEqual(self.mock.get.call_count, 2)
      with open(second.kernel_binary, 'rb') as kernel_file:
        self.assertEqual(kernel_file.read(), b'lk-22222')
      with open(second.app_binary, 'rb') as app_file:
        self.assertEqual(app_file.read(), b'app-22222')
      with open(first.kernel_binary, 'rb') as kernel_file:
        self.assertEqual(kernel_file.read(), b'lk-11111')

  def test_downloads_when_only_one_elf_exists_locally(self):
    """Downloads and replaces stale lk.elf when app ELF is missing locally."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      bid_dir = os.path.join(symbols_dir, 'trusty', '12345')
      os.makedirs(bid_dir)
      with open(os.path.join(bid_dir, 'lk.elf'), 'wb') as kernel_file:
        kernel_file.write(b'stale-lk')

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, output_filename
        archive_path = os.path.join(output_dir, artifact_name)
        with zipfile.ZipFile(archive_path, 'w') as zf:
          zf.writestr('lk.elf', b'fresh-lk')
          zf.writestr('keymaster.syms.elf', b'fresh-app')

      self.mock.get.side_effect = fake_fetch

      result = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '12345')

      self.assertEqual(result.kernel_binary, os.path.join(bid_dir, 'lk.elf'))
      self.assertEqual(result.app_binary,
                       os.path.join(bid_dir, 'keymaster.syms.elf'))
      with open(result.kernel_binary, 'rb') as kernel_file:
        self.assertEqual(kernel_file.read(), b'fresh-lk')
      with open(result.app_binary, 'rb') as app_file:
        self.assertEqual(app_file.read(), b'fresh-app')
      self.mock.get.assert_called_once()

  def test_failed_extraction_midway_does_not_poison_cache_for_retry(self):
    """Cleans up failed extraction so a subsequent call re-downloads cleanly."""
    with tempfile.TemporaryDirectory() as symbols_dir:
      attempts = [0]

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, output_filename
        attempts[0] += 1
        archive_path = os.path.join(output_dir, artifact_name)
        if attempts[0] == 1:
          with zipfile.ZipFile(archive_path, 'w') as zf:
            zf.writestr('lk.elf', b'partial-lk')
            zf.writestr('keymaster.syms.elf', b'corrupt-payload')
          with open(archive_path, 'rb') as zf_in:
            raw = bytearray(zf_in.read())
          payload_offset = raw.index(b'corrupt-payload')
          raw[payload_offset] ^= 0xFF
          with open(archive_path, 'wb') as zf_out:
            zf_out.write(raw)
        else:
          with zipfile.ZipFile(archive_path, 'w') as zf:
            zf.writestr('lk.elf', b'clean-lk')
            zf.writestr('keymaster.syms.elf', b'clean-app')

      self.mock.get.side_effect = fake_fetch

      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_trusty_symbols_if_needed(
            symbols_dir, 'keymaster', '12345')

      bid_dir = os.path.join(symbols_dir, 'trusty', '12345')
      self.assertFalse(os.path.exists(os.path.join(bid_dir, 'lk.elf')))
      self.assertFalse(
          os.path.exists(os.path.join(bid_dir, 'keymaster.syms.elf')))

      result = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '12345')

      with open(result.kernel_binary, 'rb') as kernel_file:
        self.assertEqual(kernel_file.read(), b'clean-lk')
      with open(result.app_binary, 'rb') as app_file:
        self.assertEqual(app_file.read(), b'clean-app')
      self.assertEqual(attempts[0], 2)

  def test_downloading_second_app_for_same_bid_preserves_first_app_elf(self):
    """Preserves an already-cached app ELF when downloading a second app for the same bid."""
    with tempfile.TemporaryDirectory() as symbols_dir:

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, output_filename
        archive_path = os.path.join(output_dir, artifact_name)
        with zipfile.ZipFile(archive_path, 'w') as zf:
          zf.writestr('lk.elf', b'lk-12345')
          zf.writestr('apps/keymaster.syms.elf', b'keymaster-elf')
          zf.writestr('apps/gatekeeper.syms.elf', b'gatekeeper-elf')

      self.mock.get.side_effect = fake_fetch

      first = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'keymaster', '12345')
      second = symbols_downloader.download_trusty_symbols_if_needed(
          symbols_dir, 'gatekeeper', '12345')

      self.assertEqual(first.kernel_binary, second.kernel_binary)
      self.assertTrue(os.path.isfile(first.app_binary))
      self.assertTrue(os.path.isfile(second.app_binary))
      with open(first.app_binary, 'rb') as first_app_file:
        self.assertEqual(first_app_file.read(), b'keymaster-elf')
      with open(second.app_binary, 'rb') as second_app_file:
        self.assertEqual(second_app_file.read(), b'gatekeeper-elf')
      self.assertEqual(self.mock.get.call_count, 2)

  def test_raises_when_extraction_hits_zlib_error(self):
    """Translates zlib.error from a corrupt deflate stream into SymbolDownloadError."""
    with tempfile.TemporaryDirectory() as symbols_dir:

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, output_filename
        archive_path = os.path.join(output_dir, artifact_name)
        with zipfile.ZipFile(
            archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
          zf.writestr('lk.elf', b'kernel-elf')
          zf.writestr('keymaster.syms.elf', b'A' * 1024)
          header_offset = zf.getinfo('keymaster.syms.elf').header_offset
        with open(archive_path, 'rb') as zf_in:
          raw = bytearray(zf_in.read())
        name_len, extra_len = struct.unpack(
            '<HH', raw[header_offset + 26:header_offset + 30])
        data_offset = header_offset + 30 + name_len + extra_len
        # Set invalid deflate block type (bits 1..2 == 11) to trigger zlib.error.
        raw[data_offset] = 0xFF
        raw[data_offset + 1] = 0xFF
        with open(archive_path, 'wb') as zf_out:
          zf_out.write(raw)

      self.mock.get.side_effect = fake_fetch

      with self.assertRaises(symbols_downloader.SymbolDownloadError) as ctx:
        symbols_downloader.download_trusty_symbols_if_needed(
            symbols_dir, 'keymaster', '12345')

      self.assertIsInstance(ctx.exception.__cause__, zlib.error)
      bid_dir = os.path.join(symbols_dir, 'trusty', '12345')
      self.assertFalse(os.path.exists(os.path.join(bid_dir, 'lk.elf')))
      self.assertFalse(
          os.path.exists(os.path.join(bid_dir, 'keymaster.syms.elf')))

  def test_raises_when_build_parameters_unavailable(self):
    """Raises SymbolDownloadError when device build parameters are missing."""
    self.mock.get_build_parameters.return_value = None
    with tempfile.TemporaryDirectory() as symbols_dir:
      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_trusty_symbols_if_needed(
            symbols_dir, 'keymaster', '12345')
      self.mock.get.assert_not_called()

  def test_raises_for_unsupported_device(self):
    """Raises SymbolDownloadError when device is not a supported Trusty target."""
    self.mock.get_build_parameters.return_value = {'target': 'cuttlefish'}
    with tempfile.TemporaryDirectory() as symbols_dir:
      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_trusty_symbols_if_needed(
            symbols_dir, 'keymaster', '12345')
      self.mock.get.assert_not_called()

  def test_raises_when_archive_download_fails(self):
    """Raises SymbolDownloadError when the Trusty symbols archive fails to download."""
    self.mock.get.return_value = None
    with tempfile.TemporaryDirectory() as symbols_dir:
      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_trusty_symbols_if_needed(
            symbols_dir, 'keymaster', '12345')

  def test_raises_when_archive_is_corrupt_zip(self):
    """Raises SymbolDownloadError when the downloaded archive is not a valid zip."""
    with tempfile.TemporaryDirectory() as symbols_dir:

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, output_filename
        with open(os.path.join(output_dir, artifact_name), 'wb') as bad_file:
          bad_file.write(b'not-a-zip')

      self.mock.get.side_effect = fake_fetch

      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_trusty_symbols_if_needed(
            symbols_dir, 'keymaster', '12345')

  def test_raises_when_extracted_archive_missing_app_elf(self):
    """Raises SymbolDownloadError when the archive lacks the requested app ELF."""
    with tempfile.TemporaryDirectory() as symbols_dir:

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, output_filename
        archive_path = os.path.join(output_dir, artifact_name)
        with zipfile.ZipFile(archive_path, 'w') as zf:
          zf.writestr('lk.elf', b'kernel-elf')

      self.mock.get.side_effect = fake_fetch

      with self.assertRaises(symbols_downloader.SymbolDownloadError):
        symbols_downloader.download_trusty_symbols_if_needed(
            symbols_dir, 'keymaster', '12345')

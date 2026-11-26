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

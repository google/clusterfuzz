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
"""Tests for symbols_downloader."""

import os
import tempfile
import unittest
from unittest import mock

from clusterfuzz._internal.platforms.android import symbols_downloader
from clusterfuzz._internal.tests.test_libs import helpers

BUILD_ID = '1234567'
DEVICE_LIBRARY_PATH = '/system/lib64/libfoo.so'
MISSING_LIBRARY_MESSAGE = (
    f'Unable to find library {DEVICE_LIBRARY_PATH} for symbolization.')


def _create_file(path):
  """Creates an empty file at |path|, along with its parent directories."""
  os.makedirs(os.path.dirname(path), exist_ok=True)
  with open(path, 'wb'):
    pass


def _fake_adb_pull(cmd):
  """Fakes `adb pull <device_path> <local_path>` by creating |local_path|."""
  with open(cmd.split()[-1], 'wb'):
    pass


class SymbolsDownloaderTestBase(unittest.TestCase):
  """Sets up an Android uworker, which can't download symbols."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.debug',
        'clusterfuzz._internal.metrics.logs.error',
        'clusterfuzz._internal.platforms.android.adb.run_command',
        ('fetch_artifact_get',
         'clusterfuzz._internal.platforms.android.fetch_artifact.get'),
        'clusterfuzz._internal.platforms.android.fetch_artifact.get_latest_artifact_info',
        'clusterfuzz._internal.platforms.android.settings.get_build_parameters',
        'clusterfuzz._internal.platforms.android.settings.is_google_device',
    ])
    self.mock.is_google_device.return_value = True
    self.mock.get_build_parameters.return_value = {
        'build_id': BUILD_ID,
        'target': 'cheetah',
        'type': 'userdebug',
    }

    temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(temp_dir.cleanup)
    self.build_dir = os.path.join(temp_dir.name, 'build')
    # Not created on purpose, to check it gets created when needed.
    self.symbols_dir = os.path.join(temp_dir.name, 'symbols')

    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)

  def _set_regular_bot(self):
    """Turns the uworker into a regular bot, which can download symbols."""
    del os.environ['UWORKER']


class ShouldDownloadSymbolsTest(SymbolsDownloaderTestBase):
  """Tests for should_download_symbols."""

  def test_uworker(self):
    """Tests that uworkers don't download symbols, even for google devices."""
    self.assertFalse(symbols_downloader.should_download_symbols())

  def test_regular_bot(self):
    """Tests that regular bots download symbols for google devices."""
    self._set_regular_bot()
    self.assertTrue(symbols_downloader.should_download_symbols())


class DownloadRepoPropIfNeededTest(SymbolsDownloaderTestBase):
  """Tests for download_repo_prop_if_needed."""

  def _download_repo_prop(self):
    symbols_downloader.download_repo_prop_if_needed(
        self.symbols_dir, BUILD_ID, 'target', ['kernel'], 'kernel')

  def test_uworker(self):
    """Tests that uworkers neither download the repo.prop nor wipe the bundled
    one."""
    repo_prop_path = os.path.join(
        self.symbols_dir,
        symbols_downloader.get_repo_prop_archive_filename(BUILD_ID, 'target'))
    _create_file(repo_prop_path)

    self._download_repo_prop()

    self.assertTrue(os.path.exists(repo_prop_path))
    self.mock.fetch_artifact_get.assert_not_called()
    self.mock.error.assert_not_called()

  def test_regular_bot(self):
    """Tests that regular bots download the repo.prop."""
    self._set_regular_bot()
    self._download_repo_prop()
    self.mock.fetch_artifact_get.assert_called_once()


class DownloadTrustySymbolsIfNeededTest(SymbolsDownloaderTestBase):
  """Tests for download_trusty_symbols_if_needed."""

  def _download_trusty_symbols(self):
    symbols_downloader.download_trusty_symbols_if_needed(
        self.symbols_dir, 'keymaster', BUILD_ID)

  def test_uworker(self):
    """Tests that uworkers neither download the Trusty symbols nor wipe the
    bundled ones."""
    bundled_symbols = [
        os.path.join(self.symbols_dir, 'lk.elf'),
        os.path.join(self.symbols_dir, 'keymaster.syms.elf'),
    ]
    for path in bundled_symbols:
      _create_file(path)

    self._download_trusty_symbols()

    for path in bundled_symbols:
      self.assertTrue(os.path.exists(path))
    self.mock.get_build_parameters.assert_not_called()
    self.mock.get_latest_artifact_info.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()
    self.mock.error.assert_not_called()

  def test_regular_bot(self):
    """Tests that regular bots download the Trusty symbols."""
    self._set_regular_bot()
    self._download_trusty_symbols()
    self.mock.fetch_artifact_get.assert_called_once()


class FilterBinaryPathTest(SymbolsDownloaderTestBase):
  """Tests for filter_binary_path."""

  def test_build_dir_library_on_uworker(self):
    """Tests that libraries bundled in the build directory are used."""
    library_path = os.path.join(self.build_dir, 'lib64', 'libfoo.so')
    _create_file(library_path)

    self.assertEqual(library_path,
                     symbols_downloader.filter_binary_path(DEVICE_LIBRARY_PATH))
    self.mock.run_command.assert_not_called()
    self.mock.error.assert_not_called()

  def test_bundled_symbols_library_on_uworker(self):
    """Tests that libraries bundled in the symbols directory are used, without
    wiping it."""
    library_path = os.path.join(self.symbols_dir, 'libfoo.so')
    _create_file(library_path)

    self.assertEqual(library_path,
                     symbols_downloader.filter_binary_path(DEVICE_LIBRARY_PATH))
    self.assertTrue(os.path.exists(library_path))
    self.mock.run_command.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()
    self.mock.error.assert_not_called()

  def test_adb_pulled_libraries_on_uworker(self):
    """Tests that libraries are pulled from the device into the (missing)
    symbols directory, and are kept across frames."""
    self.mock.run_command.side_effect = _fake_adb_pull
    foo_path = os.path.join(self.symbols_dir, 'libfoo.so')
    bar_path = os.path.join(self.symbols_dir, 'libbar.so')

    self.assertEqual(foo_path,
                     symbols_downloader.filter_binary_path(DEVICE_LIBRARY_PATH))
    self.assertEqual(
        bar_path,
        symbols_downloader.filter_binary_path('/system/lib64/libbar.so'))
    self.assertEqual([
        mock.call(f'pull {DEVICE_LIBRARY_PATH} {foo_path}'),
        mock.call(f'pull /system/lib64/libbar.so {bar_path}'),
    ], self.mock.run_command.call_args_list)

    # The library pulled for the first frame is reused rather than pulled again.
    self.mock.run_command.reset_mock()
    self.assertEqual(foo_path,
                     symbols_downloader.filter_binary_path(DEVICE_LIBRARY_PATH))
    self.mock.run_command.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()
    self.mock.error.assert_not_called()

  def test_missing_library_on_uworker(self):
    """Tests that missing libraries are only logged at debug level on uworkers,
    as their symbols can't be downloaded."""
    self.assertEqual('',
                     symbols_downloader.filter_binary_path(DEVICE_LIBRARY_PATH))
    self.mock.debug.assert_called_once_with(MISSING_LIBRARY_MESSAGE)
    self.mock.fetch_artifact_get.assert_not_called()
    self.mock.error.assert_not_called()

  def test_missing_symbols_dir_on_uworker(self):
    """Tests that a missing symbols directory is handled gracefully, without
    pulling the library from the device."""
    del os.environ['SYMBOLS_DIR']
    self.assertEqual('',
                     symbols_downloader.filter_binary_path(DEVICE_LIBRARY_PATH))
    self.mock.run_command.assert_not_called()
    self.mock.debug.assert_called_once_with(MISSING_LIBRARY_MESSAGE)
    self.mock.error.assert_not_called()

  def test_missing_library_on_regular_bot(self):
    """Tests that missing libraries are logged as errors on regular bots, after
    trying to download their symbols."""
    self._set_regular_bot()
    self.assertEqual('',
                     symbols_downloader.filter_binary_path(DEVICE_LIBRARY_PATH))
    self.mock.fetch_artifact_get.assert_called_once()
    self.mock.error.assert_called_with(MISSING_LIBRARY_MESSAGE)

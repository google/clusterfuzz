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
"""Tests remote symbol fetching gates and local library resolution."""

import os
import tempfile
import unittest
from unittest import mock

from clusterfuzz._internal.platforms.android import symbols_downloader
from clusterfuzz._internal.tests.test_libs import helpers


class CanFetchBuildSymbolsTest(unittest.TestCase):
  """Tests whether the current bot environment may fetch remote build
  symbols."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_regular_bot(self):
    """Verifies that regular production bots are allowed to fetch remote build
    symbols."""
    os.environ.pop('UWORKER', None)
    os.environ.pop('LOCAL_DEVELOPMENT', None)

    self.assertTrue(symbols_downloader.can_fetch_build_symbols())

  def test_uworker(self):
    """Verifies that untrusted workers are blocked from fetching remote build
    symbols."""
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)

    self.assertFalse(symbols_downloader.can_fetch_build_symbols())

  def test_local_development(self):
    """Verifies that local development runs are blocked from fetching remote
    build symbols."""
    os.environ.pop('UWORKER', None)
    os.environ['LOCAL_DEVELOPMENT'] = 'True'

    self.assertFalse(symbols_downloader.can_fetch_build_symbols())


class ShouldDownloadSymbolsTest(unittest.TestCase):
  """Tests whether system symbol archives should be downloaded for a device."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.settings.is_google_device',
    ])

  def test_uworker_on_google_device(self):
    """Verifies that untrusted workers skip system symbol downloads even for
    Google devices."""
    self.mock.is_google_device.return_value = True
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)

    self.assertFalse(symbols_downloader.should_download_symbols())

  def test_regular_bot_on_google_device(self):
    """Verifies that regular bots download system symbols when running against
    Google devices."""
    self.mock.is_google_device.return_value = True
    os.environ.pop('UWORKER', None)
    os.environ.pop('LOCAL_DEVELOPMENT', None)

    self.assertTrue(symbols_downloader.should_download_symbols())


class DownloadRepoPropIfNeededTest(unittest.TestCase):
  """Tests conditional downloading of repo.prop build manifest files."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        ('fetch_artifact_get',
         'clusterfuzz._internal.platforms.android.fetch_artifact.get'),
    ])
    temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(temp_dir.cleanup)
    self.symbols_dir = temp_dir.name

  def test_uworker(self):
    """Verifies that untrusted workers skip repo.prop downloads without wiping
    existing local files."""
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)
    repo_prop_path = os.path.join(self.symbols_dir, 'target-1234567-repo.prop')
    with open(repo_prop_path, 'wb'):
      pass

    symbols_downloader.download_repo_prop_if_needed(
        self.symbols_dir, '1234567', 'target', ['kernel'], 'kernel')

    self.assertTrue(os.path.exists(repo_prop_path))
    self.mock.fetch_artifact_get.assert_not_called()

  def test_regular_bot(self):
    """Verifies that regular bots trigger a remote repo.prop download when not
    cached locally."""
    os.environ.pop('UWORKER', None)
    os.environ.pop('LOCAL_DEVELOPMENT', None)

    symbols_downloader.download_repo_prop_if_needed(
        self.symbols_dir, '1234567', 'target', ['kernel'], 'kernel')

    self.mock.fetch_artifact_get.assert_called_once()


class DownloadTrustySymbolsIfNeededTest(unittest.TestCase):
  """Tests conditional downloading of Trusted App symbol archives."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        ('fetch_artifact_get',
         'clusterfuzz._internal.platforms.android.fetch_artifact.get'),
        'clusterfuzz._internal.platforms.android.fetch_artifact.get_latest_artifact_info',
        'clusterfuzz._internal.platforms.android.settings.get_build_parameters',
    ])
    temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(temp_dir.cleanup)
    self.symbols_dir = temp_dir.name

  def test_uworker(self):
    """Verifies that untrusted workers skip Trusty symbol downloads without
    wiping existing local files."""
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)
    kernel_elf = os.path.join(self.symbols_dir, 'lk.elf')
    app_elf = os.path.join(self.symbols_dir, 'keymaster.syms.elf')
    with open(kernel_elf, 'wb'):
      pass
    with open(app_elf, 'wb'):
      pass

    symbols_downloader.download_trusty_symbols_if_needed(
        self.symbols_dir, 'keymaster', '1234567')

    self.assertTrue(os.path.exists(kernel_elf))
    self.assertTrue(os.path.exists(app_elf))
    self.mock.get_build_parameters.assert_not_called()
    self.mock.get_latest_artifact_info.assert_not_called()
    self.mock.fetch_artifact_get.assert_not_called()

  def test_regular_bot(self):
    """Verifies that regular bots download the Trusted App symbol archive for
    the target device."""
    os.environ.pop('UWORKER', None)
    os.environ.pop('LOCAL_DEVELOPMENT', None)
    self.mock.get_build_parameters.return_value = {'target': 'cheetah'}

    symbols_downloader.download_trusty_symbols_if_needed(
        self.symbols_dir, 'keymaster', '1234567')

    self.mock.fetch_artifact_get.assert_called_once()


class FilterBinaryPathTest(unittest.TestCase):
  """Tests resolving device library paths to local copies for symbolization."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.adb.run_command',
        ('fetch_artifact_get',
         'clusterfuzz._internal.platforms.android.fetch_artifact.get'),
        'clusterfuzz._internal.platforms.android.settings.get_build_parameters',
        'clusterfuzz._internal.platforms.android.settings.is_google_device',
    ])
    temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(temp_dir.cleanup)
    self.build_dir = os.path.join(temp_dir.name, 'build')
    self.symbols_dir = os.path.join(temp_dir.name, 'symbols')

  def test_build_dir_library_on_uworker(self):
    """Verifies that libraries bundled with the build are resolved directly
    without device pulls or remote fetches."""
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
    """Verifies that a previously pulled device library is reused locally
    without pulling it again."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)
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

  def test_adb_pulled_libraries_on_uworker(self):
    """Verifies that libraries pulled from the device keep their full paths so
    same-named libraries do not collide across frames."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)
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

  def test_missing_library_on_uworker(self):
    """Verifies that unresolvable libraries on untrusted workers return empty
    without attempting remote symbol fetches."""
    os.environ['OS_OVERRIDE'] = 'ANDROID'
    os.environ['BUILD_DIR'] = self.build_dir
    os.environ['SYMBOLS_DIR'] = self.symbols_dir
    os.environ['UWORKER'] = 'True'
    os.environ.pop('LOCAL_DEVELOPMENT', None)
    self.mock.is_google_device.return_value = True

    actual_path = symbols_downloader.filter_binary_path(
        '/system/lib64/libfoo.so')

    self.assertEqual('', actual_path)
    self.mock.run_command.assert_called_once()
    self.mock.fetch_artifact_get.assert_not_called()

  def test_missing_library_on_regular_bot(self):
    """Verifies that unresolvable libraries on regular bots return empty after
    attempting both remote symbol fetch and device pull."""
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

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
"""build_manager tests."""
# pylint: disable=protected-access

import functools
import os
import shutil
import tempfile
import types
import unittest

import mock
import parameterized
from pyfakefs import fake_filesystem_unittest
import six

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks import fuzz_task
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

FAKE_APP_NAME = 'app'


# pylint: disable=unused-argument
def _mock_unpack_build(
    self,
    _,
    build_dir,
    build_url,
    target_weights=None,
):
  """Mock _unpack_build."""
  if not shell.remove_directory(build_dir, recreate=True):
    return False

  with open(os.path.join(build_dir, FAKE_APP_NAME), 'w') as f:
    f.write('')

  with open(os.path.join(build_dir, 'args.gn'), 'w') as f:
    f.write('')

  with open(os.path.join(build_dir, 'llvm-symbolizer'), 'w') as f:
    f.write('')

  fuzz_target = os.environ.get('FUZZ_TARGET')
  if fuzz_target:
    with open(os.path.join(build_dir, '.partial_build'), 'w') as f:
      f.write('')

  return True


def _get_timestamp(base_build_dir):
  """Return the timestamp, or None."""
  return utils.read_data_from_file(
      os.path.join(base_build_dir, '.timestamp'), eval_data=True)


class TrunkBuildTest(unittest.TestCase):
  """Tests for setting up trunk build."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager._setup_build_directories',
        'clusterfuzz._internal.build_management.build_manager.get_build_urls_list',
        'clusterfuzz._internal.build_management.build_manager.setup_regular_build',
    ])

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['RELEASE_BUILD_BUCKET_PATH'] = (
        'gs://path/file-release-([0-9]+).zip')
    os.environ['SYM_RELEASE_BUILD_BUCKET_PATH'] = (
        'gs://path/file-sym-release-([0-9]+).zip')
    os.environ['SYM_DEBUG_BUILD_BUCKET_PATH'] = (
        'gs://path/file-sym-debug-([0-9]+).zip')

  def test_setup_success(self):
    """Test successful setup."""
    self.mock.get_build_urls_list.side_effect = (
        [
            'gs://path/file-release-10.zip',
            'gs://path/file-release-2.zip',
            'gs://path/file-release-1.zip',
        ],
        [
            'gs://path/file-sym-release-10.zip',
            'gs://path/file-sym-release-2.zip',
            'gs://path/file-sym-release-1.zip',
        ],
        [
            'gs://path/file-sym-debug-10.zip',
            'gs://path/file-sym-debug-2.zip',
            'gs://path/file-sym-debug-1.zip',
        ],
    )

    build_manager.setup_build()
    self.mock.setup_regular_build.assert_called_with(
        10,
        'gs://path/file-release-([0-9]+).zip',
        build_prefix=None,
        target_weights=None)

  def test_setup_mismatch(self):
    """Test setup finding the first matching revision."""
    self.mock.get_build_urls_list.side_effect = (
        [
            'gs://path/file-release-10.zip',
            'gs://path/file-release-2.zip',
            'gs://path/file-release-1.zip',
        ],
        [
            'gs://path/file-sym-release-11.zip',
            'gs://path/file-sym-release-2.zip',
            'gs://path/file-sym-release-1.zip',
        ],
        [
            'gs://path/file-sym-debug-10.zip',
            'gs://path/file-sym-debug-2.zip',
            'gs://path/file-sym-debug-1.zip',
        ],
    )

    build_manager.setup_build()
    self.mock.setup_regular_build.assert_called_with(
        2,
        'gs://path/file-release-([0-9]+).zip',
        build_prefix=None,
        target_weights=None)

  def test_setup_fail(self):
    """Test setup failing to find any matching revisions."""
    self.mock.get_build_urls_list.side_effect = (
        [
            'gs://path/file-release-10.zip',
            'gs://path/file-release-3.zip',
            'gs://path/file-release-1.zip',
        ],
        [
            'gs://path/file-sym-release-11.zip',
            'gs://path/file-sym-release-2.zip',
            'gs://path/file-sym-release-1.zip',
        ],
        [
            'gs://path/file-sym-debug-10.zip',
            'gs://path/file-sym-debug-2.zip',
            'gs://path/file-sym-debug-0.zip',
        ],
    )

    build_manager.setup_build()
    self.assertEqual(0, self.mock.setup_regular_build.call_count)


@unittest.skipIf(
    not environment.get_value('FUCHSIA_TESTS'),
    'Temporarily disabling the Fuchsia test until build size reduced.')
class FuchsiaBuildTest(unittest.TestCase):
  """Tests for Fuchsia build setup."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.shell.clear_temp_directory',
    ])

    self.temp_dir = tempfile.mkdtemp()
    builds_dir = os.path.join(self.temp_dir, 'builds')
    os.mkdir(builds_dir)
    urls_dir = os.path.join(self.temp_dir, 'urls')
    os.mkdir(urls_dir)

    environment.set_value('JOB_NAME', 'libfuzzer_asan_fuchsia')
    environment.set_value('FAIL_RETRIES', 1)
    environment.set_value('BUILDS_DIR', builds_dir)
    environment.set_value('BUILD_URLS_DIR', urls_dir)
    environment.set_value('UNPACK_ALL_FUZZ_TARGETS_AND_FILES', True)
    environment.set_value(
        'RELEASE_BUILD_BUCKET_PATH',
        'gs://clusterfuchsia-builds-test/libfuzzer/'
        'fuchsia-([0-9]+).zip')
    environment.set_value('OS_OVERRIDE', 'FUCHSIA')

    self.maxDiff = None  # pylint: disable=invalid-name

  def tearDown(self):
    shutil.rmtree(self.temp_dir)

  def test_setup(self):
    """Tests setting up a build."""
    build = build_manager.setup_build(
        target_weights={'example_fuzzers/trap_fuzzer': 1000000.0})
    self.assertIsInstance(build, build_manager.FuchsiaBuild)

    self.assertIsNotNone(os.environ['FUZZ_TARGET'])
    self.assertEqual('example_fuzzers/trap_fuzzer', os.environ['FUZZ_TARGET'])
    self.assertEqual(20190926201257, environment.get_value('APP_REVISION'))

    # pylint: disable=protected-access
    targets = build._get_fuzz_targets_from_dir(build.build_dir)
    six.assertCountEqual(self, [
        'example_fuzzers/baz_fuzzer',
        'example_fuzzers/overflow_fuzzer',
        'example_fuzzers/trap_fuzzer',
        'ledger_fuzzers/p2p_sync_fuzzer',
        'ledger_fuzzers/encoding_fuzzer',
        'ledger_fuzzers/commit_pack_fuzzer',
        'bluetooth_fuzzers/basic_mode_rx_engine_fuzzer',
        'bluetooth_fuzzers/enhanced_retransmission_mode_rx_engine_fuzzer',
        'mdns_fuzzers/packet_reader_fuzzer',
        'zircon_fuzzers/nhlt-fuzzer',
        'zircon_fuzzers/zstd-fuzzer',
        'zircon_fuzzers/utf_conversion-fuzzer',
        'zircon_fuzzers/zbi-bootfs-fuzzer',
        'zircon_fuzzers/lz4-decompress-fuzzer',
        'zircon_fuzzers/lz4-fuzzer',
        'zircon_fuzzers/noop-fuzzer',
    ], targets)


class RegularBuildTest(fake_filesystem_unittest.TestCase):
  """Tests for regular build setup."""

  def setUp(self):
    """Setup for regular build test."""
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.get_build_urls_list',
        'clusterfuzz._internal.build_management.build_manager.Build._unpack_build',
        'clusterfuzz._internal.fuzzing.fuzzer_selection.get_fuzz_target_weights',
        'clusterfuzz._internal.system.shell.clear_temp_directory',
        'time.time',
    ])

    test_helpers.patch_environ(self)

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_NAME'] = FAKE_APP_NAME
    os.environ['JOB_NAME'] = 'job'

    self.mock._unpack_build.side_effect = _mock_unpack_build

  def _assert_env_vars(self):
    """Assert env vars exist."""
    self.assertEqual(os.environ['BUILD_URL'], 'gs://path/file-release-2.zip')

    self.assertEqual(
        os.environ['APP_PATH'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions/app')

    self.assertEqual(
        os.environ['GN_ARGS_PATH'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions/'
        'args.gn')

    self.assertEqual(
        os.environ['APP_DIR'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions')

    self.assertEqual(
        os.environ['LLVM_SYMBOLIZER_PATH'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions/'
        'llvm-symbolizer')

    self.assertEqual(
        os.environ['BUILD_DIR'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions')

  def test_setup(self):
    """Tests setting up a build."""
    os.environ['RELEASE_BUILD_BUCKET_PATH'] = (
        'gs://path/file-release-([0-9]+).zip')

    self.mock.get_build_urls_list.return_value = [
        'gs://path/file-release-10.zip',
        'gs://path/file-release-2.zip',
        'gs://path/file-release-1.zip',
    ]

    self.mock.time.return_value = 1000.0
    build = build_manager.setup_regular_build(2)
    self.assertIsInstance(build, build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)

    self.mock._unpack_build.assert_called_once_with(
        mock.ANY, '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025',
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions',
        'gs://path/file-release-2.zip', None)

    self._assert_env_vars()
    self.assertEqual(os.environ['APP_REVISION'], '2')

    self.mock.time.return_value = 1005.0
    self.assertIsInstance(
        build_manager.setup_regular_build(2), build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)

    # Already set up.
    self.assertEqual(self.mock._unpack_build.call_count, 1)
    self._assert_env_vars()
    self.assertEqual(os.environ['APP_REVISION'], '2')

    # Non-existent revisions do not result in any builds being set up.
    self.assertIsNone(build_manager.setup_regular_build(3))

  def test_delete(self):
    """Test deleting this build."""
    os.environ['RELEASE_BUILD_BUCKET_PATH'] = (
        'gs://path/file-release-([0-9]+).zip')

    self.mock.get_build_urls_list.return_value = [
        'gs://path/file-release-2.zip',
    ]

    build = build_manager.setup_regular_build(2)
    self.assertTrue(
        os.path.isdir(
            '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions'))
    build.delete()
    self.assertFalse(
        os.path.isdir(
            '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions'))
    self.assertTrue(
        os.path.isdir('/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025'))


class RegularLibFuzzerBuildTest(fake_filesystem_unittest.TestCase):
  """Tests for regular libFuzzer build setup."""

  def setUp(self):
    """Setup for regular libFuzzer build test."""
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.utils.get_fuzz_targets',
        'clusterfuzz._internal.build_management.build_manager.get_build_urls_list',
        'clusterfuzz._internal.build_management.build_manager.Build.'
        '_get_fuzz_targets_from_archive',
        'clusterfuzz._internal.build_management.build_manager._make_space',
        'clusterfuzz._internal.build_management.build_manager._make_space_for_build',
        'clusterfuzz._internal.system.shell.clear_temp_directory',
        'clusterfuzz._internal.google_cloud_utils.storage.copy_file_from',
        'clusterfuzz._internal.google_cloud_utils.storage.get_download_file_size',
        'clusterfuzz._internal.system.archive.unpack',
        'time.time',
    ])

    test_helpers.patch_environ(self)

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_NAME'] = FAKE_APP_NAME
    os.environ['JOB_NAME'] = 'libfuzzer_job'

    self.target_weights = {
        'target1': 0.0,
        'target2': 1.0,
        'target3': 0.0,
    }
    self.mock.get_download_file_size.return_value = 1
    self.mock.copy_file_from.return_value = True

    mock_targets_from_archive = self.mock._get_fuzz_targets_from_archive
    mock_targets_from_archive.return_value.__iter__.return_value = [
        'target1', 'target2', 'target3'
    ]
    self.mock.get_fuzz_targets.return_value = [
        '/path/target1', '/path/target2', '/path/target3'
    ]
    self.mock._make_space.return_value = True
    self.mock._make_space_for_build.return_value = True
    self.mock.unpack.return_value = True
    self.mock.time.return_value = 1000.0

    os.environ['RELEASE_BUILD_BUCKET_PATH'] = (
        'gs://path/file-release-([0-9]+).zip')

    self.mock.get_build_urls_list.return_value = [
        'gs://path/file-release-10.zip',
        'gs://path/file-release-2.zip',
        'gs://path/file-release-1.zip',
    ]

  def _assert_env_vars(self):
    self.assertEqual(os.environ['BUILD_URL'], 'gs://path/file-release-2.zip')
    self.assertEqual(
        os.environ['BUILD_DIR'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions')

  @parameterized.parameterized.expand(['True', 'False'])
  def test_setup_fuzz(self, unpack_all):
    """Tests setting up a build during fuzzing."""
    os.environ['UNPACK_ALL_FUZZ_TARGETS_AND_FILES'] = unpack_all
    os.environ['TASK_NAME'] = 'fuzz'

    self.mock.time.return_value = 1000.0
    build = build_manager.setup_regular_build(
        2, target_weights=self.target_weights)
    self.assertIsInstance(build, build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)

    self.assertEqual('target2', os.environ['FUZZ_TARGET'])
    self._assert_env_vars()
    self.assertEqual(os.environ['APP_REVISION'], '2')

    self.assertEqual(1, self.mock.unpack.call_count)

    # Test setting up build again.
    os.environ['FUZZ_TARGET'] = ''
    self.mock.time.return_value = 1005.0
    self.assertIsInstance(
        build_manager.setup_regular_build(
            2, target_weights=self.target_weights), build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)

    # If it was a partial build, the unpack should be called again.
    if unpack_all == 'True':
      self.assertEqual(1, self.mock.unpack.call_count)
    else:
      self.assertEqual(2, self.mock.unpack.call_count)

    self.assertEqual('target2', os.environ['FUZZ_TARGET'])
    self.assertEqual('3', os.environ['FUZZ_TARGET_COUNT'])

  @parameterized.parameterized.expand(['True', 'False'])
  def test_setup_nonfuzz(self, unpack_all):
    """Test setting up a build during a non-fuzz task."""
    os.environ['UNPACK_ALL_FUZZ_TARGETS_AND_FILES'] = unpack_all
    os.environ['TASK_NAME'] = 'progression'
    os.environ['FUZZ_TARGET'] = 'target3'

    build = build_manager.setup_regular_build(2)
    self.assertIsInstance(build, build_manager.RegularBuild)

    self.assertEqual(1, self.mock.unpack.call_count)
    if unpack_all == 'True':
      self.assertIsNone(build_manager._get_file_match_callback())
    else:
      self.assertIsNotNone(build_manager._get_file_match_callback())

    class FileMatchCallbackChecker(object):
      """Used to verify that the callback passed to unpack is what we expect."""

      def __eq__(_, file_match_callback):  # pylint: disable=no-self-argument
        if unpack_all == 'True':
          # Ensure that |file_match_callback| is always None when we are
          # unpacking everything.
          self.assertIsNone(file_match_callback)
          return True

        self.assertIsNotNone(file_match_callback)
        self.assertEqual(file_match_callback.__name__, 'file_match_callback')
        self.assertTrue(isinstance(file_match_callback, types.FunctionType))
        return True

    file_match_callback_checker = FileMatchCallbackChecker()
    self.mock.unpack.assert_called_with(
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/'
        'revisions/file-release-2.zip',
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions',
        file_match_callback=file_match_callback_checker,
        trusted=True)
    self.assertEqual('target3', os.environ['FUZZ_TARGET'])

    build = build_manager.setup_regular_build(2)
    self.assertIsInstance(build, build_manager.RegularBuild)

    # If it was a partial build, the unpack should be called again.
    if unpack_all != 'True':
      self.assertEqual(2, self.mock.unpack.call_count)
      self.mock.unpack.assert_called_with(
          '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/'
          'revisions/file-release-2.zip',
          '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions',
          file_match_callback=file_match_callback_checker,
          trusted=True)

    self.assertEqual('target3', os.environ['FUZZ_TARGET'])

  def test_delete(self):
    """Test deleting this build."""
    os.environ['FUZZ_TARGET'] = 'fuzz_target'
    os.environ['RELEASE_BUILD_BUCKET_PATH'] = (
        'gs://path/file-release-([0-9]+).zip')

    self.mock.get_build_urls_list.return_value = [
        'gs://path/file-release-2.zip',
    ]

    build = build_manager.setup_regular_build(2)
    self.assertTrue(
        os.path.isdir(
            '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions'))
    build.delete()
    self.assertFalse(
        os.path.isdir(
            '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/revisions'))
    self.assertTrue(
        os.path.isdir('/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025'))


class SymbolizedBuildTest(fake_filesystem_unittest.TestCase):
  """Tests for symbolized build setup."""

  def setUp(self):
    """Setup for symbolized build test."""
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.get_build_urls_list',
        'clusterfuzz._internal.build_management.build_manager.Build._unpack_build',
        'clusterfuzz._internal.system.shell.clear_temp_directory', 'time.time'
    ])

    test_helpers.patch_environ(self)

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_NAME'] = FAKE_APP_NAME
    os.environ['JOB_NAME'] = 'job'

    self.release_urls = None
    self.debug_urls = None

    self.mock._unpack_build.side_effect = _mock_unpack_build
    self.mock.get_build_urls_list.side_effect = self._mock_get_build_urls_list

  def _mock_get_build_urls_list(self, bucket_path):
    if 'release' in bucket_path:
      return self.release_urls or []

    return self.debug_urls or []

  def _prepare_test(self, release_urls, debug_urls):
    """Prepare test."""
    os.environ['SYM_RELEASE_BUILD_BUCKET_PATH'] = ''
    os.environ['SYM_DEBUG_BUILD_BUCKET_PATH'] = ''

    if release_urls:
      os.environ['SYM_RELEASE_BUILD_BUCKET_PATH'] = (
          'gs://path/file-release-([0-9]+).zip')

    if debug_urls:
      os.environ['SYM_DEBUG_BUILD_BUCKET_PATH'] = (
          'gs://path/file-debug-([0-9]+).zip')

    self.release_urls = release_urls
    self.debug_urls = debug_urls

  def _assert_env_vars_both(self):
    """Assert env vars."""
    self.assertEqual(os.environ['BUILD_URL'], 'gs://path/file-release-2.zip')

    self.assertEqual(
        os.environ['APP_PATH'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/symbolized/'
        'release/app')

    self.assertEqual(
        os.environ['APP_PATH_DEBUG'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/symbolized/'
        'debug/app')

    self.assertEqual(
        os.environ['APP_DIR'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/symbolized/'
        'debug')

    self.assertEqual(
        os.environ['LLVM_SYMBOLIZER_PATH'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/symbolized/'
        'debug/llvm-symbolizer')

    self.assertEqual(
        os.environ['BUILD_DIR'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/symbolized/'
        'debug')

  def _assert_env_vars_release(self):
    """Assert env vars for release."""
    self.assertEqual(os.environ['BUILD_URL'], 'gs://path/file-release-2.zip')

    self.assertEqual(
        os.environ['APP_PATH'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/symbolized/'
        'release/app')
    self.assertEqual(os.environ['APP_PATH_DEBUG'], '')

    self.assertEqual(
        os.environ['APP_DIR'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/symbolized/'
        'release')

    self.assertEqual(
        os.environ['LLVM_SYMBOLIZER_PATH'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/symbolized/'
        'release/llvm-symbolizer')

    self.assertEqual(
        os.environ['BUILD_DIR'],
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/symbolized/'
        'release')

  def test_setup_both(self):
    """Tests setting up both release and debug builds."""
    self._prepare_test([
        'gs://path/file-release-10.zip',
        'gs://path/file-release-2.zip',
        'gs://path/file-release-1.zip',
    ], [
        'gs://path/file-debug-10.zip',
        'gs://path/file-debug-2.zip',
        'gs://path/file-debug-1.zip',
    ])

    self.mock.time.return_value = 1000.0
    build = build_manager.setup_symbolized_builds(2)
    self.assertIsInstance(build, build_manager.SymbolizedBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)

    self.mock._unpack_build.assert_has_calls([
        mock.call(
            mock.ANY, '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025',
            '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/'
            'symbolized/release', 'gs://path/file-release-2.zip'),
        mock.call(
            mock.ANY, '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025',
            '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/'
            'symbolized/debug', 'gs://path/file-debug-2.zip'),
    ])
    self._assert_env_vars_both()
    self.assertEqual(os.environ['APP_REVISION'], '2')

    self.mock.time.return_value = 1005.0
    build = build_manager.setup_symbolized_builds(2)
    self.assertIsInstance(build, build_manager.SymbolizedBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)

    self._assert_env_vars_both()
    self.assertEqual(os.environ['APP_REVISION'], '2')
    self.assertTrue(self.mock._unpack_build.call_count, 2)

    self.assertIsNone(build_manager.setup_symbolized_builds(4))

  def test_setup_release_only(self):
    """Tests setting up release builds."""
    self._prepare_test([
        'gs://path/file-release-10.zip',
        'gs://path/file-release-2.zip',
        'gs://path/file-release-1.zip',
    ], None)

    self.mock.time.return_value = 1000.0
    build = build_manager.setup_symbolized_builds(2)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)

    self.assertIsInstance(build, build_manager.SymbolizedBuild)
    self.mock._unpack_build.assert_called_once_with(
        mock.ANY, '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025',
        '/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/'
        'symbolized/release', 'gs://path/file-release-2.zip')
    self._assert_env_vars_release()
    self.assertEqual(os.environ['APP_REVISION'], '2')

    self.mock.time.return_value = 1005.0
    self.assertIsInstance(
        build_manager.setup_symbolized_builds(2), build_manager.SymbolizedBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)
    self._assert_env_vars_release()
    self.assertEqual(os.environ['APP_REVISION'], '2')
    self.assertTrue(self.mock._unpack_build.call_count, 1)

    self.assertIsNone(build_manager.setup_symbolized_builds(4))

  def test_delete(self):
    """Test deleting this build."""
    self._prepare_test([
        'gs://path/file-release-10.zip',
        'gs://path/file-release-2.zip',
        'gs://path/file-release-1.zip',
    ], [
        'gs://path/file-debug-10.zip',
        'gs://path/file-debug-2.zip',
        'gs://path/file-debug-1.zip',
    ])

    build = build_manager.setup_symbolized_builds(2)
    self.assertTrue(
        os.path.isdir('/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/'
                      'symbolized/release'))
    self.assertTrue(
        os.path.isdir('/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/'
                      'symbolized/debug'))
    build.delete()
    self.assertFalse(
        os.path.isdir('/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/'
                      'symbolized/release'))
    self.assertFalse(
        os.path.isdir('/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025/'
                      'symbolized/debug'))
    self.assertTrue(
        os.path.isdir('/builds/path_be4c9ca0267afcd38b7c1a3eebb5998d0908f025'))


class ProductionBuildTest(fake_filesystem_unittest.TestCase):
  """Tests for production build setup."""

  def setUp(self):
    """Setup for production build test."""
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.get_build_urls_list',
        'clusterfuzz._internal.build_management.build_manager.Build._unpack_build',
        'clusterfuzz._internal.system.shell.clear_temp_directory',
        'time.sleep',
        'time.time',
    ])

    test_helpers.patch_environ(self)

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_NAME'] = FAKE_APP_NAME
    os.environ['JOB_NAME'] = 'job'
    os.environ['VERSION_PATTERN'] = r'.*-([0-9.]+).zip'

    os.environ['STABLE_BUILD_BUCKET_PATH'] = (
        'gs://path/file-stable-([0-9.]+).zip')
    os.environ['BETA_BUILD_BUCKET_PATH'] = ('gs://path/file-beta-([0-9.]+).zip')

    self.mock._unpack_build.side_effect = _mock_unpack_build
    self.mock.get_build_urls_list.side_effect = self._mock_get_build_urls_list

  def _mock_get_build_urls_list(self, bucket_path):
    """Mock get_build_urls_list()"""
    if not bucket_path:
      return []

    if 'extended_stable' in bucket_path:
      return [
          'gs://path/file-extended_stable-45.0.1824.2.zip',
          'gs://path/file-extended_stable-44.0.1824.1.zip',
          'gs://path/file-extended_stable-44.0.1822.2.zip',
      ]

    if 'stable' in bucket_path:
      return [
          'gs://path/file-stable-45.0.1824.2.zip',
          'gs://path/file-stable-44.0.1824.1.zip',
          'gs://path/file-stable-44.0.1822.2.zip',
      ]

    return [
        'gs://path/file-beta-45.0.1824.2.zip',
        'gs://path/file-beta-44.0.1824.1.zip',
        'gs://path/file-beta-44.0.1822.2.zip',
    ]

  def _assert_env_vars(self, build_type):
    """Assert env vars."""
    self.assertEqual(os.environ['BUILD_URL'],
                     'gs://path/file-%s-45.0.1824.2.zip' % build_type)

    self.assertEqual(
        os.environ['APP_PATH'],
        '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b/%s/app' %
        build_type)

    self.assertEqual(os.environ['APP_PATH_DEBUG'], '')

    self.assertEqual(
        os.environ['APP_DIR'],
        '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b/%s' % build_type)

    self.assertEqual(
        os.environ['LLVM_SYMBOLIZER_PATH'],
        '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b/%s/'
        'llvm-symbolizer' % build_type)

    self.assertEqual(
        os.environ['BUILD_DIR'],
        '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b/%s' % build_type)

  def test_setup_stable(self):
    """Test setting up a stable build."""
    self.mock.time.return_value = 1000.0
    build = build_manager.setup_production_build('stable')
    self.assertIsInstance(build, build_manager.ProductionBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)

    self.assertEqual(build.revision, '45.0.1824.2')
    self.assertEqual(os.environ['APP_REVISION'], '45.0.1824.2')
    self._assert_env_vars('stable')

    self.mock._unpack_build.assert_called_once_with(
        mock.ANY, '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b',
        '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b/stable',
        'gs://path/file-stable-45.0.1824.2.zip')

    self.mock.time.return_value = 1005.0
    self.assertEqual(
        build_manager.setup_production_build('stable').revision, '45.0.1824.2')
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)
    self._assert_env_vars('stable')
    self.assertEqual(self.mock._unpack_build.call_count, 1)

    self.assertIsNone(build_manager.setup_production_build('wrong'))

  def test_setup_beta(self):
    """Test setting up a stable build."""
    self.mock.time.return_value = 1000.0
    build = build_manager.setup_production_build('beta')
    self.assertIsInstance(build, build_manager.ProductionBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)
    self.assertEqual(os.environ['APP_REVISION'], '45.0.1824.2')
    self._assert_env_vars('beta')

    self.mock._unpack_build.assert_called_once_with(
        mock.ANY, '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b',
        '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b/beta',
        'gs://path/file-beta-45.0.1824.2.zip')

    self.mock.time.return_value = 1005.0
    self.assertEqual(
        build_manager.setup_production_build('beta').revision, '45.0.1824.2')
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)
    self._assert_env_vars('beta')
    self.assertEqual(self.mock._unpack_build.call_count, 1)

  def test_setup_extended_stable(self):
    """Test setting up an extended stable build."""
    os.environ['EXTENDED_STABLE_BUILD_BUCKET_PATH'] = (
        'gs://path/file-extended_stable-([0-9.]+).zip')

    self.mock.time.return_value = 1000.0
    build = build_manager.setup_production_build('extended_stable')
    self.assertIsInstance(build, build_manager.ProductionBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)

    self.assertEqual(build.revision, '45.0.1824.2')
    self.assertEqual(os.environ['APP_REVISION'], '45.0.1824.2')
    self._assert_env_vars('extended_stable')

    self.mock._unpack_build.assert_called_once_with(
        mock.ANY, '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b',
        '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b/extended_stable',
        'gs://path/file-extended_stable-45.0.1824.2.zip')

    self.mock.time.return_value = 1005.0
    self.assertEqual(
        build_manager.setup_production_build('extended_stable').revision,
        '45.0.1824.2')
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)
    self._assert_env_vars('extended_stable')
    self.assertEqual(self.mock._unpack_build.call_count, 1)

    self.assertIsNone(build_manager.setup_production_build('wrong'))

  def test_delete(self):
    """Test deleting this build."""
    build = build_manager.setup_production_build('stable')
    self.assertTrue(
        os.path.isdir(
            '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b/stable'))
    build.delete()
    self.assertFalse(
        os.path.isdir(
            '/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b/stable'))
    self.assertTrue(
        os.path.isdir('/builds/path_8102046d3cea496c945743eb5f79284e7b10b51b'))


@test_utils.with_cloud_emulators('datastore')
class CustomBuildTest(fake_filesystem_unittest.TestCase):
  """Tests for custom build setup."""

  def setUp(self):
    """Setup for custom build test."""
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager._make_space_for_build',
        'clusterfuzz._internal.system.shell.clear_temp_directory',
        'clusterfuzz._internal.google_cloud_utils.blobs.read_blob_to_disk',
        'clusterfuzz._internal.system.archive.unpack',
        'time.sleep',
        'time.time',
    ])

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_NAME'] = FAKE_APP_NAME
    os.environ['CUSTOM_BINARY'] = 'True'

    data_types.Job(
        name='job_custom',
        custom_binary_key='key',
        custom_binary_filename='custom_binary.zip',
        custom_binary_revision=3).put()

    test_utils.set_up_pyfakefs(self)
    self.mock._make_space_for_build.return_value = True
    self.mock.unpack.side_effect = self._mock_unpack
    self.mock.read_blob_to_disk.return_value = True

  # pylint: disable=unused-argument
  def _mock_unpack(self, _, build_dir, trusted=True):
    """mock archive.unpack."""
    _mock_unpack_build(None, None, build_dir, None)

  def _assert_env_vars(self):
    """Assert env vars."""
    self.assertEqual(os.environ['APP_PATH'], '/builds/job_custom/custom/app')
    self.assertEqual(os.environ['APP_DIR'], '/builds/job_custom/custom')
    self.assertEqual(os.environ['APP_PATH_DEBUG'], '')

    self.assertEqual(os.environ['LLVM_SYMBOLIZER_PATH'],
                     '/builds/job_custom/custom/llvm-symbolizer')

    self.assertEqual(os.environ['APP_REVISION'], '3')
    self.assertEqual(os.environ['BUILD_KEY'], 'key')
    self.assertEqual(os.environ['BUILD_DIR'], '/builds/job_custom/custom')

  def test_setup(self):
    """Test setting up a custom binary."""
    os.environ['JOB_NAME'] = 'job_custom'
    self.mock.time.return_value = 1000.0
    build = build_manager.setup_custom_binary()
    self.assertIsInstance(build, build_manager.CustomBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)

    self.mock.read_blob_to_disk.assert_called_once_with(
        'key', '/builds/job_custom/custom/custom_binary.zip')

    self.mock.unpack.assert_called_once_with(
        '/builds/job_custom/custom/custom_binary.zip',
        '/builds/job_custom/custom',
        trusted=True)

    self._assert_env_vars()

    self.mock.time.return_value = 1005.0
    self.assertIsInstance(build_manager.setup_custom_binary(),
                          build_manager.CustomBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)
    self.assertEqual(self.mock.read_blob_to_disk.call_count, 1)
    self.assertEqual(self.mock.unpack.call_count, 1)
    self._assert_env_vars()

  def test_setup_shared(self):
    """Test setting up a custom binary (shared)."""
    os.environ['JOB_NAME'] = 'job_share'
    os.environ['SHARE_BUILD_WITH_JOB_TYPE'] = 'job_custom'

    self.mock.time.return_value = 1000.0
    build = build_manager.setup_custom_binary()
    self.assertIsInstance(build, build_manager.CustomBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)

    self.mock.read_blob_to_disk.assert_called_once_with(
        'key', '/builds/job_custom/custom/custom_binary.zip')

    self.mock.unpack.assert_called_once_with(
        '/builds/job_custom/custom/custom_binary.zip',
        '/builds/job_custom/custom',
        trusted=True)

    self._assert_env_vars()
    self.assertEqual(os.environ['JOB_NAME'], 'job_share')

  def test_delete(self):
    """Test deleting this build."""
    os.environ['JOB_NAME'] = 'job_custom'
    build = build_manager.setup_custom_binary()
    self.assertTrue(os.path.isdir('/builds/job_custom/custom'))
    build.delete()
    self.assertFalse(os.path.isdir('/builds/job_custom/custom'))
    self.assertTrue(os.path.isdir('/builds/job_custom'))


class SystemBuildTest(fake_filesystem_unittest.TestCase):
  """Tests for system build setup."""

  def setUp(self):
    """Setup for system build test."""
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch(self, [
        'clusterfuzz._internal.system.shell.clear_temp_directory',
    ])

    test_helpers.patch_environ(self)

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_NAME'] = FAKE_APP_NAME
    os.environ['SYSTEM_BINARY_DIR'] = '/system_binary'
    _mock_unpack_build(
        build_manager.SystemBuild('/'), None, '/system_binary', None)

  def test_setup(self):
    """Test setting up a system binary."""
    self.assertIsNotNone(build_manager.setup_system_binary())

    self.assertEqual(os.environ['APP_REVISION'], '1')
    self.assertEqual(os.environ['APP_PATH'], '/system_binary/app')
    self.assertEqual(os.environ['APP_DIR'], '/system_binary')
    self.assertEqual(os.environ['BUILD_DIR'], '/system_binary')

  def test_delete(self):
    """Test deleting this build."""
    build = build_manager.setup_system_binary()
    with self.assertRaises(build_manager.BuildManagerException):
      build.delete()


class AuxiliaryRegularBuildTest(fake_filesystem_unittest.TestCase):
  """Tests for auxiliary build setup."""

  def setUp(self):
    """Setup for auxiliary regular build Test."""
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.get_build_urls_list',
        'clusterfuzz._internal.build_management.build_manager.Build._unpack_build',
        'clusterfuzz._internal.system.shell.clear_temp_directory',
        'time.time',
    ])

    test_helpers.patch_environ(self)

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_NAME'] = FAKE_APP_NAME
    os.environ['JOB_NAME'] = 'job'

    self.mock._unpack_build.side_effect = _mock_unpack_build

  def _assert_env_vars(self):
    """An auxiliary build show not overwrite the common env variables, but
    should set up some variables with a prefix in their names."""
    self.assertIsNone(os.environ.get('APP_PATH'))
    self.assertIsNone(os.environ.get('APP_REVISION'))
    self.assertIsNone(os.environ.get('BUILD_DIR'))
    self.assertIsNone(os.environ.get('BUILD_URL'))
    self.assertIsNone(os.environ.get('GN_ARGS_PATH'))

    self.assertEqual(os.environ['DATAFLOW_APP_PATH'], '')
    self.assertEqual(
        os.environ['DATAFLOW_BUILD_DIR'],
        '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/dataflow')
    self.assertEqual(os.environ['DATAFLOW_BUILD_URL'],
                     'gs://path/file-dataflow-10.zip')

  def test_setup(self):
    """Tests setting up a build."""
    os.environ['DATAFLOW_BUILD_BUCKET_PATH'] = (
        'gs://path/file-dataflow-([0-9]+).zip')

    self.mock.get_build_urls_list.return_value = [
        'gs://path/file-dataflow-10.zip',
        'gs://path/file-dataflow-2.zip',
        'gs://path/file-dataflow-1.zip',
    ]

    self.mock.time.return_value = 1000.0
    build = build_manager.setup_trunk_build(
        [os.environ['DATAFLOW_BUILD_BUCKET_PATH']], build_prefix='DATAFLOW')
    self.assertIsInstance(build, build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)

    self.mock._unpack_build.assert_called_once_with(
        mock.ANY, '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d',
        '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/dataflow',
        'gs://path/file-dataflow-10.zip', None)

    self._assert_env_vars()

    self.mock.time.return_value = 1005.0
    self.assertIsInstance(
        build_manager.setup_trunk_build(
            [os.environ['DATAFLOW_BUILD_BUCKET_PATH']],
            build_prefix='DATAFLOW'), build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)

    # Already set up.
    self.assertEqual(self.mock._unpack_build.call_count, 1)
    self._assert_env_vars()

  def test_delete(self):
    """Test deleting this build."""
    os.environ['DATAFLOW_BUILD_BUCKET_PATH'] = (
        'gs://path/file-dataflow-([0-9]+).zip')

    self.mock.get_build_urls_list.return_value = [
        'gs://path/file-dataflow-2.zip',
    ]

    build = fuzz_task.build_manager.setup_trunk_build(
        [os.environ['DATAFLOW_BUILD_BUCKET_PATH']], 'DATAFLOW')
    self.assertTrue(
        os.path.isdir(
            '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/revisions'))
    build.delete()
    self.assertFalse(
        os.path.isdir(
            '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/dataflow'))
    self.assertTrue(
        os.path.isdir('/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d'))


class AuxiliaryRegularLibFuzzerBuildTest(fake_filesystem_unittest.TestCase):
  """Tests for auxiliary libFuzzer build setup."""

  def setUp(self):
    """Setup for auxiliary regular libFuzzer build test."""
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.utils.get_fuzz_targets',
        'clusterfuzz._internal.build_management.build_manager.get_build_urls_list',
        'clusterfuzz._internal.build_management.build_manager.Build.'
        '_get_fuzz_targets_from_archive',
        'clusterfuzz._internal.build_management.build_manager._make_space',
        'clusterfuzz._internal.build_management.build_manager._make_space_for_build',
        'clusterfuzz._internal.system.shell.clear_temp_directory',
        'clusterfuzz._internal.google_cloud_utils.storage.copy_file_from',
        'clusterfuzz._internal.google_cloud_utils.storage.get_download_file_size',
        'clusterfuzz._internal.system.archive.unpack',
        'time.time',
    ])

    test_helpers.patch_environ(self)

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_NAME'] = FAKE_APP_NAME
    os.environ['JOB_NAME'] = 'libfuzzer_job'

    self.target_weights = {
        'target1': 0.0,
        'target2': 1.0,
        'target3': 0.0,
    }
    self.mock.get_download_file_size.return_value = 1
    self.mock.copy_file_from.return_value = True

    mock_targets_from_archive = self.mock._get_fuzz_targets_from_archive
    mock_targets_from_archive.return_value.__iter__.return_value = [
        'target1', 'target2', 'target3'
    ]
    self.mock.get_fuzz_targets.return_value = [
        '/path/target1', '/path/target2', '/path/target3'
    ]
    self.mock._make_space.return_value = True
    self.mock._make_space_for_build.return_value = True
    self.mock.unpack.return_value = True
    self.mock.time.return_value = 1000.0

    os.environ['DATAFLOW_BUILD_BUCKET_PATH'] = (
        'gs://path/file-dataflow-([0-9]+).zip')

    self.mock.get_build_urls_list.return_value = [
        'gs://path/file-dataflow-10.zip',
        'gs://path/file-dataflow-2.zip',
        'gs://path/file-dataflow-1.zip',
    ]

  def _assert_env_vars(self):
    # Assert the expected values of environment variables.
    self.assertIsNone(os.environ.get('APP_REVISION'))
    self.assertIsNone(os.environ.get('BUILD_URL'))

    self.assertEqual(os.environ['DATAFLOW_APP_REVISION'], '10')
    self.assertEqual(
        os.environ['DATAFLOW_BUILD_DIR'],
        '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/dataflow')
    self.assertEqual(os.environ['DATAFLOW_BUILD_URL'],
                     'gs://path/file-dataflow-10.zip')

  @parameterized.parameterized.expand(['True', 'False'])
  def test_setup_fuzz(self, unpack_all):
    """Tests setting up a build during fuzzing."""
    os.environ['UNPACK_ALL_FUZZ_TARGETS_AND_FILES'] = unpack_all
    os.environ['TASK_NAME'] = 'fuzz'
    self.mock.time.return_value = 1000.0

    class FileMatchCallbackChecker(object):
      """Used to verify that the callback passed to unpack is what we expect."""

      def __eq__(_, file_match_callback):  # pylint: disable=no-self-argument
        if unpack_all == 'True':
          # Ensure that |file_match_callback| is always None when we are
          # unpacking everything.
          self.assertIsNone(file_match_callback)
          return True

        self.assertIsNotNone(file_match_callback)
        self.assertEqual(file_match_callback.__name__, 'file_match_callback')
        self.assertTrue(isinstance(file_match_callback, types.FunctionType))
        return True

    # Test setting up build with a fuzz target specified (comes from regular
    # build setup).
    os.environ['FUZZ_TARGET'] = 'target1'

    if unpack_all == 'True':
      self.assertIsNone(build_manager._get_file_match_callback())
    else:
      self.assertIsNotNone(build_manager._get_file_match_callback())

    build = build_manager.setup_trunk_build(
        [os.environ['DATAFLOW_BUILD_BUCKET_PATH']],
        build_prefix='DATAFLOW',
        target_weights=self.target_weights)
    self.assertIsInstance(build, build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)
    self.assertEqual('target1', os.environ['FUZZ_TARGET'])
    self._assert_env_vars()

    self.assertEqual(1, self.mock.unpack.call_count)
    file_match_callback_checker = FileMatchCallbackChecker()
    self.mock.unpack.assert_called_with(
        '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/'
        'dataflow/file-dataflow-10.zip',
        '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/dataflow',
        file_match_callback=file_match_callback_checker,
        trusted=True)

    os.environ['FUZZ_TARGET'] = 'target3'
    self.mock.time.return_value = 1005.0
    self.assertIsInstance(
        build_manager.setup_trunk_build(
            [os.environ['DATAFLOW_BUILD_BUCKET_PATH']],
            build_prefix='DATAFLOW',
            target_weights=self.target_weights), build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1005.0)

    # An auxiliary build set up should not choose and overwrite the fuzz target.
    self.assertEqual('target3', os.environ['FUZZ_TARGET'])

    # If it was a partial build, the unpack should be called again.
    if unpack_all == 'True':
      self.assertEqual(1, self.mock.unpack.call_count)
    else:
      self.assertEqual(2, self.mock.unpack.call_count)

    self.mock.unpack.assert_called_with(
        '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/'
        'dataflow/file-dataflow-10.zip',
        '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/dataflow',
        file_match_callback=file_match_callback_checker,
        trusted=True)

  def test_delete(self):
    """Test deleting this build."""
    os.environ['FUZZ_TARGET'] = 'fuzz_target'
    os.environ['DATAFLOW_BUILD_BUCKET_PATH'] = (
        'gs://path/file-dataflow-([0-9]+).zip')

    self.mock.get_build_urls_list.return_value = [
        'gs://path/file-dataflow-2.zip',
    ]

    build = build_manager.setup_trunk_build(
        [os.environ['DATAFLOW_BUILD_BUCKET_PATH']], 'DATAFLOW')
    self.assertTrue(
        os.path.isdir(
            '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/dataflow'))
    build.delete()
    self.assertFalse(
        os.path.isdir(
            '/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d/dataflow'))
    self.assertTrue(
        os.path.isdir('/builds/path_2992e823e35fd34a63e0f8733cdafd6875036a1d'))


@mock.patch(
    'clusterfuzz._internal.build_management.build_manager.MAX_EVICTED_BUILDS',
    3)
class BuildEvictionTests(fake_filesystem_unittest.TestCase):
  """Build eviction tests."""

  def setUp(self):
    """Setup for build eviction tests."""
    test_utils.set_up_pyfakefs(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.is_chromium',
        'clusterfuzz._internal.system.shell.get_free_disk_space',
        'clusterfuzz._internal.system.archive.extracted_size',
    ])

    test_helpers.patch_environ(self)

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'

    os.makedirs('/builds/build1/revisions')
    os.makedirs('/builds/build2/revisions')
    os.makedirs('/builds/build3/revisions')
    os.makedirs('/builds/build4/revisions')
    self.fs.create_file(
        '/builds/build1/.timestamp', contents='1486166114.668105')
    self.fs.create_file(
        '/builds/build2/.timestamp', contents='1486166110.142942')
    self.fs.create_file(
        '/builds/build3/.timestamp', contents='1486166112.180345')

    self.free_disk_space = []
    self.mock.is_chromium.return_value = True

  def _mock_free_disk_space(self, _):
    return self.free_disk_space.pop(0)

  def test_make_space_for_build_remove_one_build(self):
    """Test make_space_for_build (remove 1 build)."""
    self.mock.extracted_size.return_value = 1 * 1024 * 1024 * 1024  # 1 GB
    self.mock.get_free_disk_space.side_effect = self._mock_free_disk_space
    self.free_disk_space = [
        9 * 1024 * 1024 * 1024,
        24 * 1024 * 1024 * 1024,
    ]

    self.assertTrue(
        build_manager._make_space_for_build('/archive.zip', '/builds/build4'))

    self.assertTrue(os.path.isdir('/builds/build1'))
    self.assertFalse(os.path.isdir('/builds/build2'))
    self.assertTrue(os.path.isdir('/builds/build3'))
    self.assertTrue(os.path.isdir('/builds/build4'))

  def test_make_space_for_build_remove_two_builds(self):
    """Test make_space_for_build (remove 2 builds)."""
    self.mock.extracted_size.return_value = 1 * 1024 * 1024 * 1024  # 1 GB
    self.mock.get_free_disk_space.side_effect = self._mock_free_disk_space
    self.free_disk_space = [
        8 * 1024 * 1024 * 1024,
        9 * 1024 * 1024 * 1024,
        12 * 1024 * 1024 * 1024,
    ]

    self.assertTrue(
        build_manager._make_space_for_build('/archive.zip', '/builds/build4'))

    self.assertTrue(os.path.isdir('/builds/build1'))
    self.assertFalse(os.path.isdir('/builds/build2'))
    self.assertFalse(os.path.isdir('/builds/build3'))
    self.assertTrue(os.path.isdir('/builds/build4'))

  def test_make_space_for_build_remove_three_builds(self):
    """Test make_space_for_build (remove 3 builds)."""
    self.mock.extracted_size.return_value = 1 * 1024 * 1024 * 1024  # 1 GB
    self.mock.get_free_disk_space.side_effect = self._mock_free_disk_space
    self.free_disk_space = [
        7 * 1024 * 1024 * 1024,
        8 * 1024 * 1024 * 1024,
        9 * 1024 * 1024 * 1024,
        14 * 1024 * 1024 * 1024,
    ]

    self.assertTrue(
        build_manager._make_space_for_build('/archive.zip', '/builds/build4'))

    self.assertFalse(os.path.isdir('/builds/build1'))
    self.assertFalse(os.path.isdir('/builds/build2'))
    self.assertFalse(os.path.isdir('/builds/build3'))
    self.assertTrue(os.path.isdir('/builds/build4'))

  def test_make_space_for_build_fail(self):
    """Test make_space_for_build failure."""
    self.mock.extracted_size.return_value = 20 * 1024 * 1024 * 1024  # 1 GB
    self.mock.get_free_disk_space.side_effect = self._mock_free_disk_space
    self.free_disk_space = [
        12 * 1024 * 1024 * 1024,
        17 * 1024 * 1024 * 1024,
        18 * 1024 * 1024 * 1024,
        24 * 1024 * 1024 * 1024,
    ]

    self.assertFalse(
        build_manager._make_space_for_build('/archive.zip', '/builds/build4'))

    self.assertFalse(os.path.isdir('/builds/build1'))
    self.assertFalse(os.path.isdir('/builds/build2'))
    self.assertFalse(os.path.isdir('/builds/build3'))
    self.assertTrue(os.path.isdir('/builds/build4'))

  def test_make_space_for_build_no_builds_to_remove(self):
    """Test _make_space_for_build failure (no builds to remove)."""
    shutil.rmtree('/builds/build1')
    shutil.rmtree('/builds/build2')
    shutil.rmtree('/builds/build3')

    self.mock.extracted_size.return_value = 20 * 1024 * 1024 * 1024  # 1 GB
    self.mock.get_free_disk_space.side_effect = self._mock_free_disk_space
    self.free_disk_space = [
        18 * 1024 * 1024 * 1024,
    ]

    self.assertFalse(
        build_manager._make_space_for_build('/archive.zip', '/builds/build4'))


class GetFileMatchCallbackTest(unittest.TestCase):
  """Tests for _get_file_match_callback."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def _test_helper(self, fuzz_target):
    """Test helper."""
    os.environ['FUZZ_TARGET'] = fuzz_target
    match_callback = build_manager._get_file_match_callback()
    self.assertIsNotNone(match_callback)

    # TODO(metzman): This test (and many others), use hardcoded paths, meaning
    # that the tests won't work on Windows. Convert them to using os.path.join.
    # Tests for absolute path.
    self.assertTrue(match_callback('/b/build/my_fuzzer'))
    self.assertTrue(match_callback('/b/build/my_fuzzer.dict'))
    self.assertTrue(match_callback('/b/build/my_fuzzer.options'))
    self.assertTrue(match_callback('/b/build/llvm-symbolizer'))
    self.assertTrue(match_callback('/b/build/icudtl.dat'))
    self.assertTrue(match_callback('/b/build/swiftshader/libGLESv2.so'))
    self.assertTrue(
        match_callback(
            '/b/build/instrumented_libraries/msan/lib/libgcrypt.so.11.8.2'))
    self.assertTrue(match_callback('/b/build/afl-fuzz'))
    # Windows
    self.assertTrue(match_callback('my_fuzzer.exe'))
    # Python
    self.assertTrue(match_callback('my_fuzzer.par'))

    # Tests for relative path.
    self.assertTrue(match_callback('build/my_fuzzer'))
    self.assertTrue(match_callback('build/my_fuzzer.dict'))
    self.assertTrue(match_callback('build/my_fuzzer.options'))
    self.assertTrue(match_callback('build/llvm-symbolizer'))
    self.assertTrue(match_callback('build/icudtl.dat'))
    self.assertTrue(match_callback('build/swiftshader/libGLESv2.so'))
    self.assertTrue(
        match_callback(
            'build/instrumented_libraries/msan/lib/libgcrypt.so.11.8.2'))
    self.assertTrue(match_callback(r'build/afl-fuzz'))

    # Tests for absolute path on Mac platform.
    self.assertTrue(
        match_callback(
            r'/b/build/my_fuzzer.dSYM/Contents/Resources/DWARF/some_dependency')
    )

    # Tests for relative path on Mac platform.
    self.assertTrue(
        match_callback(
            r'build/my_fuzzer.dSYM/Contents/Resources/DWARF/some_dependency'))

    # Tests for other fuzz target files with absolute paths.
    self.assertFalse(match_callback('/b/build/other_fuzzer'))
    self.assertFalse(match_callback('/b/build/other_fuzzer.options'))
    self.assertFalse(match_callback('/b/build/other_fuzzer.zip'))
    self.assertFalse(match_callback('/b/afl-build/other_fuzzer'))
    self.assertTrue(match_callback('/b/build/other_fuzzer.dict'))

    # Tests for other fuzz target files with relative paths.
    self.assertFalse(match_callback('build/other_fuzzer'))
    self.assertFalse(match_callback('build/other_fuzzer.options'))
    self.assertFalse(match_callback('build/other_fuzzer.zip'))
    self.assertFalse(match_callback('afl-build/other_fuzzer'))
    self.assertTrue(match_callback('build/other_fuzzer.dict'))

    # Tests for other fuzz target files with absolute path on Mac platform.
    self.assertFalse(
        match_callback(r'/b/build/other_fuzzer.dSYM/Contents/Resources/DWARF/'
                       'some_dependency'))

    # Tests for other fuzz target files with relative path on Mac platform.
    self.assertFalse(
        match_callback(
            r'build/other_fuzzer.dSYM/Contents/Resources/DWARF/some_dependency')
    )

    # Test for other fuzz target files with relative path to current directory.
    self.assertFalse(match_callback('./other_fuzzer'))

    # Test for a non-dependency file format.
    self.assertFalse(match_callback('README.txt'))

    # Tests for files that appear in Windows libFuzzer builds.
    self.assertTrue(match_callback(fuzz_target + '.exe'))
    self.assertTrue(match_callback(fuzz_target + '.exe.pdb'))
    self.assertTrue(match_callback('shared.dll'))
    self.assertTrue(match_callback('shared.dll.pdb'))
    self.assertFalse(match_callback('other_fuzzer.exe'))
    self.assertFalse(match_callback('other_fuzzer.exe.pdb'))
    # Test that other .par targets are not included.
    self.assertFalse(match_callback('other_fuzzer.par'))
    # Make sure we aren't excluding files that contain but don't end in
    # ".exe.pdb".
    self.assertTrue(match_callback('other_fuzzer.exe.pdbb'))

  def test_with_fuzz_target(self):
    self._test_helper('my_fuzzer')

  def test_without_fuzz_target(self):
    match_callback = build_manager._get_file_match_callback()
    self.assertIsNone(match_callback)


@test_utils.integration
class RpathsTest(unittest.TestCase):
  """Rpath patching tests."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.Build._unpack_build',
        'clusterfuzz._internal.system.shell.clear_temp_directory',
    ])

    os.environ['JOB_NAME'] = 'linux_msan_test'
    os.environ['INSTRUMENTED_LIBRARIES_PATHS_MSAN_CHAINED'] = (
        '/msan/lib:/msan/usr/lib')
    os.environ['INSTRUMENTED_LIBRARIES_PATHS_MSAN_NO_ORIGINS'] = (
        '/msan-no-origins/lib:/msan-no-origins/usr/lib')
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_NAME'] = 'app'

    self.base_build_dir = tempfile.mkdtemp()

  def tearDown(self):
    shutil.rmtree(self.base_build_dir, ignore_errors=True)

  # pylint: disable=unused-argument
  def mock_unpack_build(self, test_build_dir, actual_self, base_build_dir,
                        build_dir, url, target_weights):
    test_data_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'build_manager_data',
        test_build_dir)

    shell.remove_directory(build_dir, recreate=False)
    shutil.copytree(test_data_dir, build_dir)
    return True

  def test_patch_rpaths_no_origins(self):
    """Tests that no-origins libraries are used."""
    self.mock._unpack_build.side_effect = functools.partial(
        self.mock_unpack_build, 'rpath_new')
    build = build_manager.RegularBuild(self.base_build_dir, 1337, 'no-origins')
    self.assertTrue(build.setup())

    self.assertEqual(
        os.path.join(self.base_build_dir, 'revisions', 'app'),
        os.environ['APP_PATH'])

    rpaths = build_manager.get_rpaths(os.environ['APP_PATH'])
    self.assertListEqual(['/msan-no-origins/lib', '/msan-no-origins/usr/lib'],
                         rpaths)

  def test_patch_rpaths_not_available(self):
    """Tests that rpaths aren't added when libs aren't available.."""
    os.environ['JOB_NAME'] = 'linux_asan_test'

    self.mock._unpack_build.side_effect = functools.partial(
        self.mock_unpack_build, 'rpath_new')
    build = build_manager.RegularBuild(self.base_build_dir, 1337,
                                       'chained-origins')
    self.assertTrue(build.setup())

    self.assertEqual(
        os.path.join(self.base_build_dir, 'revisions', 'app'),
        os.environ['APP_PATH'])

    rpaths = build_manager.get_rpaths(os.environ['APP_PATH'])
    self.assertListEqual([], rpaths)

  def test_patch_rpaths_prepend(self):
    """Tests patching rpaths to a binary that already has an rpath."""
    self.mock._unpack_build.side_effect = functools.partial(
        self.mock_unpack_build, 'rpath_prepend_to_existing')
    build = build_manager.RegularBuild(self.base_build_dir, 1337,
                                       'chained-origins')
    self.assertTrue(build.setup())

    self.assertEqual(
        os.path.join(self.base_build_dir, 'revisions', 'app'),
        os.environ['APP_PATH'])

    rpaths = build_manager.get_rpaths(os.environ['APP_PATH'])
    self.assertListEqual(['/msan/lib', '/msan/usr/lib', '$ORIGIN/.'], rpaths)

  def test_patch_rpaths_chrpath(self):
    """Tests patching rpaths to a binary using chrpath."""
    limit = build_manager.PATCHELF_SIZE_LIMIT
    build_manager.PATCHELF_SIZE_LIMIT = 0

    def cleanup():
      build_manager.PATCHELF_SIZE_LIMIT = limit

    self.addCleanup(cleanup)

    self.mock._unpack_build.side_effect = functools.partial(
        self.mock_unpack_build, 'rpath_prepend_to_existing')
    build = build_manager.RegularBuild(self.base_build_dir, 1337,
                                       'chained-origins')
    self.assertTrue(build.setup())

    self.assertEqual(
        os.path.join(self.base_build_dir, 'revisions', 'app'),
        os.environ['APP_PATH'])

    rpaths = build_manager.get_rpaths(os.environ['APP_PATH'])
    self.assertListEqual(['/msan/lib', '/msan/usr/lib', '$ORIGIN/.'], rpaths)

  def test_patch_rpaths_new(self):
    """Tests patching rpaths for a binary that doesn't have an rpath."""
    self.mock._unpack_build.side_effect = functools.partial(
        self.mock_unpack_build, 'rpath_new')
    build = build_manager.RegularBuild(self.base_build_dir, 1337,
                                       'chained-origins')
    self.assertTrue(build.setup())

    self.assertEqual(
        os.path.join(self.base_build_dir, 'revisions', 'app'),
        os.environ['APP_PATH'])

    rpaths = build_manager.get_rpaths(os.environ['APP_PATH'])
    self.assertListEqual(['/msan/lib', '/msan/usr/lib'], rpaths)

  def test_patch_rpaths_libfuzzer(self):
    """Tests patching rpaths for libFuzzer targets."""
    os.environ['JOB_NAME'] = 'libfuzzer_msan_test'

    self.mock._unpack_build.side_effect = functools.partial(
        self.mock_unpack_build, 'rpath_libfuzzer')
    build = build_manager.RegularBuild(self.base_build_dir, 1337,
                                       'chained-origins')
    self.assertTrue(build.setup())

    self.assertEqual('', os.environ['APP_DIR'])

    rpaths = build_manager.get_rpaths(
        os.path.join(os.environ['BUILD_DIR'], 'target_1'))
    self.assertListEqual(['/msan/lib', '/msan/usr/lib'], rpaths)

    rpaths = build_manager.get_rpaths(
        os.path.join(os.environ['BUILD_DIR'], 'target_2'))
    self.assertListEqual(['/msan/lib', '/msan/usr/lib'], rpaths)

  def test_patch_rpaths_existing_msan(self):
    """Tests patching rpaths for a binary that already has a msan rpath
    patched."""
    self.mock._unpack_build.side_effect = functools.partial(
        self.mock_unpack_build, 'rpath_existing_msan')
    build = build_manager.RegularBuild(self.base_build_dir, 1337,
                                       'chained-origins')
    self.assertTrue(build.setup())

    self.assertEqual(
        os.path.join(self.base_build_dir, 'revisions', 'app'),
        os.environ['APP_PATH'])

    rpaths = build_manager.get_rpaths(os.environ['APP_PATH'])
    self.assertListEqual(['/msan/lib', '/msan/usr/lib'], rpaths)


class SortBuildUrlsByRevisionTest(unittest.TestCase):
  """Test _sort_build_urls_by_revision."""

  def test_simple(self):
    """Tests regular case with and without reverse flag set."""
    bucket_path = ('gs://chromium-browser-libfuzzer/'
                   'linux-release-asan/libfuzzer-linux-release-([0-9]+).zip')
    build_urls = [
        'linux-release-asan/libfuzzer-linux-release-359936.zip',
        'linux-release-asan/libfuzzer-linux-release-359950.zip',
        'linux-release-asan/libfuzzer-linux-release-359945.zip',
        'linux-release-asan/libfuzzer-linux-release-359953.zip',
    ]
    expected_result = [
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359953.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359950.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359945.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359936.zip'
    ]
    actual_result = build_manager._sort_build_urls_by_revision(
        build_urls, bucket_path, reverse=True)
    self.assertEqual(expected_result, actual_result)

    expected_result = [
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359936.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359945.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359950.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359953.zip',
    ]
    actual_result = build_manager._sort_build_urls_by_revision(
        build_urls, bucket_path, reverse=False)
    self.assertEqual(expected_result, actual_result)

  def test_duplicate_revision(self):
    """Tests that duplicate revision filename results in an exception."""
    bucket_path = ('gs://chromium-browser-libfuzzer/'
                   'linux-release-asan/libfuzzer-linux-release-(35)[0-9]+.zip')
    build_urls = [
        'linux-release-asan/libfuzzer-linux-release-359936.zip',
        'linux-release-asan/libfuzzer-linux-release-359945.zip',
    ]

    with self.assertRaises(errors.BadStateError):
      build_manager._sort_build_urls_by_revision(
          build_urls, bucket_path, reverse=True)

  def test_revision_in_revision(self):
    """Tests that if a revision is a substring of another revision, then it is
    only shown once and not repeated."""
    bucket_path = ('gs://chromium-browser-libfuzzer/'
                   'linux-release-asan/libfuzzer-linux-release-([0-9]+).zip')
    build_urls = [
        'linux-release-asan/libfuzzer-linux-release-359936.zip',
        'linux-release-asan/libfuzzer-linux-release-936.zip',
        'linux-release-asan/libfuzzer-linux-release-359945.zip',
        'linux-release-asan/libfuzzer-linux-release-599.zip',
    ]

    expected_result = [
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359945.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359936.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-936.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-599.zip'
    ]
    actual_result = build_manager._sort_build_urls_by_revision(
        build_urls, bucket_path, reverse=True)
    self.assertEqual(expected_result, actual_result)

  def test_duplicate_different_prefix(self):
    """Test that we handle duplicate filenames with different prefixes
    properly."""
    bucket_path = ('gs://chromium-browser-libfuzzer/'
                   'linux-release-asan/libfuzzer-linux-release-([0-9]+).zip')
    build_urls = [
        'linux-release-asan/libfuzzer-linux-release-359936.zip',
        'linux-release-asan/duplicate/libfuzzer-linux-release-359936.zip',
        'linux-release-asan/libfuzzer-linux-release-936.zip',
        'linux-release-asan/duplicate/libfuzzer-linux-release-936.zip',
        'linux-release-asan/duplicate/libfuzzer-linux-release-123.zip',
    ]

    expected_result = [
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-359936.zip',
        'gs://chromium-browser-libfuzzer/'
        'linux-release-asan/libfuzzer-linux-release-936.zip',
    ]
    actual_result = build_manager._sort_build_urls_by_revision(
        build_urls, bucket_path, reverse=True)
    self.assertEqual(expected_result, actual_result)

  def test_bucket_root(self):
    """Tests regular case on bucket root with and without reverse flag set."""
    bucket_path = ('gs://chromium-browser-libfuzzer/'
                   'libfuzzer-linux-release-([0-9]+).zip')
    build_urls = [
        'libfuzzer-linux-release-359936.zip',
        'libfuzzer-linux-release-359950.zip',
        'libfuzzer-linux-release-359945.zip',
        'libfuzzer-linux-release-359953.zip',
    ]
    expected_result = [
        'gs://chromium-browser-libfuzzer/libfuzzer-linux-release-359953.zip',
        'gs://chromium-browser-libfuzzer/libfuzzer-linux-release-359950.zip',
        'gs://chromium-browser-libfuzzer/libfuzzer-linux-release-359945.zip',
        'gs://chromium-browser-libfuzzer/libfuzzer-linux-release-359936.zip'
    ]
    actual_result = build_manager._sort_build_urls_by_revision(
        build_urls, bucket_path, reverse=True)
    self.assertEqual(expected_result, actual_result)

    expected_result = [
        'gs://chromium-browser-libfuzzer/libfuzzer-linux-release-359936.zip',
        'gs://chromium-browser-libfuzzer/libfuzzer-linux-release-359945.zip',
        'gs://chromium-browser-libfuzzer/libfuzzer-linux-release-359950.zip',
        'gs://chromium-browser-libfuzzer/libfuzzer-linux-release-359953.zip',
    ]
    actual_result = build_manager._sort_build_urls_by_revision(
        build_urls, bucket_path, reverse=False)
    self.assertEqual(expected_result, actual_result)


class SplitFuzzTargetsBuildTest(fake_filesystem_unittest.TestCase):
  """Tests for split fuzz target build setup."""

  def setUp(self):
    """Setup for split fuzz targets build test."""
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.get_build_urls_list',
        'clusterfuzz._internal.build_management.build_manager._make_space',
        'clusterfuzz._internal.build_management.build_manager._make_space_for_build',
        'clusterfuzz._internal.system.shell.clear_temp_directory',
        'clusterfuzz._internal.google_cloud_utils.storage.copy_file_from',
        'clusterfuzz._internal.google_cloud_utils.storage.get_download_file_size',
        'clusterfuzz._internal.google_cloud_utils.storage.list_blobs',
        'clusterfuzz._internal.google_cloud_utils.storage.read_data',
        'clusterfuzz._internal.system.archive.unpack',
        'time.time',
    ])

    test_helpers.patch_environ(self)

    os.environ['BUILDS_DIR'] = '/builds'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['JOB_NAME'] = 'libfuzzer_job'
    os.environ['UNPACK_ALL_FUZZ_TARGETS_AND_FILES'] = 'True'
    os.environ['FUZZER_DIR'] = os.path.join(os.environ['ROOT_DIR'], 'src',
                                            'clusterfuzz', '_internal', 'bot',
                                            'fuzzers', 'libFuzzer')
    self.fs.add_real_directory(os.environ['FUZZER_DIR'])

    self.mock.list_blobs.return_value = (
        '/subdir/target1/',
        '/subdir/target2/',
        '/subdir/target3/',
        '/subdir/targets.list',
    )
    self.mock.read_data.return_value = (b'target1\ntarget2\ntarget3\n')

    self.target_weights = {
        'target1': 0.0,
        'target2': 1.0,
        'target3': 0.0,
    }
    self.mock.get_download_file_size.return_value = 1
    self.mock.copy_file_from.return_value = True

    self.mock._make_space.return_value = True
    self.mock._make_space_for_build.return_value = True
    self.mock.unpack.return_value = True
    self.mock.time.return_value = 1000.0

    os.environ['FUZZ_TARGET_BUILD_BUCKET_PATH'] = (
        'gs://bucket/subdir/%TARGET%/([0-9]+).zip')

    self.mock.get_build_urls_list.return_value = [
        'gs://bucket/subdir/target2/10.zip',
        'gs://bucket/subdir/target2/2.zip',
        'gs://bucket/subdir/target2/1.zip',
    ]

  def _assert_env_vars(self, target, revision):
    """Assert the expected values of environment variables."""
    self.assertEqual(
        'gs://bucket/subdir/{target}/{revision}.zip'.format(
            target=target, revision=revision), os.environ.get('BUILD_URL'))
    self.assertEqual(str(revision), os.environ['APP_REVISION'])
    self.assertEqual(
        '/builds/bucket_subdir_{target}_'
        '77651789446b3c3a04b9f492ff141f003d437347/revisions'.format(
            target=target),
        os.environ['BUILD_DIR'])
    self.assertEqual('', os.environ['APP_PATH'])

  def test_setup_fuzz(self):
    """Tests setting up a build during fuzzing."""
    os.environ['TASK_NAME'] = 'fuzz'
    self.mock.time.return_value = 1000.0

    build = build_manager.setup_build(target_weights=self.target_weights)
    self.assertIsInstance(build, build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)
    self.assertEqual('target2', os.environ['FUZZ_TARGET'])
    self._assert_env_vars('target2', 10)

    self.assertEqual(1, self.mock.unpack.call_count)
    self.mock.unpack.assert_called_with(
        '/builds/bucket_subdir_target2_77651789446b3c3a04b9f492ff141f003d437347'
        '/revisions/10.zip',
        '/builds/bucket_subdir_target2_77651789446b3c3a04b9f492ff141f003d437347'
        '/revisions',
        file_match_callback=None,
        trusted=True)
    self.assertEqual(3, environment.get_value('FUZZ_TARGET_COUNT'))

  def test_setup_nonfuzz(self):
    """Tests setting up a build during a non-fuzz task."""
    os.environ['FUZZ_TARGET'] = 'target1'
    self.mock.time.return_value = 1000.0

    self.mock.get_build_urls_list.return_value = [
        'gs://bucket/subdir/target1/10.zip',
        'gs://bucket/subdir/target1/8.zip',
    ]

    build = build_manager.setup_build(8)
    self.assertIsInstance(build, build_manager.RegularBuild)
    self.assertEqual(_get_timestamp(build.base_build_dir), 1000.0)
    self.assertEqual('target1', os.environ['FUZZ_TARGET'])
    self._assert_env_vars('target1', 8)

    self.assertEqual(1, self.mock.unpack.call_count)
    self.mock.unpack.assert_called_with(
        '/builds/bucket_subdir_target1_77651789446b3c3a04b9f492ff141f003d437347'
        '/revisions/8.zip',
        '/builds/bucket_subdir_target1_77651789446b3c3a04b9f492ff141f003d437347'
        '/revisions',
        file_match_callback=None,
        trusted=True)
    self.assertIsNone(environment.get_value('FUZZ_TARGET_COUNT'))

  def test_delete(self):
    """Test deleting this build."""
    os.environ['FUZZ_TARGET'] = 'target2'
    build = build_manager.setup_build(10)

    self.assertTrue(
        os.path.isdir('/builds/bucket_subdir_target2_'
                      '77651789446b3c3a04b9f492ff141f003d437347'
                      '/revisions'))
    build.delete()
    self.assertFalse(
        os.path.isdir('/builds/bucket_subdir_target2_'
                      '77651789446b3c3a04b9f492ff141f003d437347'
                      '/revisions'))
    self.assertTrue(
        os.path.isdir('/builds/bucket_subdir_target2_'
                      '77651789446b3c3a04b9f492ff141f003d437347'))

  def test_target_not_built(self):
    """Test a target that's listed in target.list, but not yet built."""
    self.mock.list_blobs.return_value = (
        '/subdir/target1/',
        '/subdir/target3/',
        '/subdir/targets.list',
    )

    targets_list = build_manager._get_targets_list(
        os.environ['FUZZ_TARGET_BUILD_BUCKET_PATH'])
    six.assertCountEqual(self, ['target1', 'target3'], targets_list)


class GetPrimaryBucketPathTest(unittest.TestCase):
  """Tests for get_primary_bucket_path."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def test_release_bucket_path(self):
    """Test primary bucket being a RELEASE_BUILD_BUCKET_PATH."""
    os.environ['RELEASE_BUILD_BUCKET_PATH'] = 'gs://release_build'
    self.assertEqual('gs://release_build',
                     build_manager.get_primary_bucket_path())

  def test_fuzz_target_bucket_path(self):
    """Test primary bucket being a FUZZ_TARGET_BUILD_BUCKET_PATH."""
    os.environ[
        'FUZZ_TARGET_BUILD_BUCKET_PATH'] = 'gs://fuzz_target/%TARGET%/path'
    os.environ['FUZZ_TARGET'] = 'test_target'
    self.assertEqual('gs://fuzz_target/test_target/path',
                     build_manager.get_primary_bucket_path())

  def test_fuzz_target_bucket_path_multi_target(self):
    """Test primary bucket being a FUZZ_TARGET_BUILD_BUCKET_PATH with a multi
    target binary."""
    os.environ[
        'FUZZ_TARGET_BUILD_BUCKET_PATH'] = 'gs://fuzz_target/%TARGET%/path'
    os.environ['FUZZ_TARGET'] = 'test_target@target'
    self.assertEqual('gs://fuzz_target/test_target/path',
                     build_manager.get_primary_bucket_path())

  def test_fuzz_target_bucket_path_no_fuzz_target(self):
    """Test primary bucket being a FUZZ_TARGET_BUILD_BUCKET_PATH with no fuzz
    target defined."""
    os.environ[
        'FUZZ_TARGET_BUILD_BUCKET_PATH'] = 'gs://fuzz_target/%TARGET%/path'
    with self.assertRaises(build_manager.BuildManagerException):
      build_manager.get_primary_bucket_path()

  def test_no_path_defined(self):
    """Test no bucket paths defined."""
    with self.assertRaises(build_manager.BuildManagerException):
      build_manager.get_primary_bucket_path()

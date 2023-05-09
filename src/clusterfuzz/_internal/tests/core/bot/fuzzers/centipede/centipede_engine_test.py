# Copyright 2022 Google LLC
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
"""Tests for centipede engine."""

import collections
import contextlib
import os
import pathlib
import re
import shutil
import tempfile
import unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.centipede import engine
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz.stacktraces import constants

TestPaths = collections.namedtuple(
    'TestPaths', ['data', 'corpus', 'crashes', 'centipede', 'centipede_old'])

# test_data in the repo.
_TEST_DATA_SRC = pathlib.Path(__file__).parent / 'test_data'


@contextlib.contextmanager
def get_test_paths():
  """Returns temporary test_paths that can be used for centipede."""
  with tempfile.TemporaryDirectory() as temp_dir:
    temp_dir = pathlib.Path(temp_dir)
    data_dir = temp_dir / 'test_data'
    shutil.copytree(_TEST_DATA_SRC, data_dir)
    test_paths = TestPaths(data_dir, temp_dir / 'corpus', temp_dir / 'crashes',
                           str(data_dir / 'centipede'),
                           str(data_dir / 'centipede-old'))
    os.mkdir(test_paths.corpus)
    os.mkdir(test_paths.crashes)
    yield test_paths


TEST_PATH = pathlib.Path(__file__).parent
MAX_TIME = 25

# Centipede's runtime args for testing.
_SERVER_COUNT = 1
_RSS_LIMIT = 4096
_ADDRESS_SPACE_LIMIT = 4096
_TIMEOUT_PER_INPUT = 25
_RSS_LIMIT_TEST = 2
_TIMEOUT_PER_INPUT_TEST = 5  # For testing timeout only.
_DEFAULT_ARGUMENTS = [
    '--exit_on_crash=1',
    f'--fork_server={_SERVER_COUNT}',
    f'--rss_limit_mb={_RSS_LIMIT}',
    f'--address_space_limit_mb={_ADDRESS_SPACE_LIMIT}',
]


def setup_testcase(testcase, test_paths):
  """Sets up testcase and corpus."""

  src_testcase_path = test_paths.data / testcase
  copied_testcase_path = test_paths.corpus / testcase
  shutil.copy(src_testcase_path, copied_testcase_path)

  return copied_testcase_path


def setup_centipede(target_name, test_paths, centipede_bin=None):
  """Sets up Centipede for fuzzing."""
  # Setup Centipede's fuzz target.
  engine_impl = engine.Engine()
  target_path = engine_common.find_fuzzer_path(test_paths.data, target_name)
  sanitized_target_path = test_paths.data / fuzzer_utils.EXTRA_BUILD_DIR / target_name

  # Setup Centipede's binary.
  if centipede_bin and centipede_bin != test_paths.centipede:
    os.rename(centipede_bin, test_paths.centipede)

  return engine_impl, target_path, sanitized_target_path


@test_utils.integration
class IntegrationTest(unittest.TestCase):
  """Integration tests."""

  def run(self, *args, **kwargs):
    test_helpers.patch_environ(self)
    with get_test_paths() as test_paths:
      self.test_paths = test_paths
      os.environ['BUILD_DIR'] = str(self.test_paths.data)
      super().run(*args, **kwargs)

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name
    test_helpers.patch(self, ['os.getpid'])
    self.mock.getpid.return_value = 1337

  def compare_arguments(self, expected, actual):
    """Compares expected arguments."""
    self.assertListEqual(expected, actual)

  def _test_reproduce(self,
                      regex,
                      testcase_path,
                      target_name='clusterfuzz_format_target'):
    """Tests reproducing a crash."""
    engine_impl, target_path, sanitized_target_path = setup_centipede(
        target_name, self.test_paths)

    result = engine_impl.reproduce(target_path, testcase_path, [], MAX_TIME)

    self.assertListEqual([f'{sanitized_target_path}', testcase_path],
                         result.command)
    self.assertRegex(result.output, regex)

    return re.search(regex, result.output)

  def test_reproduce_uaf_without_unsanitized_target_binary(self):
    """Tests reproducing an ASAN heap-use-after-free crash when no unsanitized
    target binary was provided."""
    testcase_path = setup_testcase('uaf', self.test_paths)
    crash_info = self._test_reproduce(
        constants.ASAN_REGEX, testcase_path,
        'clusterfuzz_format_target_no_unsanitized')

    # Check the crash reason was parsed correctly.
    self.assertEqual(crash_info.group(1), 'AddressSanitizer')
    self.assertIn('heap-use-after-free', crash_info.group(2))

  def test_reproduce_uaf_old(self):
    """Tests reproducing an old ASAN heap-use-after-free crash."""
    testcase_path = setup_testcase('crash', self.test_paths)
    crash_info = self._test_reproduce(constants.ASAN_REGEX, testcase_path,
                                      'always_crash_fuzzer')

    # Check the crash reason was parsed correctly.
    self.assertEqual(crash_info.group(1), 'AddressSanitizer')
    self.assertIn('heap-use-after-free', crash_info.group(2))

  def test_reproduce_uaf(self):
    """Tests reproducing a ASAN heap-use-after-free crash."""
    testcase_path = setup_testcase('uaf', self.test_paths)
    crash_info = self._test_reproduce(constants.ASAN_REGEX, testcase_path)

    # Check the crash reason was parsed correctly.
    self.assertEqual(crash_info.group(1), 'AddressSanitizer')
    self.assertIn('heap-use-after-free', crash_info.group(2))

  def test_reproduce_oom(self):
    """Tests reproducing a out-of-memory crash."""
    testcase_path = setup_testcase('oom', self.test_paths)
    existing_runner_flags = os.environ.get('CENTIPEDE_RUNNER_FLAGS')
    # For testing oom only.
    os.environ['CENTIPEDE_RUNNER_FLAGS'] = f':rss_limit_mb={_RSS_LIMIT_TEST}:'
    self._test_reproduce(constants.OUT_OF_MEMORY_REGEX, testcase_path)
    if existing_runner_flags:
      os.environ['CENTIPEDE_RUNNER_FLAGS'] = existing_runner_flags
    else:
      os.unsetenv('CENTIPEDE_RUNNER_FLAGS')

  def test_reproduce_timeout(self):
    """Tests reproducing a timeout."""
    testcase_path = setup_testcase('slo', self.test_paths)

    existing_runner_flags = os.environ.get('CENTIPEDE_RUNNER_FLAGS')
    # For testing only.
    os.environ['CENTIPEDE_RUNNER_FLAGS'] = (
        f':timeout_per_input={_TIMEOUT_PER_INPUT_TEST}:')
    self._test_reproduce(constants.CENTIPEDE_TIMEOUT_REGEX, testcase_path)
    if existing_runner_flags:
      os.environ['CENTIPEDE_RUNNER_FLAGS'] = existing_runner_flags
    else:
      os.unsetenv('CENTIPEDE_RUNNER_FLAGS')

  def _run_centipede(self,
                     target_name,
                     dictionary=None,
                     timeout_flag=None,
                     rss_limit=_RSS_LIMIT,
                     centipede_bin=None):
    """Run Centipede for other unittest."""
    if centipede_bin is None:
      centipede_bin = self.test_paths.centipede
    engine_impl, target_path, sanitized_target_path = setup_centipede(
        target_name, self.test_paths, centipede_bin)
    work_dir = '/tmp/temp-1337/workdir'

    options = engine_impl.prepare(self.test_paths.corpus, target_path,
                                  self.test_paths.data)
    # For testing oom only.
    options.arguments = [
        f'--rss_limit_mb={rss_limit}'
        if flag == f'--rss_limit_mb={_RSS_LIMIT}' else flag
        for flag in options.arguments
    ]
    # For testing timeout only.
    if timeout_flag:
      options.arguments = [
          timeout_flag if '--timeout' in flag else flag
          for flag in options.arguments
      ]

    results = engine_impl.fuzz(target_path, options, self.test_paths.crashes,
                               MAX_TIME)

    expected_command = [self.test_paths.centipede]
    if dictionary:
      expected_command.append(f'--dictionary={dictionary}')
    expected_command.extend([
        f'--workdir={work_dir}',
        f'--corpus_dir={self.test_paths.corpus}',
        f'--binary={target_path}',
        f'--extra_binaries={sanitized_target_path}',
        f'--timeout_per_input={_TIMEOUT_PER_INPUT}',
    ] + _DEFAULT_ARGUMENTS)
    expected_command = [
        f'--rss_limit_mb={rss_limit}'
        if flag == f'--rss_limit_mb={_RSS_LIMIT}' else flag
        for flag in expected_command
    ]
    # For testing timeout only.
    if timeout_flag:
      expected_command = [
          timeout_flag if '--timeout' in flag else flag
          for flag in expected_command
      ]

    self.compare_arguments(expected_command, results.command)
    return results

  @test_utils.slow
  def test_fuzz_no_crash(self):
    """Tests fuzzing (no crash)."""
    dictionary = self.test_paths.data / 'test_fuzzer.dict'
    self._run_centipede(target_name='test_fuzzer', dictionary=dictionary)
    self.assertTrue(self.test_paths.corpus.iterdir())

  def _test_crash_log_regex(self,
                            crash_regex,
                            content,
                            timeout_flag=None,
                            rss_limit=_RSS_LIMIT,
                            centipede_bin=None):
    """Fuzzes the target and check if regex matches Centipede's crash log."""
    if centipede_bin is None:
      centipede_bin = self.test_paths.centipede
    results = self._run_centipede(
        target_name='clusterfuzz_format_target',
        timeout_flag=timeout_flag,
        rss_limit=rss_limit,
        centipede_bin=centipede_bin)

    # Check there is one and only one expected crash.
    self.assertEqual(1, len(results.crashes))
    crash = results.crashes[0]
    # Check the crash was saved properly.
    self.assertEqual(self.test_paths.crashes,
                     pathlib.Path(crash.input_path).parent)
    # Check the regex can capture the crash info in the stacktrace.
    self.assertRegex(crash.stacktrace, crash_regex)

    # Check reproducer location format.
    self.assertRegex(results.logs, engine.CRASH_REGEX)
    # Check the prefix was trimmed.
    self.assertNotRegex(results.logs, 'CRASH LOG:.*')

    # Check the correct input was saved.
    with open(crash.input_path, 'r') as f:
      self.assertEqual(content, f.read())

    return re.search(crash_regex, crash.stacktrace)

  def test_crash_uaf_old(self):
    """Tests fuzzing that results in an old ASAN heap-use-after-free crash."""
    setup_testcase('uaf', self.test_paths)
    crash_info = self._test_crash_log_regex(
        constants.ASAN_REGEX,
        'uaf',
        centipede_bin=self.test_paths.centipede_old)

    # Check the crash reason was parsed correctly.
    self.assertEqual(crash_info.group(1), 'AddressSanitizer')
    self.assertIn('heap-use-after-free', crash_info.group(2))

  def test_crash_oom_old(self):
    """Tests fuzzing that results in an old out-of-memory crash."""
    setup_testcase('oom', self.test_paths)
    self._test_crash_log_regex(
        constants.OUT_OF_MEMORY_REGEX,
        'oom',
        rss_limit=_RSS_LIMIT_TEST,
        centipede_bin=self.test_paths.centipede_old)

  def test_crash_uaf(self):
    """Tests fuzzing that results in a ASAN heap-use-after-free crash."""
    setup_testcase('uaf', self.test_paths)
    crash_info = self._test_crash_log_regex(constants.ASAN_REGEX, 'uaf')

    # Check the crash reason was parsed correctly.
    self.assertEqual(crash_info.group(1), 'AddressSanitizer')
    self.assertIn('heap-use-after-free', crash_info.group(2))

  def test_crash_oom(self):
    """Tests fuzzing that results in a out-of-memory crash."""
    setup_testcase('oom', self.test_paths)
    self._test_crash_log_regex(
        constants.OUT_OF_MEMORY_REGEX, 'oom', rss_limit=_RSS_LIMIT_TEST)

  def test_crash_timeout(self):
    """Tests fuzzing that results in a timeout."""
    setup_testcase('slo', self.test_paths)
    self._test_crash_log_regex(
        constants.CENTIPEDE_TIMEOUT_REGEX,
        'slo',
        timeout_flag=f'--timeout_per_input={_TIMEOUT_PER_INPUT_TEST}')


@test_utils.integration
class UnshareIntegrationTest(IntegrationTest):
  """Integration tests."""

  def compare_arguments(self, expected, actual):
    """Compares expected arguments."""
    unshare_path = (
        pathlib.Path(environment.get_value('ROOT_DIR')) / 'resources' /
        'platform' / 'linux' / 'unshare')
    self.assertListEqual([str(unshare_path), '-c', '-n'] + expected, actual)

  def setUp(self):
    super().setUp()
    os.environ['USE_UNSHARE'] = 'True'

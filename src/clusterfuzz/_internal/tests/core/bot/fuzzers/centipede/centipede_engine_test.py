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
from unittest.mock import patch

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import options as fuzzer_options
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.centipede import \
    constants as centipede_constants
from clusterfuzz._internal.bot.fuzzers.centipede import engine
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz.stacktraces import constants

TestPaths = collections.namedtuple('TestPaths',
                                   ['data', 'corpus', 'crashes', 'centipede'])

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
                           str(data_dir / 'centipede'))
    os.mkdir(test_paths.corpus)
    os.mkdir(test_paths.crashes)
    yield test_paths


TEST_PATH = pathlib.Path(__file__).parent
MAX_TIME = 3

# Centipede's runtime args for testing.
_RSS_LIMIT_TEST = 2
_TIMEOUT_PER_INPUT_TEST = 1  # For testing timeout only.


def setup_testcase(testcase, test_paths):
  """Sets up testcase and corpus."""

  src_testcase_path = test_paths.data / testcase
  src_testcase_options_path = test_paths.data / f'{testcase}.options'
  copied_testcase_path = test_paths.corpus / testcase
  copied_testcase_options_path = test_paths.corpus / f'{testcase}.options'
  shutil.copy(src_testcase_path, copied_testcase_path)
  if src_testcase_options_path.exists():
    shutil.copy(src_testcase_options_path, copied_testcase_options_path)

  return copied_testcase_path


def setup_centipede(target_name,
                    test_paths,
                    centipede_bin=None,
                    sanitized_target_dir=None):
  """Sets up Centipede for fuzzing."""
  # Setup Centipede's fuzz target.
  engine_impl = engine.Engine()
  target_path = engine_common.find_fuzzer_path(test_paths.data, target_name)

  if sanitized_target_dir is None:
    sanitized_target_dir = test_paths.data / fuzzer_utils.EXTRA_BUILD_DIR
  sanitized_target_path = sanitized_target_dir / target_name

  # Setup Centipede's binary.
  if centipede_bin and centipede_bin != test_paths.centipede:
    os.rename(centipede_bin, test_paths.centipede)

  return engine_impl, target_path, sanitized_target_path


@test_utils.integration
class IntegrationTest(unittest.TestCase):
  """Integration tests."""

  def run(self, *args, **kwargs):
    with get_test_paths() as test_paths:
      self.test_paths = test_paths
      super().run(*args, **kwargs)

  def setUp(self):
    self.maxDiff = None
    test_helpers.patch(self, ['os.getpid'])
    self.mock.getpid.return_value = 1337
    test_helpers.patch_environ(self)
    os.environ['BUILD_DIR'] = str(self.test_paths.data)
    os.environ['JOB_NAME'] = 'centipede_asan_job'

  def compare_arguments(self, expected, actual):
    """Compares expected arguments."""
    # First, compare that the binary is the first element of the list
    self.assertListEqual(expected[:1], actual[:1], "binary argument differ")

    # The other arguments for centipede are not positional, so we do not really care about ordering.
    self.assertListEqual(sorted(expected[1:]), sorted(actual[1:]))

  def _test_reproduce(self,
                      regex,
                      testcase_path,
                      target_name='clusterfuzz_format_target',
                      sanitized_target_dir=None):
    """Tests reproducing a crash."""
    engine_impl, target_path, sanitized_target_path = setup_centipede(
        target_name, self.test_paths, sanitized_target_dir=sanitized_target_dir)

    result = engine_impl.reproduce(target_path, testcase_path, [], MAX_TIME)

    self.assertListEqual([f'{sanitized_target_path}', testcase_path],
                         result.command)
    self.assertRegex(result.output, regex)

    return re.search(regex, result.output)

  def test_reproduce_uaf_without_unsanitized_binary(self):
    """Tests reproducing an ASAN heap-use-after-free crash when no unsanitized
    target binary was provided."""
    testcase_path = setup_testcase('uaf', self.test_paths)
    crash_info = self._test_reproduce(
        constants.ASAN_REGEX,
        testcase_path,
        'clusterfuzz_format_target_sanitized',
        sanitized_target_dir=self.test_paths.data)

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

  def test_options_arguments(self):
    """Tests that the options file is correctly taken into account when querying for arguments."""
    testcase_path = setup_testcase('fuzzer_arguments', self.test_paths)
    engine_impl = engine.Engine()
    # pylint: disable=protected-access
    arguments = engine_impl._get_arguments(str(testcase_path))
    args = arguments.list()
    self.assertIn('-rss_limit_mb=1234', args)

  @patch('clusterfuzz._internal.bot.fuzzers.centipede.engine._CLEAN_EXIT_SECS',
         5)
  def _run_centipede(self,
                     target_name,
                     dictionary=None,
                     timeout_per_input=None,
                     rss_limit=centipede_constants.RSS_LIMIT_MB_DEFAULT,
                     centipede_bin=None,
                     sanitized_target_dir=None):
    """Run Centipede for other unittest."""
    if centipede_bin is None:
      centipede_bin = self.test_paths.centipede
    engine_impl, target_path, sanitized_target_path = setup_centipede(
        target_name,
        self.test_paths,
        centipede_bin,
        sanitized_target_dir=sanitized_target_dir)
    work_dir = '/tmp/temp-1337/workdir'

    options = engine_impl.prepare(self.test_paths.corpus, target_path,
                                  self.test_paths.data)

    arguments = fuzzer_options.FuzzerArguments.from_list(options.arguments)
    self.assertListEqual(arguments.list(), options.arguments)

    # For testing oom only.
    arguments[centipede_constants.RSS_LIMIT_MB_FLAGNAME] = rss_limit

    # For testing timeout only.
    if timeout_per_input:
      arguments[
          centipede_constants.TIMEOUT_PER_INPUT_FLAGNAME] = timeout_per_input

    options.arguments = arguments.list()
    results = engine_impl.fuzz(target_path, options, self.test_paths.crashes,
                               MAX_TIME)

    expected_command = [self.test_paths.centipede]
    expected_args = fuzzer_options.FuzzerArguments(
        centipede_constants.get_default_arguments())
    if dictionary:
      expected_args[centipede_constants.DICTIONARY_FLAGNAME] = str(dictionary)
    expected_args[centipede_constants.WORKDIR_FLAGNAME] = str(work_dir)
    expected_args[centipede_constants.CORPUS_DIR_FLAGNAME] = str(
        self.test_paths.corpus)
    expected_args[centipede_constants.BINARY_FLAGNAME] = str(target_path)
    if str(target_path) != str(sanitized_target_path):
      expected_args[centipede_constants.EXTRA_BINARIES_FLAGNAME] = str(
          sanitized_target_path)
    if timeout_per_input:
      expected_args[
          centipede_constants.TIMEOUT_PER_INPUT_FLAGNAME] = timeout_per_input
    expected_args[centipede_constants.RSS_LIMIT_MB_FLAGNAME] = rss_limit

    expected_command.extend(expected_args.list())

    self.compare_arguments(expected_command, results.command)
    return results

  @test_utils.slow
  def test_fuzz_no_crash(self):
    """Tests fuzzing (no crash)."""
    dictionary = self.test_paths.data / 'test_fuzzer.dict'
    self._run_centipede(target_name='test_fuzzer', dictionary=dictionary)
    self.assertTrue(self.test_paths.corpus.iterdir())

  def test_fuzz_no_crash_without_unsanitized_binary(self):
    """Tests fuzzing (no crash) when no unsanitized target binary was provided.
    """
    dictionary = self.test_paths.data / 'test_fuzzer_sanitized.dict'
    self._run_centipede(
        target_name='test_fuzzer_sanitized',
        dictionary=dictionary,
        sanitized_target_dir=self.test_paths.data)
    self.assertTrue(self.test_paths.corpus.iterdir())

  def _test_crash_log_regex(self,
                            crash_regex,
                            content,
                            timeout_per_input=None,
                            rss_limit=centipede_constants.RSS_LIMIT_MB_DEFAULT,
                            centipede_bin=None,
                            target_name='clusterfuzz_format_target',
                            sanitized_target_dir=None):
    """Fuzzes the target and check if regex matches Centipede's crash log."""
    if centipede_bin is None:
      centipede_bin = self.test_paths.centipede
    results = self._run_centipede(
        target_name=target_name,
        timeout_per_input=timeout_per_input,
        rss_limit=rss_limit,
        centipede_bin=centipede_bin,
        sanitized_target_dir=sanitized_target_dir)

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
    with open(crash.input_path) as f:
      self.assertEqual(content, f.read())

    return re.search(crash_regex, crash.stacktrace)

  def test_crash_uaf_without_unsanitized(self):
    """Tests fuzzing that results in a ASAN heap-use-after-free crash when no
    unsanitized target binary was provided."""
    setup_testcase('uaf', self.test_paths)
    crash_info = self._test_crash_log_regex(
        constants.ASAN_REGEX,
        'uaf',
        target_name='clusterfuzz_format_target_sanitized',
        sanitized_target_dir=self.test_paths.data)

    # Check the crash reason was parsed correctly.
    self.assertEqual(crash_info.group(1), 'AddressSanitizer')
    self.assertIn('heap-use-after-free', crash_info.group(2))

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
        timeout_per_input=_TIMEOUT_PER_INPUT_TEST)

  def test_minimize_testcase(self):
    """Tests minimizing a testcase."""
    unminimized_crash = setup_testcase('unmin_crash', self.test_paths)
    self.assertTrue(os.path.isfile(unminimized_crash))
    minimized_crash = self.test_paths.data / 'min_crash'
    engine_impl, target_path, _ = setup_centipede('minimize_me_fuzz_target',
                                                  self.test_paths)
    result = engine_impl.minimize_testcase(target_path, [], unminimized_crash,
                                           minimized_crash, MAX_TIME)
    self.assertTrue(result)

    self.assertTrue(os.path.isfile(minimized_crash))
    with open(minimized_crash, encoding='utf-8') as f:
      result = f.read()
      self.assertEqual('?fuz?', result)


class GetRunnerTest(unittest.TestCase):
  """Tests that _get_runner works as intended."""

  def test_get_runner(self):
    """Tests that _get_runner works as intended."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      build_dir = pathlib.Path(tmp_dir) / 'build'
      os.makedirs(build_dir)
      centipede_path = build_dir / 'centipede'
      target_path = build_dir / 'target'
      with open(centipede_path, 'w') as fp:
        fp.write('')
      self.assertIsNotNone(engine._get_runner(target_path))  # pylint: disable=protected-access


@test_utils.integration
class UnshareIntegrationTest(IntegrationTest):
  """Integration tests."""

  def compare_arguments(self, expected, actual):
    """Compares expected arguments."""
    unshare_path = (
        pathlib.Path(environment.get_value('ROOT_DIR')) / 'resources' /
        'platform' / 'linux' / 'unshare')
    super().compare_arguments([str(unshare_path), '-c', '-n'] + expected,
                              actual)

  def setUp(self):
    super().setUp()
    os.environ['USE_UNSHARE'] = 'True'

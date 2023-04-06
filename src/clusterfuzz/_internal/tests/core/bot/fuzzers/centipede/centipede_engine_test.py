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

import os
from pathlib import Path
import re
import shutil
import unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.centipede import engine
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz.stacktraces.constants import ASAN_REGEX
from clusterfuzz.stacktraces.constants import CENTIPEDE_TIMEOUT_REGEX
from clusterfuzz.stacktraces.constants import OUT_OF_MEMORY_REGEX

TEST_PATH = Path(__file__).parent
DATA_DIR = TEST_PATH / 'test_data'
CORPUS_DIR = TEST_PATH / 'corpus_dir'
CRASHES_DIR = TEST_PATH / 'crashes_dir'
MAX_TIME = 25

# Centipede's runtime args for testing.
_SERVER_COUNT = 1
_RSS_LIMIT = 4096
_ADDRESS_SPACE_LIMIT = 4096
_DEFAULT_ARGUMENTS = [
    '--exit_on_crash=1',
    f'--fork_server={_SERVER_COUNT}',
    f'--rss_limit_mb={_RSS_LIMIT}',
    f'--address_space_limit_mb={_ADDRESS_SPACE_LIMIT}',
    '--symbolizer_path=/dev/null',
]


def clear_output_dirs():
  """Clears output directory."""
  for input_dir in [CORPUS_DIR, CRASHES_DIR]:
    if input_dir.exists():
      shutil.rmtree(input_dir)
    input_dir.mkdir()


def setup_testcase(testcase):
  """Sets up testcase and corpus."""
  clear_output_dirs()

  src_testcase_path = DATA_DIR / testcase
  copied_testcase_path = CORPUS_DIR / testcase
  shutil.copy(src_testcase_path, copied_testcase_path)

  return copied_testcase_path


def setup_centipede(target_name):
  """Sets up Centipede for fuzzing."""
  engine_impl = engine.Engine()
  target_path = engine_common.find_fuzzer_path(DATA_DIR, target_name)
  sanitized_target_path = DATA_DIR / fuzzer_utils.EXTRA_BUILD_DIR / target_name
  return engine_impl, target_path, sanitized_target_path


@test_utils.integration
class IntegrationTest(unittest.TestCase):
  """Integration tests."""

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name
    test_helpers.patch_environ(self)

    os.environ['BUILD_DIR'] = str(DATA_DIR)

    test_helpers.patch(self, ['os.getpid'])
    self.mock.getpid.return_value = 1337

  clear_output_dirs()

  def compare_arguments(self, expected, actual):
    """Compares expected arguments."""
    self.assertListEqual(expected, actual)

  def reproduce(self):
    """Tests reproducing a crash."""
    engine_impl, target_path, sanitized_target_path = setup_centipede(
        'clusterfuzz_format_target')
    testcase_path = setup_testcase('uaf')

    result = engine_impl.reproduce(target_path, testcase_path, [], MAX_TIME)

    self.assertListEqual([sanitized_target_path, testcase_path], result.command)
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free', result.output)

  def _run_centipede(self, target_name, dictionary=None,
                     timeout_per_input=None):
    """Run Centipede for other unittest."""
    engine_impl, target_path, sanitized_target_path = setup_centipede(
        target_name)
    work_dir = Path('/tmp/temp-1337/workdir')

    options = engine_impl.prepare(CORPUS_DIR, target_path, DATA_DIR)
    if timeout_per_input:
      options.arguments.append(f'--timeout_per_input={timeout_per_input}')
    results = engine_impl.fuzz(target_path, options, CRASHES_DIR, MAX_TIME)

    if dictionary:
      default_args = _DEFAULT_ARGUMENTS + [f'--dictionary={dictionary}']
    else:
      default_args = _DEFAULT_ARGUMENTS
    expected_command = ([f'{DATA_DIR / "centipede"}'] + default_args + [
        f'--workdir={work_dir}',
        f'--corpus_dir={CORPUS_DIR}',
        f'--binary={target_path}',
        f'--extra_binaries={sanitized_target_path}',
    ])
    if timeout_per_input:
      expected_command.append(f'--timeout_per_input={timeout_per_input}')
    self.compare_arguments(expected_command, results.command)
    return results

  @test_utils.slow
  def test_fuzz_no_crash(self):
    """Tests fuzzing (no crash)."""
    dictionary = DATA_DIR / 'test_fuzzer.dict'
    self._run_centipede(target_name='test_fuzzer', dictionary=dictionary)
    self.assertTrue(CORPUS_DIR.iterdir())

  def _test_crash_log_regex(self, crash_regex, content, timeout_per_input=None):
    """Fuzzes the target and check if regex matches Centipede's crash log."""
    results = self._run_centipede(
        target_name='clusterfuzz_format_target',
        timeout_per_input=timeout_per_input)

    # Check there is one and only one expected crash.
    self.assertEqual(1, len(results.crashes))
    crash = results.crashes[0]
    # Check the crash was saved properly.
    self.assertEqual(CRASHES_DIR, Path(crash.input_path).parent)
    # Check the regex can capture the crash info in the stacktrace.
    self.assertRegex(crash.stacktrace, crash_regex)

    # Check reproducer location format.
    self.assertRegex(results.logs, 'Saving input to: .+/crashes/.+')
    # Check the prefix was trimmed.
    self.assertNotRegex(results.logs, 'CRASH LOG:.*')

    # Check the correct input was saved.
    with open(crash.input_path, 'r') as f:
      self.assertEqual(content, f.read())

    return re.search(crash_regex, crash.stacktrace)

  def test_crash_uaf(self):
    """Tests fuzzing that results in a ASAN heap-use-after-free crash."""
    setup_testcase('uaf')
    crash_info = self._test_crash_log_regex(ASAN_REGEX, 'uaf')

    # Check the crash reason was parsed correctly.
    self.assertEqual(crash_info.group(1), 'AddressSanitizer')
    self.assertIn('heap-use-after-free', crash_info.group(2))

  def test_crash_oom(self):
    """Tests fuzzing that results in a out-of-memory crash."""
    setup_testcase('oom')
    self._test_crash_log_regex(OUT_OF_MEMORY_REGEX, 'oom')

  def test_crash_timeout(self):
    """Tests fuzzing that results in a timeout."""
    setup_testcase('slo')
    self._test_crash_log_regex(CENTIPEDE_TIMEOUT_REGEX, 'slo', 5)


@test_utils.integration
class UnshareIntegrationTest(IntegrationTest):
  """Integration tests."""

  def compare_arguments(self, expected, actual):
    """Compares expected arguments."""
    unshare_path = Path(
        environment.get_value('ROOT_DIR'), 'resources', 'platform', 'linux',
        'unshare')
    self.assertListEqual([f'{unshare_path}', '-c', '-n'] + expected, actual)

  def setUp(self):
    super().setUp()
    os.environ['USE_UNSHARE'] = 'True'

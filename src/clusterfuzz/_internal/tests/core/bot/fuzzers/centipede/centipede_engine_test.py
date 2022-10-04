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
import shutil
import unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.centipede import engine
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

TEST_PATH = Path(__file__).parent
DATA_DIR = TEST_PATH / 'test_data'
CORPUS_DIR = TEST_PATH / 'corpus_dir'
CRASHES_DIR = TEST_PATH / 'crashes_dir'

# Centipede's runtime args
_TIMEOUT = 25
_SERVER_COUNT = 1
_RSS_LIMIT = 4096
_RLIMIT_AS = 5120
_ADDRESS_SPACE_LIMIT = 0
_DEFAULT_ARGUMENTS = [
    '--exit_on_crash=1',
    f'--timeout={_TIMEOUT}',
    f'--fork_server={_SERVER_COUNT}',
    f'--rss_limit_mb={_RSS_LIMIT}',
    f'--address_space_limit_mb={_ADDRESS_SPACE_LIMIT}',
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
    testcase_path = setup_testcase('crash')
    engine_impl = engine.Engine()
    sanitized_target_path = DATA_DIR / fuzzer_utils.EXTRA_BUILD_DIR / 'test_fuzzer'
    result = engine_impl.reproduce(sanitized_target_path, testcase_path, [], 10)
    self.assertListEqual([sanitized_target_path, testcase_path], result.command)
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free', result.output)

  @test_utils.slow
  def test_fuzz_no_crash(self):
    """Tests fuzzing (no crash)."""
    engine_impl = engine.Engine()
    centipede_path = DATA_DIR / 'centipede'
    dictionary = DATA_DIR / "test_fuzzer.dict"
    work_dir = Path('/tmp/temp-1337/workdir')
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'test_fuzzer')
    sanitized_target_path = DATA_DIR / fuzzer_utils.EXTRA_BUILD_DIR / 'test_fuzzer'
    options = engine_impl.prepare(CORPUS_DIR, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, CRASHES_DIR, 20)
    expected_command = ([f'{centipede_path}'] + _DEFAULT_ARGUMENTS + [
        f'--dictionary={dictionary}',
        f'--workdir={work_dir}',
        f'--corpus_dir={CORPUS_DIR}',
        f'--binary={target_path}',
        f'--extra_binaries={sanitized_target_path}',
    ])
    self.compare_arguments(expected_command, results.command)
    self.assertTrue(CORPUS_DIR.iterdir())

  def test_fuzz_crash(self):
    """Tests fuzzing that results in a crash."""
    engine_impl = engine.Engine()
    centipede_path = DATA_DIR / 'centipede'
    work_dir = Path('/tmp/temp-1337/workdir')
    target_path = engine_common.find_fuzzer_path(DATA_DIR,
                                                 'always_crash_fuzzer')
    sanitized_target_path = DATA_DIR / fuzzer_utils.EXTRA_BUILD_DIR / 'always_crash_fuzzer'
    options = engine_impl.prepare(CORPUS_DIR, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, CRASHES_DIR, 20)
    expected_command = ([f'{centipede_path}'] + _DEFAULT_ARGUMENTS + [
        f'--workdir={work_dir}',
        f'--corpus_dir={CORPUS_DIR}',
        f'--binary={target_path}',
        f'--extra_binaries={sanitized_target_path}',
    ])
    self.compare_arguments(expected_command, results.command)

    self.assertIn('Crash detected, saving input to', results.logs)
    self.assertEqual(1, len(results.crashes))
    crash = results.crashes[0]
    self.assertEqual(CRASHES_DIR, Path(crash.input_path).parent)
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free',
                  crash.stacktrace)

    with open(crash.input_path, 'rb') as f:
      self.assertEqual(b'A', f.read()[:1])


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

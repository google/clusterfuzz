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
import shutil
import unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.centipede import engine
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(TEST_PATH, 'test_data')
OUTPUT_DIR = os.path.join(TEST_PATH, 'output')
WORK_DIR = os.path.join(OUTPUT_DIR, 'workdir')
CORPUS_DIR = os.path.join(OUTPUT_DIR, 'corpus_dir')
CRASHES_DIR = os.path.join(WORK_DIR, 'crashes')

# Centipede's runtime args
_TIMEOUT = 1200
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
  """Clear output directory."""
  if os.path.exists(OUTPUT_DIR):
    shutil.rmtree(OUTPUT_DIR)
  os.mkdir(OUTPUT_DIR)


def setup_testcase(testcase):
  """Setup testcase and corpus."""
  clear_output_dirs()

  src_testcase_path = os.path.join(DATA_DIR, testcase)
  copied_testcase_path = os.path.join(OUTPUT_DIR, testcase)
  shutil.copy(src_testcase_path, copied_testcase_path)

  return copied_testcase_path


@test_utils.integration
class IntegrationTest(unittest.TestCase):
  """Integration tests."""

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name
    test_helpers.patch_environ(self)

    os.environ['BUILD_DIR'] = DATA_DIR

  def compare_arguments(self, expected, actual):
    """Compare expected arguments."""
    self.assertListEqual(expected, actual)

  def assert_has_stats(self, results):
    """Assert that stats exist."""
    # Centipede does not have stats report yet.
    # TODO(Dongge): Implement this when the feature is supported.

  def test_reproduce(self):
    """Tests reproducing a crash."""
    testcase_path = setup_testcase('crash')
    engine_impl = engine.Engine()
    sanitized_target_path = os.path.join(DATA_DIR, fuzzer_utils.EXTRA_BUILD_DIR,
                                         'test_fuzzer')
    result = engine_impl.reproduce(sanitized_target_path, testcase_path, [], 10)
    self.assertListEqual([sanitized_target_path, testcase_path], result.command)
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free', result.output)

  @test_utils.slow
  def test_fuzz_no_crash(self):
    """Test fuzzing (no crash)."""
    engine_impl = engine.Engine()
    dictionary = os.path.join(DATA_DIR, "test_fuzzer.dict")
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'test_fuzzer')
    sanitized_target_path = os.path.join(DATA_DIR, fuzzer_utils.EXTRA_BUILD_DIR,
                                         'test_fuzzer')
    options = engine_impl.prepare(OUTPUT_DIR, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, None, 20)
    expected_command = (
        [os.path.join(DATA_DIR, 'centipede')] + _DEFAULT_ARGUMENTS + [
            f'--dictionary={dictionary}',
            f'--workdir={WORK_DIR}',
            f'--corpus_dir={CORPUS_DIR}',
            f'--binary={target_path}',
            f'--extra_binaries={sanitized_target_path}',
        ])
    self.compare_arguments(expected_command, results.command)
    self.assertGreater(len(os.listdir(CORPUS_DIR)), 0)
    self.assert_has_stats(results)

  def test_fuzz_crash(self):
    """Test fuzzing that results in a crash."""
    engine_impl = engine.Engine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR,
                                                 'always_crash_fuzzer')
    sanitized_target_path = os.path.join(DATA_DIR, fuzzer_utils.EXTRA_BUILD_DIR,
                                         'always_crash_fuzzer')
    options = engine_impl.prepare(OUTPUT_DIR, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, None, 20)
    expected_command = (
        [os.path.join(DATA_DIR, 'centipede')] + _DEFAULT_ARGUMENTS + [
            f'--workdir={WORK_DIR}',
            f'--corpus_dir={CORPUS_DIR}',
            f'--binary={target_path}',
            f'--extra_binaries={sanitized_target_path}',
        ])
    self.compare_arguments(expected_command, results.command)

    self.assertIn('Crash detected, saving input to', results.logs)
    print(results.crashes)
    self.assertEqual(1, len(results.crashes))
    crash = results.crashes[0]
    self.assertEqual(CRASHES_DIR, os.path.dirname(crash.input_path))
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free',
                  crash.stacktrace)

    with open(crash.input_path, 'rb') as f:
      self.assertEqual(b'A', f.read()[:1])

    self.assert_has_stats(results)


@test_utils.integration
class UnshareIntegrationTest(IntegrationTest):
  """Integration tests."""

  def compare_arguments(self, expected, actual):
    """Compare expected arguments."""
    self.assertListEqual([
        os.path.join(
            environment.get_value('ROOT_DIR'), 'resources', 'platform', 'linux',
            'unshare'), '-c', '-n'
    ] + expected, actual)

  def setUp(self):
    super().setUp()
    os.environ['USE_UNSHARE'] = 'True'

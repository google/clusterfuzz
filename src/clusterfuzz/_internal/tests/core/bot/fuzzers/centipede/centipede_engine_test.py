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

import glob
import os
import shutil
import unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.centipede import engine
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(TEST_PATH, 'test_data')
WORK_DIR = os.path.join(DATA_DIR, 'workdir')
CORPUS_DIR = os.path.join(DATA_DIR, 'corpus')
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

def clear_temp_dirs():
  """Clear temp directory."""
  for directory in [CORPUS_DIR, WORK_DIR]:
    if os.path.exists(directory):
      shutil.rmtree(directory)
    os.mkdir(directory)


def setup_testcase_and_corpus(testcase, corpus):
  """Setup testcase and corpus."""
  clear_temp_dirs()
  copied_testcase_path = os.path.join(CORPUS_DIR, testcase)
  shutil.copy(os.path.join(DATA_DIR, testcase), copied_testcase_path)

  copied_corpus_path = os.path.join(CORPUS_DIR, corpus)
  src_corpus_path = os.path.join(DATA_DIR, corpus)

  if os.path.exists(src_corpus_path):
    shutil.copytree(src_corpus_path, copied_corpus_path)
  else:
    os.mkdir(copied_corpus_path)

  return copied_testcase_path, copied_corpus_path


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
    pass

  def test_reproduce(self):
    """Tests reproducing a crash."""
    testcase_path, _ = setup_testcase_and_corpus('crash', 'empty_corpus')
    engine_impl = engine.Engine()
    sanitized_target_path = f'{DATA_DIR}/__centipede_address/test_fuzzer'
    result = engine_impl.reproduce(sanitized_target_path, testcase_path, [], 10)
    self.assertListEqual([sanitized_target_path, testcase_path], result.command)
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free', result.output)

  @test_utils.slow
  def test_fuzz_no_crash(self):
    """Test fuzzing (no crash)."""
    _, corpus_path = setup_testcase_and_corpus('empty', 'corpus')
    engine_impl = engine.Engine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'test_fuzzer')
    sanitized_targets = glob.glob(f'{DATA_DIR}/__centipede_*/test_fuzzer')
    options = engine_impl.prepare(corpus_path, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, None, 20)
    expected_command = (
        [os.path.join(DATA_DIR, 'centipede')]
        + _DEFAULT_ARGUMENTS
        + [
            f'--dictionary={os.path.join(DATA_DIR, "test_fuzzer.dict")}',
            f'--workdir={os.path.join(DATA_DIR, "workdir")}',
            f'--corpus_dir={corpus_path}',
            f'--binary={target_path}',
            f'--extra_binaries={",".join(sanitized_targets)}',
        ]
    )
    self.compare_arguments(expected_command, results.command)
    self.assertGreater(len(os.listdir(corpus_path)), 0)
    self.assert_has_stats(results)

  def test_fuzz_crash(self):
    """Test fuzzing that results in a crash."""
    _, corpus_path = setup_testcase_and_corpus('empty', 'corpus')
    engine_impl = engine.Engine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR,
                                                 'always_crash_fuzzer')
    sanitized_targets = glob.glob(
        f'{DATA_DIR}/__centipede_*/always_crash_fuzzer')
    options = engine_impl.prepare(corpus_path, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, None, 20)
    expected_command = (
        [os.path.join(DATA_DIR, 'centipede')]
        + _DEFAULT_ARGUMENTS
        + [
            f'--workdir={WORK_DIR}',
            f'--corpus_dir={corpus_path}',
            f'--binary={target_path}',
            f'--extra_binaries={",".join(sanitized_targets)}',
        ]
    )
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

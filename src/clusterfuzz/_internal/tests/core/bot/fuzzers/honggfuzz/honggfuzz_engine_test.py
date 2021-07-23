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
"""Tests for honggfuzz engine."""
# pylint: disable=unused-argument

import os
import shutil
import unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.honggfuzz import engine
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(TEST_PATH, 'test_data')
TEMP_DIR = os.path.join(TEST_PATH, 'temp')


def clear_temp_dir():
  """Clear temp directory."""
  if os.path.exists(TEMP_DIR):
    shutil.rmtree(TEMP_DIR)

  os.mkdir(TEMP_DIR)


def setup_testcase_and_corpus(testcase, corpus):
  """Setup testcase and corpus."""
  clear_temp_dir()
  copied_testcase_path = os.path.join(TEMP_DIR, testcase)
  shutil.copy(os.path.join(DATA_DIR, testcase), copied_testcase_path)

  copied_corpus_path = os.path.join(TEMP_DIR, corpus)
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

  def assert_has_stats(self, results):
    """Assert that stats exist."""
    self.assertIn('iterations', results.stats)
    self.assertIn('time', results.stats)
    self.assertIn('speed', results.stats)
    self.assertIn('crashes_count', results.stats)
    self.assertIn('timeout_count', results.stats)
    self.assertIn('new_units_added', results.stats)
    self.assertIn('slowest_unit_ms', results.stats)
    self.assertIn('guard_nb', results.stats)
    self.assertIn('branch_coverage_percent', results.stats)
    self.assertIn('peak_rss_mb', results.stats)

  def test_reproduce(self):
    """Tests reproducing a crash."""
    testcase_path, _ = setup_testcase_and_corpus('crash', 'empty_corpus')
    engine_impl = engine.HonggfuzzEngine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'test_fuzzer')
    result = engine_impl.reproduce(target_path, testcase_path, [], 65)
    self.assertListEqual([target_path], result.command)
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free', result.output)

  @test_utils.slow
  def test_fuzz_no_crash(self):
    """Test fuzzing (no crash)."""
    _, corpus_path = setup_testcase_and_corpus('empty', 'corpus')
    engine_impl = engine.HonggfuzzEngine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'test_fuzzer')
    options = engine_impl.prepare(corpus_path, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)
    self.assertListEqual([
        os.path.join(DATA_DIR, 'honggfuzz'),
        '-n',
        '1',
        '--exit_upon_crash',
        '-v',
        '-z',
        '-P',
        '-S',
        '--rlimit_rss',
        '2560',
        '--timeout',
        '25',
        '--dict',
        os.path.join(DATA_DIR, 'test_fuzzer.dict'),
        '--input',
        os.path.join(TEMP_DIR, 'corpus'),
        '--workspace',
        TEMP_DIR,
        '--run_time',
        '10',
        '--',
        target_path,
    ], results.command)

    self.assertGreater(len(os.listdir(corpus_path)), 0)
    self.assert_has_stats(results)

  def test_fuzz_crash(self):
    """Test fuzzing that results in a crash."""
    _, corpus_path = setup_testcase_and_corpus('empty', 'corpus')
    engine_impl = engine.HonggfuzzEngine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR,
                                                 'always_crash_fuzzer')
    options = engine_impl.prepare(corpus_path, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)
    self.assertListEqual([
        os.path.join(DATA_DIR, 'honggfuzz'),
        '-n',
        '1',
        '--exit_upon_crash',
        '-v',
        '-z',
        '-P',
        '-S',
        '--rlimit_rss',
        '2560',
        '--timeout',
        '25',
        '--input',
        os.path.join(TEMP_DIR, 'corpus'),
        '--workspace',
        TEMP_DIR,
        '--run_time',
        '10',
        '--',
        target_path,
    ], results.command)

    self.assertIn('Seen a crash. Terminating all fuzzing threads', results.logs)
    self.assertEqual(1, len(results.crashes))
    crash = results.crashes[0]
    self.assertEqual(TEMP_DIR, os.path.dirname(crash.input_path))
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free',
                  crash.stacktrace)

    with open(crash.input_path, 'rb') as f:
      self.assertEqual(b'A', f.read()[:1])

    self.assert_has_stats(results)

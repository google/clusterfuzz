# Copyright 2024 Google LLC
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
"""Tests for googlefuzztest engine."""
# pylint: disable=unused-argument
import os
import unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.googlefuzztest import engine

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(TEST_PATH, 'test_data')
TEMP_DIR = os.path.join(TEST_PATH, 'temp')
GOOGLEFUZZTEST_ENGINE_TEST_SUFFIX = 'googlefuzztest_engine_test'


class GoogleFuzzTestUnitTests(unittest.TestCase):
  """Tests to make sure the fuzzing engine correctly handles logging, crash and non crash scenarios"""

  def test_googlefuzztest_invoked_with_low_log_volume(self):
    """Test if we call fuzztest with the correct abseil flags to reduce logging volume."""
    engine_impl = engine.Engine()
    target_path = engine_common.find_fuzzer_path(
        DATA_DIR, GOOGLEFUZZTEST_ENGINE_TEST_SUFFIX)
    options = engine_impl.prepare(None, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)

    self.assertIn('--logtostderr', results.command)
    self.assertIn('--minloglevel=3', results.command)

  def test_fuzz_no_crash(self):
    """Test fuzzing (no crash)."""
    engine_impl = engine.Engine()
    target_path = engine_common.find_fuzzer_path(
        DATA_DIR, GOOGLEFUZZTEST_ENGINE_TEST_SUFFIX)
    options = engine_impl.prepare(None, target_path, DATA_DIR)

    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)

    self.assertEqual(len(results.crashes), 0)

  def test_fuzz_crash(self):
    """Test fuzzing that results in a crash."""
    engine_impl = engine.Engine()
    target_path = engine_common.find_fuzzer_path(
        DATA_DIR, GOOGLEFUZZTEST_ENGINE_TEST_SUFFIX)
    options = engine_impl.prepare(None, target_path, DATA_DIR)
    options.set_extra_env_vars({"FUZZTEST_SHOULD_FAIL": "1"})
    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)
    self.assertGreater(len(results.crashes), 0)
    crash = results.crashes[0]

    self.assertIn('ERROR: AddressSanitizer: heap-buffer-overflow on address',
                  crash.stacktrace)

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
import shutil
import unittest

from clusterfuzz._internal.bot.fuzzers.googlefuzztest import engine
from clusterfuzz._internal.bot.fuzzers import engine_common

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(TEST_PATH, 'test_data')
TEMP_DIR = os.path.join(TEST_PATH, 'temp')

class UnitTest(unittest.TestCase):
  """Unit tests."""

  def test_googlefuzztest_invoked_with_low_log_volume(self):
    engine_impl = engine.Engine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'passing_fuzz_test')
    options = engine_impl.prepare(None, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)

    self.assertIn("--logtostderr", results.command)
    self.assertIn("--minloglevel=3", results.command)

  #@test_utils.slow
  def test_fuzz_no_crash(self):
    """Test fuzzing (no crash)."""
    engine_impl = engine.Engine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'passing_fuzz_test')
    options = engine_impl.prepare(None, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)

    self.assertEqual(len(results.crashes), 0)
    

  def test_fuzz_crash(self):
    """Test fuzzing that results in a crash."""
    engine_impl = engine.Engine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'failing_fuzz_test')
    options = engine_impl.prepare(None, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)
    self.assertGreater(len(results.crashes), 0)
    crash = results.crashes[0]
    self.assertIn("ERROR: AddressSanitizer: heap-buffer-overflow on address", crash.stacktrace)

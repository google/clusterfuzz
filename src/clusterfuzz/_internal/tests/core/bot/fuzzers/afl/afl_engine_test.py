# Copyright 2020 Google LLC
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
"""Tests for AFL's engine implementation."""

import os
import shutil
import unittest

from clusterfuzz._internal.bot.fuzzers.afl import engine
from clusterfuzz._internal.bot.fuzzers.afl import launcher
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.core.bot.fuzzers.afl import \
    afl_launcher_integration_test
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

# TODO(mbarbella): Break dependency on afl_launcher_integration_test once
# everything has been fully converted to the new pipeline.

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
TEMP_DIRECTORY = os.path.join(TEST_PATH, 'temp')
DATA_DIRECTORY = os.path.join(TEST_PATH, 'data')
CORPUS_DIRECTORY = os.path.join(TEMP_DIRECTORY, 'corpus')
OUTPUT_DIRECTORY = os.path.join(TEMP_DIRECTORY, 'output')

BASE_FUZZ_TIMEOUT = (
    launcher.AflRunnerCommon.SIGTERM_WAIT_TIME +
    launcher.AflRunnerCommon.AFL_CLEAN_EXIT_TIME)
FUZZ_TIMEOUT = 5 + BASE_FUZZ_TIMEOUT
LONG_FUZZ_TIMEOUT = 90 + BASE_FUZZ_TIMEOUT


def clear_temp_dir():
  """Clear temp directories."""
  if os.path.exists(TEMP_DIRECTORY):
    shutil.rmtree(TEMP_DIRECTORY)


def create_temp_dir():
  """Create temp directories."""
  # Corpus directory will be created when preparing for fuzzing.
  os.mkdir(TEMP_DIRECTORY)
  os.mkdir(OUTPUT_DIRECTORY)


@unittest.skipIf(not environment.get_value('AFL_INTEGRATION_TESTS'),
                 'AFL_INTEGRATION_TESTS=1 must be set')
class AFLEngineTest(unittest.TestCase):
  """Tests for AFLEngine."""

  def setUp(self):
    clear_temp_dir()
    create_temp_dir()

    test_helpers.patch_environ(self)
    afl_launcher_integration_test.dont_use_strategies(self)

  def tearDown(self):
    clear_temp_dir()

  def test_fuzz(self):
    """Test for fuzz."""
    engine_impl = engine.AFLEngine()

    afl_launcher_integration_test.setup_testcase_and_corpus(
        'empty', 'corpus', fuzz=True)
    fuzzer_path = os.path.join(DATA_DIRECTORY, 'test_fuzzer')
    options = engine_impl.prepare(CORPUS_DIRECTORY, fuzzer_path, DATA_DIRECTORY)

    result = engine_impl.fuzz(fuzzer_path, options, OUTPUT_DIRECTORY,
                              FUZZ_TIMEOUT)

    self.assertEqual('{0}/afl-fuzz'.format(DATA_DIRECTORY), result.command[0])
    self.assertIn('-i{0}'.format(CORPUS_DIRECTORY), result.command)

    # Ensure that we've added something other than the dummy file to the corpus.
    self.assertTrue(os.listdir(CORPUS_DIRECTORY))

  def test_reproduce(self):
    """Test for reproduce."""
    engine_impl = engine.AFLEngine()
    target_path = os.path.join(DATA_DIRECTORY, 'test_fuzzer')
    testcase_path = afl_launcher_integration_test.setup_testcase_and_corpus(
        'crash', 'empty_corpus')
    timeout = 5
    result = engine_impl.reproduce(target_path, testcase_path, [], timeout)

    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000',
        result.output)

  def test_fuzz_with_crash(self):
    """Tests that we detect crashes when fuzzing."""
    engine_impl = engine.AFLEngine()

    afl_launcher_integration_test.setup_testcase_and_corpus(
        'empty', 'corpus', fuzz=True)
    fuzzer_path = os.path.join(DATA_DIRECTORY, 'easy_crash_fuzzer')
    options = engine_impl.prepare(CORPUS_DIRECTORY, fuzzer_path, DATA_DIRECTORY)

    result = engine_impl.fuzz(fuzzer_path, options, OUTPUT_DIRECTORY,
                              LONG_FUZZ_TIMEOUT)

    self.assertGreater(len(result.crashes), 0)
    crash = result.crashes[0]
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free',
                  crash.stacktrace)

    # Testcase (non-zero size) should've been copied back.
    self.assertNotEqual(os.path.getsize(crash.input_path), 0)

  def test_startup_crash_not_reported(self):
    """Ensures that we properly handle startup crashes."""
    engine_impl = engine.AFLEngine()

    afl_launcher_integration_test.setup_testcase_and_corpus(
        'empty', 'corpus', fuzz=True)
    fuzzer_path = os.path.join(DATA_DIRECTORY, 'always_crash_fuzzer')
    options = engine_impl.prepare(CORPUS_DIRECTORY, fuzzer_path, DATA_DIRECTORY)

    result = engine_impl.fuzz(fuzzer_path, options, OUTPUT_DIRECTORY,
                              FUZZ_TIMEOUT)

    self.assertFalse(result.crashes)

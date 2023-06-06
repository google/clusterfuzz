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
import tempfile
import unittest

from clusterfuzz._internal.bot.fuzzers.afl import engine
from clusterfuzz._internal.bot.fuzzers.afl import launcher
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.core.bot.fuzzers.afl import \
    afl_launcher_integration_test
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

# TODO(mbarbella): Break dependency on afl_launcher_integration_test once
# everything has been fully converted to the new pipeline.

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
DATA_DIRECTORY = os.path.join(TEST_PATH, 'data')

BASE_FUZZ_TIMEOUT = (
    launcher.AflRunnerCommon.SIGTERM_WAIT_TIME +
    launcher.AflRunnerCommon.AFL_CLEAN_EXIT_TIME)
FUZZ_TIMEOUT = 5 + BASE_FUZZ_TIMEOUT
LONG_FUZZ_TIMEOUT = 90 + BASE_FUZZ_TIMEOUT


@test_utils.integration
class EngineTest(unittest.TestCase):
  """Tests for Engine."""

  def run(self, *args, **kwargs):
    with tempfile.TemporaryDirectory() as temp_dir:
      self.temp_dir = temp_dir
      self.default_corpus_directory = os.path.join(self.temp_dir, 'corpus')
      self.output_directory = os.path.join(self.temp_dir, 'output')
      os.mkdir(self.output_directory)
      super().run(*args, **kwargs)

  def setUp(self):
    test_helpers.patch_environ(self)
    afl_launcher_integration_test.dont_use_strategies(self)
    environment.set_value('BUILD_DIR', DATA_DIRECTORY)

  def test_fuzz(self):
    """Test for fuzz."""
    engine_impl = engine.Engine()

    afl_launcher_integration_test.setup_testcase_and_corpus(
        self, 'empty', 'corpus', fuzz=True)
    fuzzer_path = os.path.join(DATA_DIRECTORY, 'test_fuzzer')
    options = engine_impl.prepare(self.default_corpus_directory, fuzzer_path,
                                  DATA_DIRECTORY)

    result = engine_impl.fuzz(fuzzer_path, options, self.output_directory,
                              FUZZ_TIMEOUT)

    self.assertEqual('{}/afl-fuzz'.format(DATA_DIRECTORY), result.command[0])
    self.assertIn('-i{}'.format(self.default_corpus_directory), result.command)

    # Ensure that we've added something other than the dummy file to the corpus.
    self.assertTrue(os.listdir(self.default_corpus_directory))

  def test_reproduce(self):
    """Test for reproduce."""
    engine_impl = engine.Engine()
    target_path = os.path.join(DATA_DIRECTORY, 'test_fuzzer')
    testcase_path = afl_launcher_integration_test.setup_testcase_and_corpus(
        self, 'crash', 'empty_corpus')
    timeout = 5
    result = engine_impl.reproduce(target_path, testcase_path, [], timeout)

    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000',
        result.output)

  def test_fuzz_with_crash(self):
    """Tests that we detect crashes when fuzzing."""
    engine_impl = engine.Engine()

    afl_launcher_integration_test.setup_testcase_and_corpus(
        self, 'empty', 'easy_crash_corpus', fuzz=True)
    fuzzer_path = os.path.join(DATA_DIRECTORY, 'easy_crash_fuzzer')
    options = engine_impl.prepare(
        os.path.join(self.temp_dir, 'easy_crash_corpus'), fuzzer_path,
        DATA_DIRECTORY)

    result = engine_impl.fuzz(fuzzer_path, options, self.output_directory,
                              LONG_FUZZ_TIMEOUT)

    self.assertGreater(len(result.crashes), 0)
    crash = result.crashes[0]
    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free',
                  crash.stacktrace)

    # Testcase (non-zero size) should've been copied back.
    self.assertNotEqual(os.path.getsize(crash.input_path), 0)

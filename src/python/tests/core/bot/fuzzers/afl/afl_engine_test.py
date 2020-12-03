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

from bot.fuzzers.afl import engine
from system import environment
from tests.core.bot.fuzzers.afl import afl_launcher_integration_test
from tests.test_libs import helpers as test_helpers

# TODO(mbarbella): Break dependency on afl_launcher_integration_test once
# everything has been fully converted to the new pipeline.

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
TEMP_DIRECTORY = os.path.join(TEST_PATH, 'temp')
DATA_DIRECTORY = os.path.join(TEST_PATH, 'data')
CORPUS_DIRECTORY = os.path.join(TEMP_DIRECTORY, 'corpus')
CRASHES_DIRECTORY = os.path.join(TEMP_DIRECTORY, 'crashes')


def clear_temp_dir():
  """Clear temp directories."""
  if os.path.exists(TEMP_DIRECTORY):
    shutil.rmtree(TEMP_DIRECTORY)


def create_temp_dir():
  """Create temp directories."""
  # Corpus directory will be created when preparing for fuzzing.
  os.mkdir(TEMP_DIRECTORY)
  os.mkdir(CRASHES_DIRECTORY)


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

    _ = afl_launcher_integration_test.setup_testcase_and_corpus(
        'empty', 'corpus', fuzz=True)
    fuzzer_path = os.path.join(DATA_DIRECTORY, 'test_fuzzer')
    options = engine_impl.prepare(CORPUS_DIRECTORY, fuzzer_path, DATA_DIRECTORY)
    timeout = afl_launcher_integration_test.get_fuzz_timeout(5.0)

    result = engine_impl.fuzz(fuzzer_path, options, CRASHES_DIRECTORY, timeout)

    self.assertEqual('{0}/afl-fuzz'.format(DATA_DIRECTORY), result.command[0])
    self.assertIn('-i{0}'.format(CORPUS_DIRECTORY), result.command)

    # Ensure that we've added something other than the dummy file to the corpus.
    assert len(os.listdir(CORPUS_DIRECTORY)) > 1, os.listdir(CORPUS_DIRECTORY)

  def test_reproduce(self):
    """Test for reproduce."""
    engine_impl = engine.AFLEngine()
    target_path = os.path.join(DATA_DIRECTORY, 'test_fuzzer')
    testcase_path = afl_launcher_integration_test.setup_testcase_and_corpus(
        'crash', 'empty_corpus')
    timeout = afl_launcher_integration_test.get_fuzz_timeout(5.0)
    result = engine_impl.reproduce(target_path, testcase_path, [], timeout)

    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000',
        result.output)

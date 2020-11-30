"""Tests for AFL's engine implementation."""

import os
import unittest

from bot.fuzzers.afl import engine
from system import environment
from tests.core.bot.fuzzers.afl import afl_launcher_integration_test
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

# TODO(mbarbella): Break dependency on afl_launcher_integration_test once
# everything has been fully converted to the new pipeline.

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
TEMP_DIRECTORY = os.path.join(TEST_PATH, 'temp')
DATA_DIRECTORY = os.path.join(TEST_PATH, 'data')

@unittest.skipIf(not environment.get_value('AFL_INTEGRATION_TESTS'),
                 'AFL_INTEGRATION_TESTS=1 must be set')
class AFLEngineTest(unittest.TestCase):
  """Tests for AFLEngine."""

  def setUp(self):
    afl_launcher_integration_test.clear_temp_dir()
    afl_launcher_integration_test.create_temp_dir()

    test_helpers.patch_environ(self)
    afl_launcher_integration_test.dont_use_strategies(self)

  def tearDown(self):
    afl_launcher_integration_test.clear_temp_dir()

  def test_fuzz(self):
    """Test for fuzz."""
    engine_impl = engine.AFLEngine()
    _ = afl_launcher_integration_test.setup_testcase_and_corpus('empty', 'corpus', fuzz=True)
    fuzzer_path = os.path.join(DATA_DIRECTORY, 'test_fuzzer')
    options = engine_impl.prepare(TEMP_DIRECTORY, fuzzer_path, DATA_DIRECTORY)
    timeout = afl_launcher_integration_test.get_fuzz_timeout(5.0)
    result = engine_impl.fuzz(fuzzer_path, options, TEMP_DIRECTORY, timeout)
    self.assertIn(
        '{0}/afl-fuzz -i{1}/corpus'.format(DATA_DIRECTORY, TEMP_DIRECTORY),
        result.command)
    # TODO(mbarbella): Ensure new items are added to the corpus.

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


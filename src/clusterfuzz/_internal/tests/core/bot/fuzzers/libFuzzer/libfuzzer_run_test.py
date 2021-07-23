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
"""Tests for fuzzer.py."""

import os
import unittest

from clusterfuzz._internal.bot.fuzzers.libFuzzer import fuzzer
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.core.bot.fuzzers import builtin_test
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))


class GenerateArgumentsTests(unittest.TestCase):
  """Unit tests for fuzzer.py."""

  def setUp(self):
    """Set up test environment."""
    test_helpers.patch_environ(self)
    environment.set_value('FUZZ_TEST_TIMEOUT', '4800')

    self.build_dir = os.path.join(SCRIPT_DIR, 'run_data', 'build_dir')
    self.corpus_directory = 'data/corpus_with_some_files'

  def test_generate_arguments_default(self):
    """Test generateArgumentsForFuzzer."""
    fuzzer_path = os.path.join(self.build_dir, 'fake0_fuzzer')
    libfuzzer = fuzzer.LibFuzzer()
    arguments = libfuzzer.generate_arguments(fuzzer_path)
    expected_arguments = '-timeout=25 -rss_limit_mb=2560'

    self.assertEqual(arguments, expected_arguments)

  def test_generate_arguments_with_options_file(self):
    """Test generateArgumentsForFuzzer."""
    fuzzer_path = os.path.join(self.build_dir, 'fake1_fuzzer')
    libfuzzer = fuzzer.LibFuzzer()
    arguments = libfuzzer.generate_arguments(fuzzer_path)

    expected_arguments = (
        '-max_len=31337 -timeout=11 -runs=9999999 -rss_limit_mb=2560')
    self.assertEqual(arguments, expected_arguments)


class FuzzerTest(builtin_test.BaseEngineFuzzerTest):
  """Unit tests for fuzzer."""

  def test_run(self):
    """Test running libFuzzer fuzzer."""
    libfuzzer = fuzzer.LibFuzzer()
    libfuzzer.run('/input', '/output', 1)
    with open('/output/flags-0') as f:
      self.assertEqual('%TESTCASE% target -timeout=25 -rss_limit_mb=2560',
                       f.read())

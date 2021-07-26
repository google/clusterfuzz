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
"""Tests for the generic blackbox fuzzer engine implementation."""

import os
import unittest
from unittest import mock

from clusterfuzz._internal.bot.fuzzers.blackbox import engine
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(TEST_PATH, 'test_data')
FUZZ_OUTPUT_DIR = os.path.join(DATA_DIR, 'sample_fuzz_output')


class BlackboxEngineTest(unittest.TestCase):
  """Tests for BlackboxEngine."""

  def setUp(self):
    test_helpers.patch_environ(self)
    environment.set_bot_environment()

    os.environ['APP_ARGS'] = '-a -b'
    os.environ['APP_DIR'] = '/build'
    os.environ['APP_PATH'] = '/build/test_binary'
    os.environ['APP_NAME'] = 'test_binary'

    os.environ['FUZZERS_DIR'] = '/fuzzers'

    test_helpers.patch(self, [
        'os.chmod',
        'clusterfuzz._internal.system.new_process.ProcessRunner.run_and_wait',
    ])

  def test_prepare(self):
    blackbox_engine = engine.BlackboxEngine()
    result = blackbox_engine.prepare('/input/corpus', 'unused', '/build')
    self.assertEqual(result.corpus_dir, '/input/corpus')
    self.assertEqual(result.arguments, [])
    self.assertEqual(result.strategies, {})

  def test_fuzz(self):
    blackbox_engine = engine.BlackboxEngine()
    options = blackbox_engine.prepare('/input/corpus', 'unused', '/build')
    result = blackbox_engine.fuzz('/fuzzers/my_fuzzer', options,
                                  FUZZ_OUTPUT_DIR, 10)
    self.assertEqual(len(result.crashes), 1)
    self.assertEqual(result.crashes[0].input_path,
                     os.path.join(FUZZ_OUTPUT_DIR, 'fuzz-real-crash'))
    self.mock.run_and_wait.assert_called_once_with(
        mock.ANY,
        additional_args=[
            '--app_path=/build/test_binary', '--app_args=-a -b',
            '--input_dir=/input/corpus'
        ],
        timeout=10)

  def test_reproduce(self):
    blackbox_engine = engine.BlackboxEngine()
    args = ['fuzzer_executable']
    blackbox_engine.reproduce('/fuzzers/my_fuzzer', '/testcase', args, 10)
    self.mock.run_and_wait.assert_called_once_with(
        mock.ANY,
        additional_args=[
            '--app_path=/build/test_binary', '--app_args=-a -b',
            '--testcase_path=/testcase'
        ],
        timeout=10)

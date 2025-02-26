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
"""Tests for libFuzzer script."""
# pylint: disable=unused-argument

import os
import shutil
import unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import libfuzzer
from clusterfuzz._internal.bot.fuzzers import strategy_selection
from clusterfuzz._internal.bot.fuzzers.libFuzzer import fuzzer
from clusterfuzz._internal.fuzzing import strategy
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

TESTDATA_PATH = os.path.join(os.path.dirname(__file__), 'libfuzzer_test_data')

BOT_NAME = 'test-bot'
BUILD_DIR = '/fake/build_dir'
FUZZ_INPUTS_DISK = '/fake/inputs-disk'
GSUTIL_PATH = '/fake/gsutil_path'
FAKE_ROOT_DIR = '/fake_root'

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))


def _read_test_data(name):
  """Read test data."""
  data_path = os.path.join(TESTDATA_PATH, name)
  with open(data_path) as f:
    return f.read()


def read_data_from_file(file_path):
  """Reads data from file."""
  with open(file_path, 'rb') as file_handle:
    return file_handle.read().decode('utf-8')


def create_mock_popen(output,
                      corpus_path=None,
                      merge_corpus_path=None,
                      number_of_testcases=0,
                      return_code=0):
  """Creates a mock subprocess.Popen."""

  class MockPopen:
    """Mock subprocess.Popen."""
    commands = []
    testcases_written = []

    def __init__(self, command, *args, **kwargs):
      """Inits the MockPopen."""
      stdout = kwargs.pop('stdout', None)
      self.command = command
      self.commands.append(command)
      self.stdout = None
      self.return_code = return_code
      if hasattr(stdout, 'write'):
        self.stdout = stdout

    def _do_merge(self):
      """Mock merge."""
      if not corpus_path or not merge_corpus_path:
        return

      for filepath in os.listdir(corpus_path):
        shutil.copy(os.path.join(corpus_path, filepath), merge_corpus_path)

    def _write_fake_units(self):
      """Mock writing of new units."""
      for i in range(number_of_testcases):
        with open(os.path.join(corpus_path, str(i)), 'w') as f:
          f.write(str(i))

        self.testcases_written.append(str(i))

    def communicate(self, input_data=None):
      """Mock subprocess.Popen.communicate."""
      if '/fake/build_dir/fake_fuzzer' in self.command:
        if '-merge=1' in self.command:
          # Mock merge.
          self._do_merge()
        else:
          # Mock writing of new units.
          self._write_fake_units()

      if self.stdout:
        self.stdout.write(output)
      return None, None

    def poll(self, input_data=None):
      """Mock subprocess.Popen.poll."""
      return self.return_code

  return MockPopen


def mock_create_tmp_mount(base_dir):
  """Mock minijail._create_tmp_mount."""
  path = os.path.join(base_dir, 'TEMP')
  os.mkdir(path)
  return path


def mock_create_chroot_dir(base_dir):
  """Mock minijail._create_chroot_dir."""
  path = os.path.join(base_dir, 'CHROOT')
  os.mkdir(path)
  return path


def set_strategy_pool(strategies=None):
  """Helper method to create instances of strategy pools
  for patching use."""
  strategy_pool = strategy_selection.StrategyPool()

  if strategies is not None:
    for strategy_tuple in strategies:
      strategy_pool.add_strategy(strategy_tuple)
  return strategy_pool


class SelectGeneratorTest(unittest.TestCase):
  """Tests for _select_generator."""
  FUZZER_PATH = '/fake/fuzzer_path'

  def setUp(self):
    self.pool = strategy_selection.generate_default_strategy_pool(
        strategy_list=strategy.LIBFUZZER_STRATEGY_LIST, use_generator=True)
    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.engine_common.is_lpm_fuzz_target',
        'clusterfuzz._internal.bot.fuzzers.strategy_selection.StrategyPool.do_strategy'
    ])
    self.mock.is_lpm_fuzz_target.return_value = True
    self.mock.do_strategy.return_value = True

  def test_lpm_fuzz_target(self):
    self.assertEqual(engine_common.Generator.NONE,
                     engine_common.select_generator(self.pool,
                                                    self.FUZZER_PATH))  # pylint: disable=protected-access


class ShouldSetForkFlagTest(unittest.TestCase):
  """Tests for should_set_fork_flag."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.build_dir = os.path.join(SCRIPT_DIR, 'run_data', 'build_dir')

  def test_zero(self):
    """Tests that should_set_fork_flag doesn't return True when it is already
    set to 0."""
    fuzzer_path = os.path.join(self.build_dir, 'fake1_fuzzer')
    existing_arguments = fuzzer.get_arguments(fuzzer_path)

    class MockPool:

      def do_strategy(self, *args, **kwargs):
        del args
        del kwargs
        return True

    self.assertFalse(
        libfuzzer.should_set_fork_flag(existing_arguments, MockPool()))


if __name__ == '__main__':
  unittest.main()

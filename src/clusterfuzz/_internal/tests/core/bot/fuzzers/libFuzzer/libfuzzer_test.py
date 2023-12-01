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

import pyfakefs.fake_filesystem_unittest as fake_fs_unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import libfuzzer
from clusterfuzz._internal.bot.fuzzers import strategy_selection
from clusterfuzz._internal.fuzzing import strategy
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

TESTDATA_PATH = os.path.join(os.path.dirname(__file__), 'libfuzzer_test_data')

BOT_NAME = 'test-bot'
BUILD_DIR = '/fake/build_dir'
FUZZ_INPUTS_DISK = '/fake/inputs-disk'
GSUTIL_PATH = '/fake/gsutil_path'
FAKE_ROOT_DIR = '/fake_root'

# An arbirtrary SHA1 sum.
ARBITRARY_SHA1_HASH = 'dd122581c8cd44d0227f9c305581ffcb4b6f1b46'


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


class IsSha1HashTest(unittest.TestCase):
  """Tests for is_sha1_hash."""

  def test_non_hashes(self):
    """Tests that False is returned for non hashes."""
    self.assertFalse(libfuzzer.is_sha1_hash(''))
    self.assertFalse(libfuzzer.is_sha1_hash('z' * 40))
    self.assertFalse(libfuzzer.is_sha1_hash('a' * 50))
    fake_hash = str('z' + ARBITRARY_SHA1_HASH[1:])
    self.assertFalse(libfuzzer.is_sha1_hash(fake_hash))

  def test_hash(self):
    """Tests that False is returned for a real hash."""
    self.assertTrue(libfuzzer.is_sha1_hash(ARBITRARY_SHA1_HASH))


class MoveMergeableUnitsTest(fake_fs_unittest.TestCase):
  """Tests for move_mergeable_units."""
  CORPUS_DIRECTORY = '/corpus'
  MERGE_DIRECTORY = '/corpus-merge'

  def setUp(self):
    test_utils.set_up_pyfakefs(self)

  def move_mergeable_units(self):
    """Helper function for move_mergeable_units."""
    libfuzzer.move_mergeable_units(self.MERGE_DIRECTORY, self.CORPUS_DIRECTORY)

  def test_duplicate_not_moved(self):
    """Tests that a duplicated file is not moved into the corpus directory."""
    self.fs.create_file(
        os.path.join(self.CORPUS_DIRECTORY, ARBITRARY_SHA1_HASH))
    merge_corpus_file = os.path.join(self.MERGE_DIRECTORY, ARBITRARY_SHA1_HASH)
    self.fs.create_file(merge_corpus_file)
    self.move_mergeable_units()
    # File will be deleted from merge directory if it isn't a duplicate.
    self.assertTrue(os.path.exists(merge_corpus_file))

  def test_new_file_moved(self):
    """Tests that a new file is moved into the corpus directory."""
    # Make a file that looks like a sha1 hash but is different from
    # ARBITRARY_SHA1_HASH.
    filename = ARBITRARY_SHA1_HASH.replace('d', 'a')
    self.fs.create_file(os.path.join(self.CORPUS_DIRECTORY, filename))
    # Create an arbitrary file with a hash name that is different from this
    # filename.
    merge_corpus_file = os.path.join(self.MERGE_DIRECTORY, ARBITRARY_SHA1_HASH)
    self.fs.create_file(merge_corpus_file)
    self.move_mergeable_units()
    # File will be deleted from merge directory if it isn't a duplicate.
    self.assertFalse(os.path.exists(merge_corpus_file))
    self.assertTrue(
        os.path.exists(os.path.join(self.CORPUS_DIRECTORY, filename)))


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
    self.mock.do_strategy.return_value = True
    self.mock.is_lpm_fuzz_target.return_value = True

  def test_lpm_fuzz_target(self):
    self.assertEqual(engine_common.Generator.NONE,
                     engine_common.select_generator(self.pool,
                                                    self.FUZZER_PATH))  # pylint: disable=protected-access


if __name__ == '__main__':
  unittest.main()

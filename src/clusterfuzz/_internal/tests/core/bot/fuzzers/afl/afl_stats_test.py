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
"""Test the stats.py script for AFL-based fuzzers."""

import copy
import os
import unittest

import mock
import six

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.afl import launcher
from clusterfuzz._internal.bot.fuzzers.afl import stats
from clusterfuzz._internal.fuzzing import strategy
from clusterfuzz._internal.tests.core.bot.fuzzers.afl.afl_launcher_test import \
    dont_use_strategies
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


def override_fail_retries(env_var, default_value=None):
  """Used to patch environment.getEnv to set FAIL_RETRIES."""
  return os.getenv(
      env_var, default=default_value) if env_var != 'FAIL_RETRIES' else 1


class StatsGetterTests(unittest.TestCase):
  """Tests for launcher.StatsGetter"""
  MANUAL_DICT_SIZE = 3
  NEW_UNITS_GENERATED = 2
  NEW_UNITS_ADDED = 1
  CORPUS_SIZE = 20
  ACTUAL_DURATION = 5

  @mock.patch('clusterfuzz._internal.system.environment.get_value',
              override_fail_retries)
  def setUp(self):

    def get_data_path(filename, is_in_output=True):
      """Returns absolute path of data files used in unittests."""
      input_or_output_dir = 'output' if is_in_output else 'input'
      return os.path.join(self.data_dir, input_or_output_dir, filename)

    self.data_dir = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), 'stats_data')
    self.fuzzer_stats_path = get_data_path('fuzzer_stats')
    self.fuzzer_stats_invalid_path = get_data_path('fuzzer_stats_invalid')
    self.dict_path = get_data_path('sample.dict', False)

    self.stats_getter = stats.StatsGetter(self.fuzzer_stats_path,
                                          self.dict_path)

    self.stats_getter.set_afl_stats()
    dont_use_strategies(self)
    test_helpers.patch(
        self,
        ['clusterfuzz._internal.bot.fuzzers.engine_common.is_lpm_fuzz_target'])
    self.mock.is_lpm_fuzz_target.return_value = True
    self.strategies = launcher.FuzzingStrategies(None)

    self.maxDiff = None  # pylint: disable=invalid-name

  def test_set_afl_stats(self):
    """Tests that set_afl_stats() parses a fuzzer_stats file properly."""
    expected_stats = {
        'afl_version': '2.38',
        'bitmap_cvg': '0.00',
        'cur_path': '1',
        'cycles_done': '1376',
        'execs_done': '621037',
        'execs_per_sec': '76.19',
        'execs_since_crash': '621037',
        'exec_timeout': '20',
        'fuzzer_pid': '37784',
        'last_crash': '0',
        'last_hang': '1504640708',
        'last_path': '1504640693',
        'last_update': '1504640710',
        'max_depth': '2',
        'paths_favored': '2',
        'paths_found': '1',
        'paths_imported': '0',
        'paths_total': '2',
        'pending_favs': '0',
        'pending_total': '0',
        'stability': '100.00',
        'start_time': '1504640693',
        'unique_crashes': '0',
        'unique_hangs': '1',
        'variable_paths': '0',
    }

    self.assertEqual(self.stats_getter.afl_stats, expected_stats)

  @mock.patch('clusterfuzz._internal.system.environment.get_value',
              override_fail_retries)
  def _set_stats(self):
    """Helper function that calls self.stats_getter.set_stats with default
    values and returns the result.
    """
    return self.stats_getter.set_stats(
        self.ACTUAL_DURATION,
        self.NEW_UNITS_GENERATED,
        self.NEW_UNITS_ADDED,
        self.CORPUS_SIZE,
        self.strategies,
        fuzzer_stderr='',
        afl_fuzz_output='')

  def test_dict_stats(self):
    """Tests that "dict_used" and "manual_dict_size" are set properly by
    set_stats() when self.stats_getter is given a valid dictionary.
    """
    actual_stats = self._set_stats()

    self.assertEqual(actual_stats['dict_used'], 1)
    self.assertEqual(actual_stats['manual_dict_size'], self.MANUAL_DICT_SIZE)

  def test_stats_without_dict(self):
    """Tests that "dict_used" and "manual_dict_size" are set properly by
    set_stats() when self.stats_getter is *not* given a dictionary.
    """
    self.stats_getter.dict_path = None
    actual_stats = self._set_stats()
    self.assertEqual(actual_stats['dict_used'], 0)
    self.assertEqual(actual_stats['manual_dict_size'], 0)

  def test_set_stats(self):
    """Tests that all stats are set properly by set_stats() when stats_getter
    is given a valid fuzzer_stats file.
    """
    actual_stats = self._set_stats()

    expected_stats = {
        'actual_duration': 5,
        'average_exec_per_sec': 124207,
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'corpus_size': 20,
        'crash_count': 0,
        'dict_used': 1,
        'log_lines_unwanted': 0,
        'manual_dict_size': 3,
        'new_units_added': 1,
        'new_units_generated': 2,
        'stability': 100.0,
        'startup_crash_count': 0,
        'strategy_selection_method': 'default',
        'timeout_count': 1,
        'timeout_limit': 20,
    }

    self.assertEqual(actual_stats, expected_stats)

  def test_set_stats_no_file(self):
    """Tests that set_stats() sets the correct stats or uses default stats when
    there is no fuzzer_stats file."""

    fuzzer_stats_path = self.fuzzer_stats_path + '.nonexistent'
    self.stats_getter = stats.StatsGetter(fuzzer_stats_path, self.dict_path)
    expected_stats = {
        'actual_duration': 5,
        'average_exec_per_sec': 0,
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'corpus_size': 20,
        'crash_count': 0,
        'dict_used': 1,
        'log_lines_unwanted': 0,
        'manual_dict_size': 3,
        'new_units_added': 1,
        'new_units_generated': 2,
        'stability': 0.0,
        'startup_crash_count': 0,
        'strategy_selection_method': 'default',
        'timeout_count': 0,
        'timeout_limit': 0,
    }
    self.assertEqual(self._set_stats(), expected_stats)

  def test_set_stats_invalid_file(self):
    """Tests that all stats are set properly by set_stats() when stats_getter
    is *not* given a valid fuzzer_stats file.
    """
    expected_stats = {
        'actual_duration': 5,
        'average_exec_per_sec': 0,
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'corpus_size': 20,
        'crash_count': 0,
        'dict_used': 1,
        'log_lines_unwanted': 0,
        'manual_dict_size': 3,
        'new_units_added': 1,
        'new_units_generated': 2,
        'stability': 0.0,
        'startup_crash_count': 0,
        'strategy_selection_method': 'default',
        'timeout_count': 0,
        'timeout_limit': 0,
    }

    self.stats_getter = stats.StatsGetter(self.fuzzer_stats_invalid_path,
                                          self.dict_path)

    actual_stats = self._set_stats()
    self.assertEqual(actual_stats, expected_stats)

  @mock.patch('clusterfuzz._internal.system.environment.get_value',
              override_fail_retries)
  def test_actual_duration_is_0(self):
    """Tests that average_exec_per_sec is set to 0 when actual_duration is 0."""
    self.stats_getter.set_stats(
        0,
        self.NEW_UNITS_GENERATED,
        self.NEW_UNITS_ADDED,
        self.CORPUS_SIZE,
        self.strategies,
        fuzzer_stderr='',
        afl_fuzz_output='')

    self.assertEqual(self.stats_getter.stats['average_exec_per_sec'], 0)

  @mock.patch('clusterfuzz._internal.system.environment.get_value',
              override_fail_retries)
  def test_log_lines_unwanted(self):
    """Tests that average_exec_per_sec is set to 0 when actual_duration is 0."""
    with open(os.path.join(self.data_dir, 'unwanted_logging.txt')) as f:
      fuzzer_stderr = f.read()

    self.stats_getter.set_stats(
        self.ACTUAL_DURATION,
        self.NEW_UNITS_GENERATED,
        self.NEW_UNITS_ADDED,
        self.CORPUS_SIZE,
        self.strategies,
        fuzzer_stderr,
        afl_fuzz_output='')

    self.assertEqual(self.stats_getter.stats['log_lines_unwanted'], 18)

  def test_get_afl_stat(self):
    """Tests that get_afl_stat works as intended when a stat that is in
    fuzzer_stats is asked for."""
    self.assertEqual(self.stats_getter.get_afl_stat('paths_total'), 2)

  def test_get_missing_afl_stat(self):
    """Tests that get_afl_stat returns 0 when a stat that is *not* in
      fuzzer_stats is asked for."""
    self.assertEqual(self.stats_getter.get_afl_stat('MISSING_STAT'), 0)

  def test_correct_types(self):
    """Tests that the types of the stats set by StatsGetter.set_stats are the
    same as the default ones."""
    default_stats = copy.copy(self.stats_getter.stats)
    actual_stats = self._set_stats()
    for stat_key, stat_value in six.iteritems(default_stats):
      self.assertEqual(type(stat_value), type(actual_stats[stat_key]))

  def test_set_strategy_stats(self):
    """Tests that set_strategy_stats works as intended."""
    self.strategies.use_corpus_subset = True
    self.strategies.corpus_subset_size = 75
    # Implicitly calls set_strategy_stats
    actual_stats = self._set_stats()
    self.assertEqual(
        actual_stats['strategy_' + strategy.CORPUS_SUBSET_STRATEGY.name], 75)

    # Test that stats for generator strategies are correct.
    self.strategies.generator_strategy = engine_common.Generator.RADAMSA
    actual_stats = self._set_stats()
    self.assertEqual(
        actual_stats['strategy_' +
                     strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name], 1)

    self.strategies.generator_strategy = engine_common.Generator.ML_RNN
    actual_stats = self._set_stats()
    self.assertEqual(
        actual_stats['strategy_' +
                     strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name], 1)

  def test_set_output_stats_bad_instrumentation(self):
    """Tests that set_output_stats sets bad_instrumentation properly."""
    stdout_path = os.path.join(self.data_dir, 'bad_instrumentation.txt')
    with open(stdout_path) as file_handle:
      afl_fuzz_output = file_handle.read()
    self.stats_getter.set_output_stats(afl_fuzz_output)
    self.assertEqual(self.stats_getter.stats['bad_instrumentation'], 1)

  def test_set_output_stats_corpus_crash(self):
    """Tests that set_output_stats sets corpus_crash_count properly."""
    stdout_path = os.path.join(self.data_dir, 'corpus_crash.txt')
    with open(stdout_path) as file_handle:
      afl_fuzz_output = file_handle.read()
    self.stats_getter.set_output_stats(afl_fuzz_output)
    self.assertEqual(self.stats_getter.stats['corpus_crash_count'], 1)

  def test_set_output_stats_startup_crash(self):
    """Tests that set_output_stats sets startup_crash_count properly."""
    stdout_path = os.path.join(self.data_dir, 'startup_crash.txt')
    with open(stdout_path) as file_handle:
      afl_fuzz_output = file_handle.read()
    self.stats_getter.set_output_stats(afl_fuzz_output)
    self.assertEqual(self.stats_getter.stats['startup_crash_count'], 1)

  def test_set_output_stats_startup_crash2(self):
    """Tests that set_output_stats sets startup_crash_count properly."""
    stdout_path = os.path.join(self.data_dir, 'startup_crash2.txt')
    with open(stdout_path) as file_handle:
      afl_fuzz_output = file_handle.read()
    self.stats_getter.set_output_stats(afl_fuzz_output)
    self.assertEqual(self.stats_getter.stats['startup_crash_count'], 1)

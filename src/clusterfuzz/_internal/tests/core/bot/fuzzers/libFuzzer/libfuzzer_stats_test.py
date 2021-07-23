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
"""Tests for stats."""

import os
import unittest

from clusterfuzz._internal.bot.fuzzers import libfuzzer
from clusterfuzz._internal.bot.fuzzers.libFuzzer import stats
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class PerformanceStatsTest(unittest.TestCase):
  """Performance stats tests class."""

  def setUp(self):
    """Prepare test data and necessary env variables."""
    self.maxDiff = None  # pylint: disable=invalid-name

    test_helpers.patch_environ(self)
    self.data_directory = os.path.join(
        os.path.dirname(__file__), 'libfuzzer_test_data')

  def _read_test_data(self, name):
    """Read test data."""
    data_path = os.path.join(self.data_directory, name)
    with open(data_path) as f:
      return f.read().splitlines()

  def test_parse_stats_from_merge_log(self):
    """Test parsing of a log file produced by libFuzzer run with -merge=1."""
    lines = self._read_test_data('merge_step_1.txt')
    actual_stats = stats.parse_stats_from_merge_log(lines)

    expected_stats = {
        'edge_coverage': 410,
        'feature_coverage': 1869,
    }
    self.assertEqual(expected_stats, actual_stats)

  def test_parse_log_stats(self):
    """Test pure stats parsing without applying of stat_overrides."""
    log_lines = self._read_test_data('no_crash.txt')
    parsed_stats = libfuzzer.parse_log_stats(log_lines)
    expected_stats = {
        'average_exec_per_sec': 97,
        'new_units_added': 55,
        'new_units_generated': 55,
        'number_of_executed_units': 258724,
        'peak_rss_mb': 103,
        'slowest_unit_time_sec': 0
    }

    self.assertEqual(parsed_stats, expected_stats)

  def test_parse_log(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self._read_test_data('no_crash_with_strategies.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [], [])
    expected_stats = {
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'crash_count': 0,
        'corpus_size': 0,
        'dict_used': 1,
        'edge_coverage': 0,
        'edges_total': 398408,
        'feature_coverage': 0,
        'initial_edge_coverage': 0,
        'initial_feature_coverage': 0,
        'leak_count': 0,
        'log_lines_from_engine': 65,
        'log_lines_ignored': 8,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 741802,
        'merge_edge_coverage': 0,
        'new_edges': 0,
        'new_features': 0,
        'oom_count': 0,
        'recommended_dict_size': 0,
        'slow_unit_count': 0,
        'slow_units_count': 0,
        'startup_crash_count': 0,
        'strategy_dataflow_tracing': 0,
        'strategy_corpus_mutations_radamsa': 1,
        'strategy_corpus_mutations_ml_rnn': 0,
        'strategy_corpus_subset': 50,
        'strategy_fork': 1,
        'strategy_mutator_plugin_radamsa': 0,
        'strategy_peach_grammar_mutation': '',
        'strategy_mutator_plugin': 1,
        'strategy_random_max_len': 1,
        'strategy_recommended_dict': 0,
        'strategy_selection_method': 'default',
        'strategy_value_profile': 0,
        'timeout_count': 0
    }

    self.assertDictEqual(expected_stats, parsed_stats)

  def test_parse_log_and_stats_crash(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self._read_test_data('crash.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [],
                                                    ['-max_len=1337'])
    self.assertEqual(1, parsed_stats['crash_count'])
    self.assertEqual(0, parsed_stats['corpus_crash_count'])
    self.assertEqual(0, parsed_stats['startup_crash_count'])

  def test_parse_log_and_stats_go_fuzz(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides for a Go fuzz target."""
    log_lines = self._read_test_data('go_fuzz_log.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [],
                                                    ['-max_len=1337'])
    self.assertEqual(0, parsed_stats['crash_count'])
    self.assertEqual(0, parsed_stats['corpus_crash_count'])
    self.assertEqual(0, parsed_stats['startup_crash_count'])

  def test_parse_log_and_stats_go_fork_fuzz(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides for a Go fuzz target in fork mode."""
    log_lines = self._read_test_data('go_fork_fuzz_log.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [],
                                                    ['-max_len=1337'])
    self.assertEqual(0, parsed_stats['crash_count'])
    self.assertEqual(0, parsed_stats['corpus_crash_count'])
    self.assertEqual(0, parsed_stats['startup_crash_count'])

  def test_parse_log_and_stats_fork_fuzz(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides for a fuzz target in fork mode."""
    log_lines = self._read_test_data('fork_fuzz_log.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [],
                                                    ['-max_len=1337'])
    self.assertEqual(0, parsed_stats['crash_count'])
    self.assertEqual(0, parsed_stats['corpus_crash_count'])
    self.assertEqual(0, parsed_stats['startup_crash_count'])

  def test_parse_log_and_stats_startup_crash(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self._read_test_data('startup_crash.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [],
                                                    ['-max_len=1337'])
    self.assertEqual(0, parsed_stats['crash_count'])
    self.assertEqual(0, parsed_stats['corpus_crash_count'])
    self.assertEqual(1, parsed_stats['startup_crash_count'])

  def test_parse_log_and_stats_corpus_crash(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self._read_test_data('corpus_crash.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [], [])
    self.assertEqual(1, parsed_stats['crash_count'])
    self.assertEqual(1, parsed_stats['corpus_crash_count'])
    self.assertEqual(0, parsed_stats['startup_crash_count'])

  def test_parse_log_and_stats_corpus_crash_with_corpus_subset(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self._read_test_data('corpus_crash_with_corpus_subset.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [], [])
    self.assertEqual(1, parsed_stats['strategy_corpus_subset'])

  def test_parse_log_and_stats_oom(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self._read_test_data('oom.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [], [])
    self.assertEqual(1, parsed_stats['oom_count'])
    self.assertEqual(0, parsed_stats['timeout_count'])

  def test_parse_log_and_stats_oom_in_seed_corpus(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self._read_test_data('oom_in_seed_corpus.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [], [])
    self.assertEqual(1, parsed_stats['oom_count'])
    self.assertEqual(0, parsed_stats['timeout_count'])

  def test_parse_log_and_stats_from_corrupted_output(self):
    """Test stats parsing from a log with corrupted libFuzzer stats."""
    log_lines = self._read_test_data('corrupted_stats.txt')
    parsed_stats = libfuzzer.parse_log_stats(log_lines)
    self.assertNotIn('peak_rss_mb', parsed_stats)

  def test_parse_log_and_stats_timeout(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self._read_test_data('timeout.txt')
    parsed_stats = stats.parse_performance_features(log_lines, [], [])
    self.assertEqual(0, parsed_stats['oom_count'])
    self.assertEqual(1, parsed_stats['timeout_count'])

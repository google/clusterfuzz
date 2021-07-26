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
"""Tests for performance_analyzer."""

import json
import os
import unittest

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import libfuzzer
from clusterfuzz._internal.bot.fuzzers.libFuzzer import \
    stats as performance_stats
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from handlers.performance_report import performance_analyzer

# Use default values for stats values usually provided by CF.
DEFAULT_STATS_PROVIDED_BY_CF = {
    'actual_duration': 2350,
    'expected_duration': 2350,
    'timestamp': 1499904000.017923
}


def _get_stats_from_log(log_path,
                        strategies=None,
                        arguments=None,
                        stats_overrides=None):
  """Calculate stats for the given log the same way as the engine does."""
  if strategies is None:
    strategies = []
  if arguments is None:
    arguments = []

  log_lines = utils.decode_to_unicode(
      utils.read_data_from_file(log_path, eval_data=False)).splitlines()
  stats = libfuzzer.parse_log_stats(log_lines)
  stats.update(
      performance_stats.parse_performance_features(log_lines, strategies,
                                                   arguments))
  if stats_overrides:
    stats.update(stats_overrides)

  return stats


class PerformanceAnalyzerTestBase(unittest.TestCase):
  """Performance analysis tests base class."""

  def setUp(self):
    """Prepare test data and necessary env variables."""
    test_helpers.patch_environ(self)
    self.data_directory = os.path.join(
        os.path.dirname(__file__), 'performance_analyzer_data')
    self.libfuzzer_data_directory = os.path.join(self.data_directory,
                                                 'libfuzzer')
    environment.set_value('FAIL_RETRIES', 1)

    self.analyzer = performance_analyzer.LibFuzzerPerformanceAnalyzer()


class PerformanceAnalyzerBasicAnalyzerTest(PerformanceAnalyzerTestBase):
  """Performance analysis tests for BasicAnalyzer functions."""

  def assert_basic_analyzer(self,
                            basic_analyzer,
                            log_filename,
                            stats_overrides=None):
    """Assert for testing a single basic analyzer."""
    extra_stats = DEFAULT_STATS_PROVIDED_BY_CF.copy()
    if stats_overrides:
      extra_stats.update(stats_overrides)

    log_file_path = os.path.join(self.libfuzzer_data_directory, 'issue_logs',
                                 log_filename)
    stats = _get_stats_from_log(log_file_path, stats_overrides=extra_stats)
    self.assertGreater(basic_analyzer(stats), 0.0)

  def test_basic_analyzer_for_bad_instrumentation(self):
    """Test analyzer_bad_instrumentation BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_bad_instrumentation,
                               'bad_instrumentation_issue.txt')

  def test_basic_analyzer_for_coverage(self):
    """Test analyzer_coverage BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_coverage,
                               'coverage_issue.txt')

  def test_basic_analyzer_for_crash(self):
    """Test analyzer_crash BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_crash, 'crash_issue.txt')

  def test_basic_analyzer_for_leak(self):
    """Test analyzer_leak BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_leak, 'leak_issue.txt')

  def test_basic_analyzer_for_logging(self):
    """Test analyzer_logging BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_logging,
                               'logging_issue.txt')

  def test_basic_analyzer_for_oom(self):
    """Test analyzer_oom BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_oom, 'oom_issue.txt')

  def test_basic_analyzer_for_slow_unit(self):
    """Test analyzer_slow_unit BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_slow_unit,
                               'slow_unit_issue.txt')

  def test_basic_analyzer_for_speed(self):
    """Test analyzer_speed BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_speed, 'speed_issue.txt')

  def test_basic_analyzer_for_startup_crash(self):
    """Test analyzer_startup_crash BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_startup_crash,
                               'startup_crash_issue.txt')

  def test_basic_analyzer_for_timeout(self):
    """Test analyzer_timeout BasicAnalyzer."""
    self.assert_basic_analyzer(self.analyzer.analyzer_timeout,
                               'timeout_issue.txt')


class PerformanceAnalyzerTest(PerformanceAnalyzerTestBase):
  """Performance analysis tests."""

  def get_issues(self, log_filename, stats_overrides=None):
    """Returns the issue for a particular log file."""
    extra_stats = DEFAULT_STATS_PROVIDED_BY_CF.copy()
    if stats_overrides:
      extra_stats.update(stats_overrides)

    log_file_path = os.path.join(self.libfuzzer_data_directory, 'issue_logs',
                                 log_filename)
    stats = _get_stats_from_log(log_file_path, stats_overrides=extra_stats)

    analyzer = performance_analyzer.LibFuzzerPerformanceAnalyzer()
    performance_scores, affected_runs_percents, examples = (
        analyzer.analyze_stats([stats]))

    return analyzer.get_issues(performance_scores, affected_runs_percents,
                               examples)

  def assert_log_has_issue_matching(self,
                                    log_filename,
                                    expected_issue,
                                    stats_overrides=None):
    """Assert for testing log has a particular issue."""
    detected_issues = self.get_issues(log_filename, stats_overrides)
    actual_issue = next(
        (i for i in detected_issues if i['type'] == expected_issue['type']),
        None)

    self.assertIsNotNone(
        actual_issue,
        '"%s" issue is not found in the result' % expected_issue['type'])
    self.assertEqual(actual_issue['percent'], expected_issue['percent'])
    self.assertEqual(actual_issue['score'], expected_issue['score'])

  def assert_log_has_no_issue_matching(self, log_filename, issue_type):
    """Assert for testing log has no issue matching a particular type."""
    detected_issues = self.get_issues(log_filename)
    detected_issue_types = [i['type'] for i in detected_issues]
    self.assertNotIn(issue_type, detected_issue_types)

  def assert_log_has_no_issues(self, log_filename, stats_overrides=None):
    """Assert for testing log has no issues."""
    expected_issue = {
        'type': 'none',
        'percent': 100.0,
        'score': 0.0,
        'examples': []
    }
    detected_issues = self.get_issues(log_filename, stats_overrides)
    self.assertEqual(detected_issues, [expected_issue])

  def test_bad_instrumentation(self):
    """Test bad instrumentation issue."""
    expected_issue = {
        'type': 'bad_instrumentation',
        'percent': 100.0,
        'score': 256.0
    }
    self.assert_log_has_issue_matching('bad_instrumentation_issue.txt',
                                       expected_issue)

  def test_coverage(self):
    """Test coverage issue."""
    expected_issue = {'type': 'coverage', 'percent': 100.0, 'score': 1.0}
    self.assert_log_has_issue_matching('coverage_issue.txt', expected_issue)

  def test_crash(self):
    """Test crash issue."""
    expected_issue = {'type': 'crash', 'percent': 100.0, 'score': 4.0}
    self.assert_log_has_issue_matching('crash_issue.txt', expected_issue)

  def test_leak(self):
    """Test leak issue."""
    expected_issue = {'type': 'leak', 'percent': 100.0, 'score': 128.0}
    self.assert_log_has_issue_matching('leak_issue.txt', expected_issue)

  def test_logging(self):
    """Test logging issue."""
    expected_issue = {'type': 'logging', 'percent': 100.0, 'score': 0.86}
    self.assert_log_has_issue_matching('logging_issue.txt', expected_issue)

  def test_oom(self):
    """Test oom issue."""
    expected_issue = {'type': 'oom', 'percent': 100.0, 'score': 8.0}
    self.assert_log_has_issue_matching('oom_issue.txt', expected_issue)

  def test_slow_unit(self):
    """Test slow unit issue."""
    expected_issue = {'type': 'slow_unit', 'percent': 100.0, 'score': 2.4}
    self.assert_log_has_issue_matching('slow_unit_issue.txt', expected_issue)

  def test_speed(self):
    """Test speed issue."""
    expected_issue = {'type': 'speed', 'percent': 100.0, 'score': 0.99}
    self.assert_log_has_issue_matching('speed_issue.txt', expected_issue)

  def test_startup_crash(self):
    """Test startup crash issue."""
    stats_overrides = {'average_exec_per_sec': 0, 'new_units_added': 0}
    expected_issue = {'type': 'startup_crash', 'percent': 100.0, 'score': 256.0}
    self.assert_log_has_issue_matching('startup_crash_issue.txt',
                                       expected_issue, stats_overrides)

  def test_no_startup_crash(self):
    """Test startup crash is not detected when libFuzzer exists early."""
    self.assert_log_has_no_issue_matching('startup_crash_no_issue.txt',
                                          'startup_crash')

  def test_timeout(self):
    """Test 'timeout' issue."""
    expected_issue = {'type': 'timeout', 'percent': 100.0, 'score': 64.0}
    self.assert_log_has_issue_matching('timeout_issue.txt', expected_issue)

  def test_no_logging_with_recommended_dictionaries(self):
    """Test no logging issue for a log with recommended dictionaries."""
    self.assert_log_has_no_issue_matching(
        'logging_recommended_dictionary_no_issue.txt', 'logging')

  def test_no_logging_with_crash(self):
    """Test no logging issue for a log with crash."""
    self.assert_log_has_no_issue_matching('logging_crash_no_issue.txt',
                                          'logging')

  def test_no_logging_with_slow_units(self):
    """Test no logging issue for a log with slow units."""
    self.assert_log_has_no_issue_matching('logging_slow_units_no_issue.txt',
                                          'logging')

  def test_no_logging_with_sanitizer_frames(self):
    """Test no logging issue for a log with sanitizer warnings."""
    self.assert_log_has_no_issue_matching(
        'logging_sanitizer_warnings_no_issue.txt', 'logging')

  def test_no_logging_with_oom(self):
    """Test no logging issue for a log with ooms in between frames."""
    self.assert_log_has_no_issue_matching('logging_oom_no_issue.txt', 'logging')

  def test_no_logging_with_few_runs(self):
    """Test no logging issue for a log with few runs."""
    self.assert_log_has_no_issue_matching('logging_few_runs_no_issue.txt',
                                          'logging')

  def test_corpus_subset_run_speed_coverage(self):
    """Test corpus subset run is ignored for a log with speed and coverage
    issue."""
    self.assert_log_has_no_issues('corpus_subset_no_coverage_speed_issue.txt')

  def test_corpus_subset_run_crash(self):
    """Test corpus subset run is not ignored for a log with crash."""
    expected_issue = {'type': 'crash', 'percent': 100.0, 'score': 4.0}
    self.assert_log_has_issue_matching('corpus_subset_crash_issue.txt',
                                       expected_issue)

  def test_perfect_fuzzer(self):
    """Test a perfect fuzzer, i.e. with no issues."""
    self.assert_log_has_no_issues('no_issue.txt')

  def test_report_generation(self):
    """Test report generation for a directory."""
    analyzer = performance_analyzer.LibFuzzerPerformanceAnalyzer()
    report_logs_directory = os.path.join(self.libfuzzer_data_directory,
                                         'report_logs')
    stats_rows = []

    # Use default values for stats values usually provided by CF.
    stats_overrides = DEFAULT_STATS_PROVIDED_BY_CF.copy()

    for filename in sorted(os.listdir(report_logs_directory)):
      # Use different timestamp values for each log.
      stats_overrides['timestamp'] += 1

      stats_rows.append(
          _get_stats_from_log(
              os.path.join(report_logs_directory, filename),
              stats_overrides=stats_overrides))

    performance_scores, affected_runs_percents, examples = (
        analyzer.analyze_stats(stats_rows))

    performance_issues = analyzer.get_issues(performance_scores,
                                             affected_runs_percents, examples)
    performance_report = performance_analyzer.generate_report(
        performance_issues, 'fuzzer1', 'job1')

    expected_report = utils.read_data_from_file(
        os.path.join(self.libfuzzer_data_directory, 'expected_report.json'),
        eval_data=False)

    self.maxDiff = None  # pylint: disable=invalid-name
    self.assertEqual(
        json.loads(performance_report), json.loads(expected_report))

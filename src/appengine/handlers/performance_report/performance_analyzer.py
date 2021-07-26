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
"""Classes for dealing with Performance Analysis."""

import collections
import datetime
import json
import operator

from clusterfuzz._internal.metrics import fuzzer_logs

# A tuple representing an analyzer for a single problem.
BasicAnalyzer = collections.namedtuple('Analyzer', 'checker weight description')

# Thresholds to be used in analyzers.
LOGGING_THRESHOLD = 0.5
LOGGING_RUNS_THRESHOLD = 5
NEW_UNITS_THRESHOLD = 1
SLOW_UNITS_THRESHOLD = 5
SPEED_THRESHOLD = 1000

# Limit on examples provided for an issue.
EXAMPLES_LIMIT = 5

# Values of weights to be used for performance analysis.
# TODO(mmoroz): https://github.com/google/oss-fuzz/issues/196.
# These values have been brute-forced during testing over logs of 115 fuzzers.
# This part will be removed or re-implemented during ongoing work on performance
# analysis. The new implementation will detect more issues and store analysis
# results in BigQuery.
WEIGHTS_FOR_LIBFUZZER = {
    'bad_instrumentation': 256.0,
    'coverage': 1.0,
    'crash': 4.0,
    'leak': 128.0,
    'logging': 1.0,
    'oom': 8.0,
    'slow_unit': 4.0,
    'speed': 1.0,
    'startup_crash': 256.0,
    'timeout': 64.0,
}


def generate_report(issues, fuzzer_name, job_type):
  """Generate a simple json representing performance analysis results.

  Args:
    issues: List of performance issues with corresponding scores and attributes.
    fuzzer_name: Fuzzer name.
    job_type: Job name.

  Returns:
    A json report for the given performance issues.
  """
  report_dict = {
      'fuzzer_name': fuzzer_name,
      'job_type': job_type,
      'issues': issues,
  }
  return json.dumps(report_dict, indent=2)


class PerformanceAnalyzer(object):
  """Performance Analyzer."""

  def __init__(self, analyzers):
    """Inits the PerformanceAnalyzer.

    Args:
      analyzers: List of BasicAnalyzer tuples to be used for analysis.
    """
    self._analyzers = analyzers

  @property
  def analyzers(self):
    return self._analyzers

  def analyze_stats(self, stats):
    """Process the given fuzzer stats.

    Args:
      stats: A list of fuzzer stats rows extracted from BigQuery.

    Returns:
      A list of scores corresponding to given analyzers, a list of percents
      showing how many fuzzer runs have been affected by each issue and a set
      of examples of that issue.
    """
    num_analyzers = len(self.analyzers)
    performance_scores = [0] * num_analyzers
    affected_runs_percent = [0] * num_analyzers
    examples = [set() for _ in range(num_analyzers)]

    if not stats:
      return performance_scores, affected_runs_percent, examples

    for row in stats:
      current_scores = self.analyze_single_stats_row(row)
      performance_scores = list(
          map(operator.add, performance_scores, current_scores))
      current_runs = [int(score > 0.0) for score in current_scores]
      affected_runs_percent = list(
          map(operator.add, affected_runs_percent, current_runs))

      # Add upto max |EXAMPLES_LIMIT| examples for each issue type.
      for i in range(num_analyzers):
        if current_scores[i] > 0.0 and len(examples[i]) < EXAMPLES_LIMIT:
          time_of_run = datetime.datetime.utcfromtimestamp(row['timestamp'])
          examples[i].add(fuzzer_logs.get_log_relative_path(time_of_run))

    # Data normalization. Divide the scores by the number of logs analyzed.
    runs_count = len(stats)
    performance_scores = [(score / runs_count) for score in performance_scores]

    # Data normalization. Convert affected runs into percents of all logs.
    affected_runs_percent = [
        ((count * 100.0) / runs_count) for count in affected_runs_percent
    ]

    return performance_scores, affected_runs_percent, examples

  def analyze_single_stats_row(self, row):
    """Analyze single stats row by given analyzers.

    Args:
      row: A dict containing stats data to be analysed.

    Returns:
      A list of scores corresponding to given analyzers.
    """
    scores = []
    for analyzer in self.analyzers:
      scores.append(analyzer.checker(row) * analyzer.weight)

    return scores

  def get_issues(self, scores, percents, examples):
    """Get list of issues and corresponding scores for given raw scores.

    Args:
      scores: Raw scores calculated with self.analyzers.
      percents: Percents of logs affected by each issue.
      examples: Log names showing this particular issue.

    Returns:
      A list of issues affecting the fuzzer with corresponding scores.
    """
    scores_sorted = sorted(
        ((value, index) for index, value in enumerate(scores)), reverse=True)

    detected_issues = []

    for value, index in scores_sorted:
      if value == 0.0:
        break

      detected_issues.append({
          'type': self.analyzers[index].description,
          'percent': round(percents[index], 2),
          'examples': sorted(examples[index]),
          'score': round(value, 2)
      })

    if not detected_issues:
      detected_issues.append({
          'type': 'none',
          'percent': 100.0,
          'examples': [],
          'score': 0.0
      })

    return detected_issues


class LibFuzzerPerformanceAnalyzer(PerformanceAnalyzer):
  """LibFuzzer specific Performance Analyzer using BigQuery data."""

  def __init__(self):
    """Inits the LibFuzzerPerformanceAnalyzer."""
    # Create a list of analyzers for libFuzzer-based fuzzers.
    analyzers = [
        BasicAnalyzer(self.analyzer_bad_instrumentation,
                      WEIGHTS_FOR_LIBFUZZER['bad_instrumentation'],
                      'bad_instrumentation'),
        BasicAnalyzer(self.analyzer_coverage, WEIGHTS_FOR_LIBFUZZER['coverage'],
                      'coverage'),
        BasicAnalyzer(self.analyzer_crash, WEIGHTS_FOR_LIBFUZZER['crash'],
                      'crash'),
        BasicAnalyzer(self.analyzer_leak, WEIGHTS_FOR_LIBFUZZER['leak'],
                      'leak'),
        BasicAnalyzer(self.analyzer_logging, WEIGHTS_FOR_LIBFUZZER['logging'],
                      'logging'),
        BasicAnalyzer(self.analyzer_oom, WEIGHTS_FOR_LIBFUZZER['oom'], 'oom'),
        BasicAnalyzer(self.analyzer_slow_unit,
                      WEIGHTS_FOR_LIBFUZZER['slow_unit'], 'slow_unit'),
        BasicAnalyzer(self.analyzer_speed, WEIGHTS_FOR_LIBFUZZER['speed'],
                      'speed'),
        BasicAnalyzer(self.analyzer_startup_crash,
                      WEIGHTS_FOR_LIBFUZZER['startup_crash'], 'startup_crash'),
        BasicAnalyzer(self.analyzer_timeout, WEIGHTS_FOR_LIBFUZZER['timeout'],
                      'timeout'),
    ]

    PerformanceAnalyzer.__init__(self, analyzers)

  def analyzer_bad_instrumentation(self, stats):
    """Check if there is bad instrumentation flag in the given stats.
    Returns a number in range [0.0, 1.0]."""
    if stats['bad_instrumentation']:
      return 1.0

    return 0.0

  def analyzer_coverage(self, stats):
    """Calculate a number of new units using the given stats data.
    Returns a number in range [0.0, 1.0]."""
    if stats.get('new_units_added') is None:
      # The stats row does not have new units info, i.e. there is another issue.
      return 0.0

    if stats['strategy_corpus_subset']:
      # We will always increase coverage when starting from a small subset, so
      # ignore these results.
      return 0.0

    if not stats['actual_duration']:
      return 0.0

    # Prorate the threshold in accordance with actual execution time.
    threshold = NEW_UNITS_THRESHOLD * (
        float(stats['actual_duration']) / stats['expected_duration'])
    if stats['new_units_added'] >= threshold:
      # The fuzzer finds NEW units quickly enough, coverage is not a problem.
      return 0.0

    # Result approaches 1.0 as fuzzer finds fewer new units.
    result = float(threshold - stats['new_units_added']) / threshold
    return min(1.0, result)

  def analyzer_crash(self, stats):
    """Check if there is a crash (ASan/MSan/UBSan) in the given stats.
    Returns a number in range [0.0, 1.0]."""
    if stats['crash_count']:
      return 1.0

    return 0.0

  def analyzer_leak(self, stats):
    """Check if there is a LeakSanitizer crash in the given stats.
    Returns a number in range [0.0, 1.0]."""
    if stats['leak_count']:
      return 1.0

    return 0.0

  def analyzer_logging(self, stats):
    """Calculate the fraction of redundant log lines of all logs lines.
    Returns number in range [0.0, 1.0]."""
    if stats['log_lines_from_engine'] < LOGGING_RUNS_THRESHOLD:
      # That means that fuzzer doesn't work and there is another problem, e.g.
      # a starup crash, or some troubles with configs, or anything else.
      return 0.0

    libfuzzer_and_other_lines_count = (
        stats['log_lines_from_engine'] + stats['log_lines_unwanted'])

    logging_score = (
        float(stats['log_lines_unwanted']) / libfuzzer_and_other_lines_count)

    if logging_score < LOGGING_THRESHOLD:
      # Ignore logging score if it's fewer than the threshold, as it often can
      # be greater that 0.0, but is not meaningful in terms of performance.
      logging_score = 0.0

    return logging_score

  def analyzer_oom(self, stats):
    """Check if there is a OOM crash in the given stats.
    Returns a number in range [0.0, 1.0]."""
    if stats['oom_count']:
      return 1.0

    return 0.0

  def analyzer_slow_unit(self, stats):
    """Calculates a number of slow units in the given stats.
    Returns a number in range [0.0, 1.0]."""
    if not stats['actual_duration']:
      return 0.0

    # Prorate the threshold in accordance with actual execution time.
    threshold = SLOW_UNITS_THRESHOLD * (
        float(stats['actual_duration']) / stats['expected_duration'])

    # A couple of slow units during fuzzing session is not that bad. This is
    # why we use a relative score below.
    return min(1.0, stats['slow_units_count'] / threshold)

  def analyzer_speed(self, stats):
    """Extract execution speed and compare to the threshold value.
    Returns a number in range [0.0, 1.0]."""
    if stats.get('average_exec_per_sec') is None:
      # The stats row does have speed info, i.e. there is another issue.
      return 0.0

    if stats['strategy_corpus_subset']:
      # When starting from a super small subset, we might have completely
      # different speed than when working from a large corpus, so ignore the
      # results.
      return 0.0

    if not stats['average_exec_per_sec']:
      # That means we have no stats in the log, there should be another problem.
      return 0.0

    # FIXME(mmoroz): needs more brainstorming. The same threshold value can be
    # unreachable for some fuzzers and too small for others.
    if stats['average_exec_per_sec'] >= SPEED_THRESHOLD:
      return 0.0

    # Result approaches 1.0 as fuzzer works slower.
    result = (
        float(SPEED_THRESHOLD - stats['average_exec_per_sec']) /
        SPEED_THRESHOLD)
    return min(1.0, result)

  def analyzer_startup_crash(self, stats):
    """Check if fuzzer had crashed on a startup."""
    if stats['startup_crash_count']:
      return 1.0

    return 0.0

  def analyzer_timeout(self, stats):
    """Check if there is a libFuzzer timeout in the stats.
    Returns a number in range [0.0, 1.0]."""
    if stats['timeout_count']:
      return 1.0

    return 0.0

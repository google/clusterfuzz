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
"""Performance stats constants and helpers for libFuzzer."""

import re

import constants

from bot.fuzzers import dictionary_manager
from bot.fuzzers import strategy
from bot.fuzzers import utils as fuzzer_utils
from crash_analysis.stack_parsing import stack_analyzer
from metrics import logs

# Regular expressions to detect different types of crashes.
LEAK_TESTCASE_REGEX = re.compile(r'.*ERROR: LeakSanitizer.*')
LIBFUZZER_BAD_INSTRUMENTATION_REGEX = re.compile(
    r'.*ERROR:.*Is the code instrumented for coverage.*')
LIBFUZZER_CRASH_TYPE_REGEX = r'.*Test unit written to.*{type}'
LIBFUZZER_CRASH_START_MARKER = r'.*ERROR: (libFuzzer|.*Sanitizer):'
LIBFUZZER_ANY_CRASH_TYPE_REGEX = re.compile(
    r'(%s|%s)' % (LIBFUZZER_CRASH_START_MARKER,
                  LIBFUZZER_CRASH_TYPE_REGEX.format(type='')))
LIBFUZZER_CRASH_TESTCASE_REGEX = re.compile(
    LIBFUZZER_CRASH_TYPE_REGEX.format(type='crash'))
LIBFUZZER_OOM_TESTCASE_REGEX = re.compile(
    LIBFUZZER_CRASH_TYPE_REGEX.format(type='oom'))
LIBFUZZER_SLOW_UNIT_TESTCASE_REGEX = re.compile(
    LIBFUZZER_CRASH_TYPE_REGEX.format(type='slow-unit'))
LIBFUZZER_TIMEOUT_TESTCASE_REGEX = re.compile(
    LIBFUZZER_CRASH_TYPE_REGEX.format(type='timeout'))

# Regular expressions to detect different sections of logs.
LIBFUZZER_FUZZING_STRATEGIES = re.compile(r'cf::fuzzing_strategies:\s*(.*)')
LIBFUZZER_LOG_COVERAGE_REGEX = re.compile(r'#\d+.*cov:\s+(\d+)\s+ft:\s+(\d+).*')
LIBFUZZER_LOG_DICTIONARY_REGEX = re.compile(r'Dictionary: \d+ entries')
LIBFUZZER_LOG_END_REGEX = re.compile(r'Done \d+ runs.*')
LIBFUZZER_LOG_IGNORE_REGEX = re.compile(r'.*WARNING:.*Sanitizer')
LIBFUZZER_LOG_LINE_REGEX = re.compile(r'^#\d+.*(READ|cov:)')
LIBFUZZER_LOG_SEED_CORPUS_INFO_REGEX = re.compile(
    r'INFO:\s+seed corpus:\s+files:\s+(\d+).*rss:\s+(\d+)Mb.*')
LIBFUZZER_LOG_START_INITED_REGEX = re.compile(
    r'#\d+\s+INITED\s+cov:\s+(\d+)\s+ft:\s+(\d+).*')
LIBFUZZER_MERGE_LOG_EDGE_COVERAGE_REGEX = re.compile(r'#\d+.*cov:\s+(\d+).*')
LIBFUZZER_MERGE_LOG_STATS_REGEX = re.compile(
    r'MERGE.*:\s(\d+)\s+new files with\s+(\d+)\s+new features added.*')
LIBFUZZER_MODULES_LOADED_REGEX = re.compile(
    r'^INFO:\s+Loaded\s+\d+\s+(modules|PC tables)\s+\((\d+)\s+.*\).*')

# Regular expressions to extract different values from the log.
LIBFUZZER_LOG_MAX_LEN_REGEX = re.compile(
    r'.*-max_len is not provided; libFuzzer will not generate inputs larger'
    r' than (\d+) bytes.*')


def calculate_log_lines(log_lines):
  """Calculate number of logs lines of different kind in the given log."""
  # Counters to be returned.
  libfuzzer_lines_count = 0
  other_lines_count = 0
  ignored_lines_count = 0

  lines_after_last_libfuzzer_line_count = 0
  start = False
  found_libfuzzer_crash = False
  for line in log_lines:
    if not start:
      # Skip to start of libFuzzer log output.
      if LIBFUZZER_LOG_START_INITED_REGEX.match(line):
        start = True
      else:
        ignored_lines_count += 1
        continue

    if LIBFUZZER_LOG_IGNORE_REGEX.match(line):
      # We should ignore lines like sanitizer warnings, etc.
      ignored_lines_count += 1
      continue
    elif LIBFUZZER_ANY_CRASH_TYPE_REGEX.match(line):
      # We should ignore whole block if a libfuzzer crash is found.
      # E.g. slow units.
      found_libfuzzer_crash = True
    elif LIBFUZZER_LOG_LINE_REGEX.match(line):
      if found_libfuzzer_crash:
        # Ignore previous block.
        other_lines_count -= lines_after_last_libfuzzer_line_count
        ignored_lines_count += lines_after_last_libfuzzer_line_count

      libfuzzer_lines_count += 1
      lines_after_last_libfuzzer_line_count = 0
      found_libfuzzer_crash = False
    elif LIBFUZZER_LOG_END_REGEX.match(line):
      libfuzzer_lines_count += 1
      break
    else:
      other_lines_count += 1
      lines_after_last_libfuzzer_line_count += 1

  # Ignore the lines after the last libfuzzer line.
  other_lines_count -= lines_after_last_libfuzzer_line_count
  ignored_lines_count += lines_after_last_libfuzzer_line_count

  return other_lines_count, libfuzzer_lines_count, ignored_lines_count


def parse_fuzzing_strategies(log_lines, strategies):
  """Extract stats for fuzzing strategies used."""
  if not strategies:
    # Extract strategies from the log.
    for line in log_lines:
      match = LIBFUZZER_FUZZING_STRATEGIES.match(line)
      if match:
        strategies = match.group(1).split(',')
        break

  stats = {}

  def parse_line_for_strategy_prefix(line, strategy_name):
    """Parse log line to find the value of a strategy with a prefix."""
    strategy_prefix = strategy_name + '_'
    if not line.startswith(strategy_prefix):
      return

    try:
      strategy_value = int(line[len(strategy_prefix):])
      stats['strategy_' + strategy_name] = strategy_value
    except (IndexError, ValueError) as e:
      logs.log_error('Failed to parse strategy "%s":\n%s\n' % (line, str(e)))

  for line in strategies:
    parse_line_for_strategy_prefix(line, strategy.CORPUS_SUBSET_STRATEGY)

  # Other strategies are either ON or OFF, without arbitrary values.
  if strategy.CORPUS_MUTATION_RADAMSA_STRATEGY in strategies:
    stats['strategy_corpus_mutations_radamsa'] = 1
  if strategy.CORPUS_MUTATION_ML_RNN_STRATEGY in strategies:
    stats['strategy_corpus_mutations_ml_rnn'] = 1
  if strategy.RANDOM_MAX_LENGTH_STRATEGY in strategies:
    stats['strategy_random_max_len'] = 1
  if strategy.RECOMMENDED_DICTIONARY_STRATEGY in strategies:
    stats['strategy_recommended_dict'] = 1
  if strategy.VALUE_PROFILE_STRATEGY in strategies:
    stats['strategy_value_profile'] = 1

  return stats


def parse_performance_features(log_lines, strategies, arguments):
  """Extract stats for performance analysis."""
  # Initialize stats with default values.
  stats = {
      'bad_instrumentation': 0,
      'corpus_crash_count': 0,
      'corpus_size': 0,
      'crash_count': 0,
      'dict_used': 0,
      'edge_coverage': 0,
      'edges_total': 0,
      'feature_coverage': 0,
      'initial_edge_coverage': 0,
      'initial_feature_coverage': 0,
      'leak_count': 0,
      'log_lines_unwanted': 0,
      'log_lines_from_engine': 0,
      'log_lines_ignored': 0,
      'max_len': 0,
      'manual_dict_size': 0,
      'merge_edge_coverage': 0,
      'merge_new_files': 0,
      'merge_new_features': 0,
      'oom_count': 0,
      'recommended_dict_size': 0,
      'slow_unit_count': 0,
      'slow_units_count': 0,
      'startup_crash_count': 1,
      'strategy_corpus_mutations_radamsa': 0,
      'strategy_corpus_mutations_ml_rnn': 0,
      'strategy_corpus_subset': 0,
      'strategy_random_max_len': 0,
      'strategy_recommended_dict': 0,
      'strategy_value_profile': 0,
      'timeout_count': 0,
  }

  # Process fuzzing strategies used.
  stats.update(parse_fuzzing_strategies(log_lines, strategies))

  # Corpus rss is only applicable when using the full corpus and not
  # in the corpus subset strategy run.
  if not stats['strategy_corpus_subset']:
    stats['corpus_rss_mb'] = 0

  (stats['log_lines_unwanted'], stats['log_lines_from_engine'],
   stats['log_lines_ignored']) = calculate_log_lines(log_lines)

  # Extract '-max_len' value from arguments, if possible.
  stats['max_len'] = int(
      fuzzer_utils.extract_argument(
          arguments, constants.MAX_LEN_FLAG, remove=False) or stats['max_len'])

  # Extract sizes of manual and recommended dictionary used for fuzzing.
  dictionary_path = fuzzer_utils.extract_argument(
      arguments, constants.DICT_FLAG, remove=False)
  stats['manual_dict_size'], stats['recommended_dict_size'] = (
      dictionary_manager.get_stats_for_dictionary_file(dictionary_path))

  # Different crashes and other flags extracted via regexp match.
  has_corpus = False
  for line in log_lines:
    if LIBFUZZER_BAD_INSTRUMENTATION_REGEX.match(line):
      stats['bad_instrumentation'] = 1
      continue

    if LIBFUZZER_CRASH_TESTCASE_REGEX.match(line):
      stats['crash_count'] = 1
      continue

    if LIBFUZZER_LOG_DICTIONARY_REGEX.match(line):
      stats['dict_used'] = 1
      continue

    if LEAK_TESTCASE_REGEX.match(line):
      stats['leak_count'] = 1
      continue

    if (LIBFUZZER_OOM_TESTCASE_REGEX.match(line) or
        stack_analyzer.OUT_OF_MEMORY_REGEX.match(line)):
      stats['oom_count'] = 1
      continue

    if LIBFUZZER_SLOW_UNIT_TESTCASE_REGEX.match(line):
      # Use |slow_unit_count| to track if this run had any slow units at all.
      # and use |slow_units_count| to track the actual number of slow units in
      # this run (used by performance analyzer).
      stats['slow_unit_count'] = 1
      stats['slow_units_count'] += 1
      continue

    match = LIBFUZZER_LOG_SEED_CORPUS_INFO_REGEX.match(line)
    if match:
      has_corpus = True
      if not stats['strategy_corpus_subset']:
        stats['corpus_rss_mb'] = int(match.group(2))

    match = LIBFUZZER_MODULES_LOADED_REGEX.match(line)
    if match:
      stats['startup_crash_count'] = 0
      stats['edges_total'] = int(match.group(2))

    match = LIBFUZZER_LOG_START_INITED_REGEX.match(line)
    if match:
      stats['initial_edge_coverage'] = int(match.group(1))
      stats['initial_feature_coverage'] = int(match.group(2))
      continue

    # This regexp will match multiple lines and will be overwriting the stats.
    # This is done on purpose, as the last line in the log may have different
    # format, e.g. 'DONE' without a crash and 'NEW' or 'pulse' with a crash.
    match = LIBFUZZER_LOG_COVERAGE_REGEX.match(line)
    if match:
      stats['edge_coverage'] = int(match.group(1))
      stats['feature_coverage'] = int(match.group(2))
      continue

    if (LIBFUZZER_TIMEOUT_TESTCASE_REGEX.match(line) or
        stack_analyzer.LIBFUZZER_TIMEOUT_REGEX.match(line)):
      stats['timeout_count'] = 1
      continue

    if not stats['max_len']:
      # Get "max_len" value from the log, if it has not been found in arguments.
      match = LIBFUZZER_LOG_MAX_LEN_REGEX.match(line)
      if match:
        stats['max_len'] = int(match.group(1))
        continue

  if has_corpus and not stats['log_lines_from_engine']:
    stats['corpus_crash_count'] = 1

  return stats


def parse_stats_from_merge_log(log_lines):
  """Extract stats from a log produced by libFuzzer run with -merge=1."""
  stats = {}
  for line in log_lines:
    match = LIBFUZZER_MERGE_LOG_EDGE_COVERAGE_REGEX.match(line)
    if match:
      stats['merge_edge_coverage'] = int(match.group(1))
      continue

    match = LIBFUZZER_MERGE_LOG_STATS_REGEX.match(line)
    if match:
      stats['merge_new_files'] = int(match.group(1))
      stats['merge_new_features'] = int(match.group(2))

  return stats

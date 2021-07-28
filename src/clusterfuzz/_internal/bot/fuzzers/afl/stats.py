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
"""Statistics for the afl launcher script."""

import os
import re

import six

from clusterfuzz._internal.bot.fuzzers import dictionary_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.fuzzing import strategy
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

SANITIZER_START_REGEX = re.compile(r'.*ERROR: [A-z]+Sanitizer:.*')
SANITIZER_SEPERATOR_REGEX = re.compile(r'^=+$')


class StatsGetter(object):
  """Calculates stats and retreives stats, compiling them into dictionary that
  can be uploaded to ClusterFuzz.
  """

  # Regex for finding stat names and values in fuzzer_stats and
  # extra_fuzzer_stats.
  STATS_REGEX = r'(?P<stat_key>\S+)\s+: (?P<stat_val>\d+[.\d]*).*\n'

  # Mapping from names in AFL's stats file to those of Clusterfuzz's
  AFL_STATS_MAPPING = {
      'exec_timeout': 'timeout_limit',
      'stability': 'stability',
      'unique_crashes': 'crash_count',
      'unique_hangs': 'timeout_count',
  }

  NO_INSTRUMENTATION_REGEX = re.compile(
      r'PROGRAM ABORT :.*No instrumentation detected')
  STARTUP_CRASH_REGEX = re.compile(r'target binary (crashed|terminated)')
  CORPUS_CRASH_REGEX = re.compile(
      r'program crashed with one of the test cases provided')

  def __init__(self, afl_stats_path, dict_path):
    """Set important attributes and initialize all stats to 0.

    Args:
      afl_stats_path: The path to the fuzzer_stats file afl-fuzz outputs.
      Note that we do not use the term "fuzzer_stats" in this parameter and
      associated vairables so that they won't be confused with the module
      "fuzzer_stats".
      dict_path: The path to the dictionary file given to afl-fuzz as input.
    """
    self.afl_stats_path = afl_stats_path

    # The parsed stats in afl_stats_path.
    self.afl_stats = {}
    self.dict_path = dict_path

    # Default values.
    self.stats = {
        'actual_duration': 0,
        'average_exec_per_sec': 0,
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'crash_count': 0,
        'dict_used': 0,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'new_units_added': 0,
        'new_units_generated': 0,
        'stability': 0.0,
        'startup_crash_count': 0,
        'timeout_count': 0,
        'timeout_limit': 0,
    }

  def set_afl_stats(self):
    """Read statistics from afl-fuzz's "fuzzer_stats" file and save them as
    self.afl_stats.
    """
    # fuzzer_stats will not exist if there was a crashing input in the corpus or
    # if afl was unable to fuzz for some other reason.
    if not os.path.exists(self.afl_stats_path):
      return

    afl_stats_string = engine_common.read_data_from_file(
        self.afl_stats_path).decode('utf-8')
    matches_iterator = re.finditer(self.STATS_REGEX, afl_stats_string)
    self.afl_stats = dict(match.groups() for match in matches_iterator)

  def get_afl_stat(self, afl_stat_name):
    """Try to get |afl_stat_name| from self.afl_stats, otherwise return a
    default value instead. Note that is imporant that the types are correct
    since a type change will prevent this data from being loaded into
    BigQuery.

      Args:
        afl_stat_name: The name of the stat from the fuzzer_stats file.

      Returns:
        The int value of |afl_stat| in fuzzer_stats if it is an int, or the
        float value if it is a float. If the value is not in fuzzer_stats, then
        return its default value if one was specified, or zero if none was
        specified.
    """
    # If the stat isn't in afl's stats file, then use the default value
    # specified.
    try:
      afl_stat_value = self.afl_stats[afl_stat_name]
    except KeyError:
      print("{0} not in AFL's stats file.".format(afl_stat_name))
      # If afl_stat_value is in AFL_STATS_MAPPING, then get the clusterfuzz name
      # of the stat to lookup the stat's default value.
      clusterfuzz_stat_name = self.AFL_STATS_MAPPING.get(
          afl_stat_name, afl_stat_name)

      return self.stats.get(clusterfuzz_stat_name, 0)

    # If we find the stat in the file, try returning it as an int. If it is a
    # float, that will fail, so return it as a float.
    try:
      return int(afl_stat_value)
    except ValueError:
      return float(afl_stat_value)

  def _get_unwanted_log_line_count(self, log_output):
    """Return number of unwanted lines in log output."""
    count = 0
    for line in log_output.splitlines():
      if SANITIZER_SEPERATOR_REGEX.match(line):
        continue
      if SANITIZER_START_REGEX.match(line):
        break
      count += 1

    return count

  def set_stats(self,
                actual_duration,
                new_units_generated,
                new_units_added,
                corpus_size,
                fuzzing_strategies,
                fuzzer_stderr,
                afl_fuzz_output=''):
    """Create a dict of statistics that can be uploaded to ClusterFuzz and save
    it in self.stats.

    Args:
      actual_duration: The length of time afl-fuzz was run for, in seconds.
      new_units_generated: The number of new corpus files generated by afl-fuzz.
      new_units_added: The number of new corpus files left after minimizing
      those generated by afl-fuzz.
      fuzzing_strategies: Fuzzing strategies used by AFL.
      afl_fuzz_output: Output from afl-fuzz.

    Returns:
      The stats dictionary. Any values that could not be found default to 0.
    """
    # TODO(metzman): Add expected_duration to stats.
    # TODO(metzman): Add the other stats that are less clear how to add.

    assert actual_duration >= 0
    assert new_units_generated >= 0
    assert new_units_added >= 0
    assert new_units_added <= new_units_generated

    # Set stats passed to this function as arguments.
    self.stats['actual_duration'] = int(actual_duration)
    self.stats['new_units_generated'] = new_units_generated
    self.stats['new_units_added'] = new_units_added
    self.stats['corpus_size'] = corpus_size

    # Set log_lines_unwanted stat from parsing fuzzer stderr.
    self.stats['log_lines_unwanted'] = self._get_unwanted_log_line_count(
        fuzzer_stderr)

    # Set dictionary stats if self.dict_path is set.
    if self.dict_path is not None:
      self.stats['dict_used'] = 1
      self.stats['manual_dict_size'], _ = (
          dictionary_manager.get_stats_for_dictionary_file(self.dict_path))

    # Read and parse stats from AFL's afl_stats. Then use them to set and
    # calculate our own stats.
    self.set_afl_stats()
    for afl_stat, clusterfuzz_stat in six.iteritems(self.AFL_STATS_MAPPING):
      self.stats[clusterfuzz_stat] = self.get_afl_stat(afl_stat)

    try:
      self.stats['average_exec_per_sec'] = int(
          self.get_afl_stat('execs_done') // actual_duration)

    except ZeroDivisionError:  # Fail gracefully if actual_duration is 0.
      self.stats['average_exec_per_sec'] = 0
      logs.log_error('actual_duration is 0 in fuzzer_stats. '
                     'average_exec_per_sec defaulting to 0.')

    # Normalize |timeout_count| and |crash_count| to be either 0 or 1.
    for stat_variable in ['crash_count', 'timeout_count']:
      self.stats[stat_variable] = int(bool(self.stats[stat_variable]))

    self.set_strategy_stats(fuzzing_strategies)
    self.set_output_stats(afl_fuzz_output)
    return self.stats

  def set_output_stats(self, afl_fuzz_output):
    """Set stats gotten from the output of afl-fuzz, |afl_fuzz_output|."""
    # If there is no instrumentation, note it.
    if re.search(self.NO_INSTRUMENTATION_REGEX, afl_fuzz_output):
      self.stats['bad_instrumentation'] = 1

    # If there is a startup crash, note it.
    if re.search(self.STARTUP_CRASH_REGEX, afl_fuzz_output):
      self.stats['startup_crash_count'] = 1

    # If there is a crashing input in corpus, note it.
    if re.search(self.CORPUS_CRASH_REGEX, afl_fuzz_output):
      self.stats['corpus_crash_count'] = 1

  def set_strategy_stats(self, fuzzing_strategies):
    """Sets strategy related stats for afl-fuzz to correct values based on
    |strategies|."""

    self.stats['strategy_selection_method'] = environment.get_value(
        'STRATEGY_SELECTION_METHOD', default_value='default')

    if fuzzing_strategies.use_corpus_subset:
      self.stats['strategy_' + strategy.CORPUS_SUBSET_STRATEGY.name] = (
          fuzzing_strategies.corpus_subset_size)

    if (fuzzing_strategies.generator_strategy == engine_common.Generator.RADAMSA
       ):
      self.stats['strategy_' +
                 strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name] = 1
    elif (fuzzing_strategies.generator_strategy ==
          engine_common.Generator.ML_RNN):
      self.stats['strategy_' +
                 strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name] = 1

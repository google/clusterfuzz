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
"""libFuzzer launcher."""
from __future__ import print_function
# pylint: disable=g-statement-before-imports
try:
  # ClusterFuzz dependencies.
  from python.base import modules
  modules.fix_module_search_paths()
except ImportError:
  pass

import collections
import multiprocessing
import os
import random
import re
import shutil
import string

from base import utils
from bot.fuzzers import dictionary_manager
from bot.fuzzers import engine_common
from bot.fuzzers import mutator_plugin
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.libFuzzer import constants
from datastore import data_types
from fuzzing import strategy
from metrics import logs
from system import environment
from system import shell

# Maximum length of a random chosen length for `-max_len`.
MAX_VALUE_FOR_MAX_LENGTH = 10000

# Probability of doing DFT-based fuzzing (depends on DFSan build presence).
DATAFLOW_TRACING_PROBABILITY = 0.25

# Prefix for the fuzzer's full name.
LIBFUZZER_PREFIX = 'libfuzzer_'

# Allow 30 minutes to merge the testcases back into the corpus.
DEFAULT_MERGE_TIMEOUT = 30 * 60

MERGED_DICT_SUFFIX = '.merged'

MERGE_DIRECTORY_NAME = 'merge-corpus'

HEXDIGITS_SET = set(string.hexdigits)

StrategyInfo = collections.namedtuple('StrategiesInfo', [
    'fuzzing_strategies',
    'arguments',
    'additional_corpus_dirs',
    'extra_env',
    'use_dataflow_tracing',
    'is_mutations_run',
])


def add_recommended_dictionary(arguments, fuzzer_name, fuzzer_path):
  """Add recommended dictionary from GCS to existing .dict file or create
  a new one and update the arguments as needed.
  This function modifies |arguments| list in some cases."""
  recommended_dictionary_path = os.path.join(
      fuzzer_utils.get_temp_dir(),
      dictionary_manager.RECOMMENDED_DICTIONARY_FILENAME)

  dict_manager = dictionary_manager.DictionaryManager(fuzzer_name)

  try:
    # Bail out if cannot download recommended dictionary from GCS.
    if not dict_manager.download_recommended_dictionary_from_gcs(
        recommended_dictionary_path):
      return False
  except Exception as ex:
    logs.log_error(
        'Exception downloading recommended dictionary:\n%s.' % str(ex))
    return False

  # Bail out if the downloaded dictionary is empty.
  if not os.path.getsize(recommended_dictionary_path):
    return False

  # Check if there is an existing dictionary file in arguments.
  original_dictionary_path = fuzzer_utils.extract_argument(
      arguments, constants.DICT_FLAG)
  merged_dictionary_path = (
      original_dictionary_path or
      dictionary_manager.get_default_dictionary_path(fuzzer_path))
  merged_dictionary_path += MERGED_DICT_SUFFIX

  dictionary_manager.merge_dictionary_files(original_dictionary_path,
                                            recommended_dictionary_path,
                                            merged_dictionary_path)
  arguments.append(constants.DICT_FLAG + merged_dictionary_path)
  return True


def get_dictionary_analysis_timeout():
  """Get timeout for dictionary analysis."""
  return engine_common.get_overridable_timeout(5 * 60,
                                               'DICTIONARY_TIMEOUT_OVERRIDE')


def analyze_and_update_recommended_dictionary(runner, fuzzer_name, log_lines,
                                              corpus_directory, arguments):
  """Extract and analyze recommended dictionary from fuzzer output, then update
  the corresponding dictionary stored in GCS if needed."""
  logs.log(
      'Extracting and analyzing recommended dictionary for %s.' % fuzzer_name)

  # Extract recommended dictionary elements from the log.
  dict_manager = dictionary_manager.DictionaryManager(fuzzer_name)
  recommended_dictionary = (
      dict_manager.parse_recommended_dictionary_from_log_lines(log_lines))
  if not recommended_dictionary:
    logs.log('No recommended dictionary in output from %s.' % fuzzer_name)
    return None

  # Write recommended dictionary into a file and run '-analyze_dict=1'.
  temp_dictionary_filename = (
      fuzzer_name + dictionary_manager.DICTIONARY_FILE_EXTENSION + '.tmp')
  temp_dictionary_path = os.path.join(fuzzer_utils.get_temp_dir(),
                                      temp_dictionary_filename)

  with open(temp_dictionary_path, 'wb') as file_handle:
    file_handle.write('\n'.join(recommended_dictionary))

  dictionary_analysis = runner.analyze_dictionary(
      temp_dictionary_path,
      corpus_directory,
      analyze_timeout=get_dictionary_analysis_timeout(),
      additional_args=arguments)

  if dictionary_analysis.timed_out:
    logs.log_warn(
        'Recommended dictionary analysis for %s timed out.' % fuzzer_name)
    return None

  if dictionary_analysis.return_code != 0:
    logs.log_warn('Recommended dictionary analysis for %s failed: %d.' %
                  (fuzzer_name, dictionary_analysis.return_code))
    return None

  # Extract dictionary elements considered useless, calculate the result.
  useless_dictionary = dict_manager.parse_useless_dictionary_from_data(
      dictionary_analysis.output)

  logs.log('%d out of %d recommended dictionary elements for %s are useless.' %
           (len(useless_dictionary), len(recommended_dictionary), fuzzer_name))

  recommended_dictionary = set(recommended_dictionary) - set(useless_dictionary)
  if not recommended_dictionary:
    return None

  new_elements_added = dict_manager.update_recommended_dictionary(
      recommended_dictionary)
  logs.log('Added %d new elements to the recommended dictionary for %s.' %
           (new_elements_added, fuzzer_name))

  return recommended_dictionary


def create_corpus_directory(name):
  """Create a corpus directory with a give name in temp directory and return its
  full path."""
  new_corpus_directory = os.path.join(fuzzer_utils.get_temp_dir(), name)
  engine_common.recreate_directory(new_corpus_directory)
  return new_corpus_directory


def copy_from_corpus(dest_corpus_path, src_corpus_path, num_testcases):
  """Choose |num_testcases| testcases from the src corpus directory (and its
  subdirectories) and copy it into the dest directory."""
  src_corpus_files = []
  for root, _, files in os.walk(src_corpus_path):
    for f in files:
      src_corpus_files.append(os.path.join(root, f))

  # There is no reason to preserve structure of src_corpus_path directory.
  for i, to_copy in enumerate(random.sample(src_corpus_files, num_testcases)):
    shutil.copy(os.path.join(to_copy), os.path.join(dest_corpus_path, str(i)))


def remove_fuzzing_arguments(arguments):
  """Remove arguments used during fuzzing."""
  for argument in [
      constants.DICT_FLAG,  # User for fuzzing only.
      constants.MAX_LEN_FLAG,  # This may shrink the testcases.
      constants.RUNS_FLAG,  # Make sure we don't have any '-runs' argument.
      constants.FORK_FLAG,  # It overrides `-merge` argument.
      constants.COLLECT_DATA_FLOW_FLAG,  # Used for fuzzing only.
  ]:
    fuzzer_utils.extract_argument(arguments, argument)


def parse_log_stats(log_lines):
  """Parse libFuzzer log output."""
  log_stats = {}

  # Parse libFuzzer generated stats (`-print_final_stats=1`).
  stats_regex = re.compile(r'stat::([A-Za-z_]+):\s*([^\s]+)')
  for line in log_lines:
    match = stats_regex.match(line)
    if not match:
      continue

    value = match.group(2)
    if not value.isdigit():
      # We do not expect any non-numeric stats from libFuzzer, skip those.
      logs.log_error('Corrupted stats reported by libFuzzer: "%s".' % line)
      continue

    value = int(value)

    log_stats[match.group(1)] = value

  if log_stats.get('new_units_added') is not None:
    # 'new_units_added' value will be overwritten after corpus merge step, but
    # the initial number of units generated is an interesting data as well.
    log_stats['new_units_generated'] = log_stats['new_units_added']

  return log_stats


def set_sanitizer_options(fuzzer_path):
  """Sets sanitizer options based on .options file overrides and what this
  script requires."""
  engine_common.process_sanitizer_options_overrides(fuzzer_path)
  sanitizer_options_var = environment.get_current_memory_tool_var()
  sanitizer_options = environment.get_memory_tool_options(
      sanitizer_options_var, {})
  sanitizer_options['exitcode'] = constants.TARGET_ERROR_EXITCODE
  environment.set_memory_tool_options(sanitizer_options_var, sanitizer_options)


def get_fuzz_timeout(is_mutations_run, total_timeout=None):
  """Get the fuzz timeout."""
  fuzz_timeout = (
      engine_common.get_hard_timeout(total_timeout=total_timeout) -
      engine_common.get_merge_timeout(DEFAULT_MERGE_TIMEOUT) -
      get_dictionary_analysis_timeout())

  if is_mutations_run:
    fuzz_timeout -= engine_common.get_new_testcase_mutations_timeout()

  return fuzz_timeout


def use_mutator_plugin(target_name, extra_env):
  """Decide whether to use a mutator plugin. If yes and there is a usable plugin
  available for |target_name|, then add it to LD_PRELOAD in |extra_env|, and
  return True."""

  # TODO(metzman): Support Windows.
  if environment.platform() == 'WINDOWS':
    return False

  mutator_plugin_path = mutator_plugin.get_mutator_plugin(target_name)
  if not mutator_plugin_path:
    return False

  logs.log('Using mutator plugin: %s' % mutator_plugin_path)
  # TODO(metzman): Change the strategy to record which plugin was used, and
  # not simply that a plugin was used.
  extra_env['LD_PRELOAD'] = mutator_plugin_path
  return True


def is_sha1_hash(possible_hash):
  """Returns True if |possible_hash| looks like a valid sha1 hash."""
  if len(possible_hash) != 40:
    return False

  return all(char in HEXDIGITS_SET for char in possible_hash)


def move_mergeable_units(merge_directory, corpus_directory):
  """Move new units in |merge_directory| into |corpus_directory|."""
  initial_units = set(
      os.path.basename(filename)
      for filename in shell.get_files_list(corpus_directory))

  for unit_path in shell.get_files_list(merge_directory):
    unit_name = os.path.basename(unit_path)
    if unit_name in initial_units and is_sha1_hash(unit_name):
      continue
    dest_path = os.path.join(corpus_directory, unit_name)
    shell.move(unit_path, dest_path)


def pick_strategies(strategy_pool, fuzzer_path, corpus_directory,
                    existing_arguments):
  """Pick strategies."""
  build_directory = environment.get_value('BUILD_DIR')
  target_name = os.path.basename(fuzzer_path)
  project_qualified_fuzzer_name = data_types.fuzz_target_project_qualified_name(
      utils.current_project(), target_name)

  fuzzing_strategies = []
  arguments = []
  additional_corpus_dirs = []

  # Select a generator to attempt to use for existing testcase mutations.
  candidate_generator = engine_common.select_generator(strategy_pool,
                                                       fuzzer_path)
  is_mutations_run = candidate_generator != engine_common.Generator.NONE

  # Depends on the presense of DFSan instrumented build.
  dataflow_build_dir = environment.get_value('DATAFLOW_BUILD_DIR')
  use_dataflow_tracing = (
      dataflow_build_dir and
      strategy_pool.do_strategy(strategy.DATAFLOW_TRACING_STRATEGY))
  if use_dataflow_tracing:
    dataflow_binary_path = os.path.join(
        dataflow_build_dir, os.path.relpath(fuzzer_path, build_directory))
    if os.path.exists(dataflow_binary_path):
      arguments.append(
          '%s%s' % (constants.COLLECT_DATA_FLOW_FLAG, dataflow_binary_path))
      fuzzing_strategies.append(strategy.DATAFLOW_TRACING_STRATEGY.name)
    else:
      logs.log_error(
          'Fuzz target is not found in dataflow build, skiping strategy.')
      use_dataflow_tracing = False

  # Generate new testcase mutations using radamsa, etc.
  if is_mutations_run:
    new_testcase_mutations_directory = create_corpus_directory('mutations')
    generator_used = engine_common.generate_new_testcase_mutations(
        corpus_directory, new_testcase_mutations_directory,
        project_qualified_fuzzer_name, candidate_generator)

    # Add the used generator strategy to our fuzzing strategies list.
    if generator_used:
      if candidate_generator == engine_common.Generator.RADAMSA:
        fuzzing_strategies.append(
            strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name)
      elif candidate_generator == engine_common.Generator.ML_RNN:
        fuzzing_strategies.append(strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name)

    additional_corpus_dirs.append(new_testcase_mutations_directory)

  if strategy_pool.do_strategy(strategy.RANDOM_MAX_LENGTH_STRATEGY):
    max_len_argument = fuzzer_utils.extract_argument(
        existing_arguments, constants.MAX_LEN_FLAG, remove=False)
    if not max_len_argument:
      max_length = random.SystemRandom().randint(1, MAX_VALUE_FOR_MAX_LENGTH)
      arguments.append('%s%d' % (constants.MAX_LEN_FLAG, max_length))
      fuzzing_strategies.append(strategy.RANDOM_MAX_LENGTH_STRATEGY.name)

  if (strategy_pool.do_strategy(strategy.RECOMMENDED_DICTIONARY_STRATEGY) and
      add_recommended_dictionary(arguments, project_qualified_fuzzer_name,
                                 fuzzer_path)):
    fuzzing_strategies.append(strategy.RECOMMENDED_DICTIONARY_STRATEGY.name)

  if strategy_pool.do_strategy(strategy.VALUE_PROFILE_STRATEGY):
    arguments.append(constants.VALUE_PROFILE_ARGUMENT)
    fuzzing_strategies.append(strategy.VALUE_PROFILE_STRATEGY.name)

  # DataFlow Tracing requires fork mode, always use it with DFT strategy.
  if use_dataflow_tracing or strategy_pool.do_strategy(strategy.FORK_STRATEGY):
    max_fuzz_threads = environment.get_value('MAX_FUZZ_THREADS', 1)
    num_fuzz_processes = max(1, multiprocessing.cpu_count() // max_fuzz_threads)
    arguments.append('%s%d' % (constants.FORK_FLAG, num_fuzz_processes))
    fuzzing_strategies.append(
        '%s_%d' % (strategy.FORK_STRATEGY.name, num_fuzz_processes))

  extra_env = {}
  if (strategy_pool.do_strategy(strategy.MUTATOR_PLUGIN_STRATEGY) and
      use_mutator_plugin(target_name, extra_env)):
    fuzzing_strategies.append(strategy.MUTATOR_PLUGIN_STRATEGY.name)

  return StrategyInfo(fuzzing_strategies, arguments, additional_corpus_dirs,
                      extra_env, use_dataflow_tracing, is_mutations_run)

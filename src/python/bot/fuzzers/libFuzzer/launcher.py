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

import atexit
import os
import random
import re
import shutil
import signal
import stat
import sys
import time

import constants
import stats

from base import utils
from bot.fuzzers import dictionary_manager
from bot.fuzzers import engine_common
from bot.fuzzers import libfuzzer
from bot.fuzzers import strategy
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.ml.rnn import generator as ml_rnn_generator
from datastore import data_types
from metrics import logs
from system import environment
from system import minijail
from system import new_process
from system import shell

# Regex to find testcase path from a crash.
CRASH_TESTCASE_REGEX = (r'.*Test unit written to\s*'
                        r'(.*(crash|oom|timeout|leak)-.*)')

# Probability of using `-max_len` option. Not applicable if already declared in
# .options file.
RANDOM_MAX_LENGTH_PROBABILITY = 0.10

# Maximum length of a random chosen length for `-max_len`.
MAX_VALUE_FOR_MAX_LENGTH = 10000

# Probability of doing ML RNN mutations on the corpus in this run.
CORPUS_MUTATION_ML_RNN_PROBABILITY = 0.50

# Probability of doing radamsa mutations on the corpus in this run.
CORPUS_MUTATION_RADAMSA_PROBABILITY = 0.05

# Number of radamsa mutations.
RADAMSA_MUTATIONS = 2000

# Maximum number of seconds to run radamsa for.
RADAMSA_TIMEOUT = 3

# Probability of recommended dictionary usage.
RECOMMENDED_DICTIONARY_PROBABILITY = 0.10

# Probability of using `-use_value_profile=1` option.
VALUE_PROFILE_PROBABILITY = 0.33

# Testcase minimization arguments being used by ClusterFuzz.
MINIMIZE_TO_ARGUMENT = '--cf-minimize-to='
MINIMIZE_TIMEOUT_ARGUMENT = '--cf-minimize-timeout='

# Cleanse arguments being used by ClusterFuzz.
CLEANSE_TO_ARGUMENT = '--cf-cleanse-to='
CLEANSE_TIMEOUT_ARGUMENT = '--cf-cleanse-timeout='

# Prefix for the fuzzer's full name.
LIBFUZZER_PREFIX = 'libfuzzer_'

# Allow 30 minutes to merge the testcases back into the corpus.
DEFAULT_MERGE_TIMEOUT = 30 * 60

IS_WIN = environment.platform() == 'WINDOWS'

MERGED_DICT_SUFFIX = '.merged'

ENGINE_ERROR_MESSAGE = 'libFuzzer: engine encountered an error.'


class Generator(object):
  """Generators we can use."""
  NONE = 0
  RADAMSA = 1
  ML_RNN = 2


def _select_generator():
  """Pick a generator to generate new testcases before fuzzing or return
  Generator.NONE if no generator selected."""
  # We can't use radamsa binary on Windows. Disable ML for now until we know it
  # works.
  if IS_WIN:
    return Generator.NONE
  elif do_ml_rnn_generator():
    return Generator.ML_RNN
  elif do_radamsa_generator():
    return Generator.RADAMSA

  return Generator.NONE


def do_random_max_length():
  """Return whether or not to do value profile."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.RANDOM_MAX_LENGTH_STRATEGY,
          default=RANDOM_MAX_LENGTH_PROBABILITY))


def do_radamsa_generator():
  """Return whether or not to do radamsa mutations."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.CORPUS_MUTATION_RADAMSA_STRATEGY,
          default=CORPUS_MUTATION_RADAMSA_PROBABILITY))


def do_ml_rnn_generator():
  """Return whether or not to do additional mutations."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.CORPUS_MUTATION_ML_RNN_STRATEGY,
          default=CORPUS_MUTATION_ML_RNN_PROBABILITY))


def do_recommended_dictionary():
  """Retrn whether or not to use the recommended dictionary."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.RECOMMENDED_DICTIONARY_STRATEGY,
          default=RECOMMENDED_DICTIONARY_PROBABILITY))


def do_value_profile():
  """Return whether or not to do value profile."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.VALUE_PROFILE_STRATEGY, default=VALUE_PROFILE_PROBABILITY))


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


def get_new_testcase_mutations_timeout():
  """Get the timeout for new testcase mutations."""
  return engine_common.get_overridable_timeout(10 * 60,
                                               'MUTATIONS_TIMEOUT_OVERRIDE')


def add_custom_crash_state_if_needed(fuzzer_name, output_lines, parsed_stats):
  """Insert a custom crash state into the output lines if needed."""
  if not parsed_stats['oom_count'] and not parsed_stats['timeout_count']:
    return

  summary_index = None

  for index, line in enumerate(output_lines):
    if 'SUMMARY:' in line or 'DEATH:' in line:
      summary_index = index
      break

  if summary_index is not None:
    output_lines.insert(summary_index, 'custom-crash-state: ' + fuzzer_name)


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

  with open(temp_dictionary_path, 'w') as file_handle:
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


def bind_corpus_dirs(chroot, corpus_directories):
  """Bind corpus directories to the minijail chroot.

  Also makes sure that the directories are world writeable.

  Args:
    chroot: The MinijailChroot.
    corpus_directories: A list of corpus paths.
  """
  for corpus_directory in corpus_directories:
    target_dir = '/' + os.path.basename(corpus_directory)
    chroot.add_binding(
        minijail.ChrootBinding(corpus_directory, target_dir, True))


def unbind_corpus_dirs(chroot, corpus_directories):
  """Unbind corpus directories from the minijail chroot.

  Args:
    chroot: The MinijailChroot.
    corpus_directories: A list of corpus paths.
  """
  for corpus_directory in corpus_directories:
    target_dir = '/' + os.path.basename(corpus_directory)
    chroot.remove_binding(
        minijail.ChrootBinding(corpus_directory, target_dir, True))


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


def generate_new_testcase_mutations(corpus_directory, fuzzer_name, generator,
                                    fuzzing_strategies):
  """Generate new testcase mutations, using existing corpus directory or other
  methods."""
  generation_timeout = get_new_testcase_mutations_timeout()
  new_testcase_mutations_directory = create_corpus_directory('mutations')

  # Generate new testcase mutations using Radamsa.
  if generator == Generator.RADAMSA:
    expected_completion_time = time.time() + generation_timeout
    generate_new_testcase_mutations_using_radamsa(
        corpus_directory, new_testcase_mutations_directory,
        expected_completion_time)

    # If new mutations are successfully generated, add radamsa stragegy.
    if shell.get_directory_file_count(new_testcase_mutations_directory):
      fuzzing_strategies.append(strategy.CORPUS_MUTATION_RADAMSA_STRATEGY)

  # Generate new testcase mutations using ML RNN model.
  elif generator == Generator.ML_RNN:
    generate_new_testcase_mutations_using_ml_rnn(
        corpus_directory, new_testcase_mutations_directory, fuzzer_name,
        generation_timeout)

    # If new mutations are successfully generated, add ml rnn stragegy.
    if shell.get_directory_file_count(new_testcase_mutations_directory):
      fuzzing_strategies.append(strategy.CORPUS_MUTATION_ML_RNN_STRATEGY)

  return new_testcase_mutations_directory


def get_corpus_directories(main_corpus_directory,
                           fuzzer_path,
                           fuzzing_strategies,
                           minijail_chroot=None):
  """Return a list of corpus directories to be passed to the fuzzer binary."""
  corpus_directories = []

  # Set up scratch directory for writing new units.
  new_testcases_directory = create_corpus_directory('new')

  corpus_directories.append(new_testcases_directory)

  # Check for seed corpus and add it into corpus directory.
  engine_common.unpack_seed_corpus_if_needed(fuzzer_path, main_corpus_directory)

  # Pick a few testcases from our corpus to use as the initial corpus.
  subset_size = engine_common.random_choice(
      engine_common.CORPUS_SUBSET_NUM_TESTCASES)

  if (engine_common.do_corpus_subset() and
      shell.get_directory_file_count(main_corpus_directory) > subset_size):
    # Copy |subset_size| testcases into 'subset' directory.
    corpus_subset_directory = create_corpus_directory('subset')
    copy_from_corpus(corpus_subset_directory, main_corpus_directory,
                     subset_size)
    corpus_directories.append(corpus_subset_directory)
    fuzzing_strategies.append(strategy.CORPUS_SUBSET_STRATEGY + '_' +
                              str(subset_size))
    if minijail_chroot:
      bind_corpus_dirs(minijail_chroot, [main_corpus_directory])
  else:
    # Regular fuzzing with the full main corpus directory.
    corpus_directories.append(main_corpus_directory)

  if minijail_chroot:
    bind_corpus_dirs(minijail_chroot, corpus_directories)

  return corpus_directories


def generate_new_testcase_mutations_using_radamsa(
    corpus_directory, new_testcase_mutations_directory,
    expected_completion_time):
  """Generate new testcase mutations based on Radamsa."""
  radamsa_path = get_radamsa_path()
  if not radamsa_path:
    # Mutations using radamsa are not supported on current platform, bail out.
    return

  radamsa_runner = new_process.ProcessRunner(radamsa_path)
  files_list = shell.get_files_list(corpus_directory)
  if not files_list:
    # No mutations to do on an empty corpus, bail out.
    return

  old_corpus_size = shell.get_directory_file_count(
      new_testcase_mutations_directory)

  for i in range(RADAMSA_MUTATIONS):
    original_file_path = engine_common.random_choice(files_list)
    original_filename = os.path.basename(original_file_path)
    output_path = os.path.join(new_testcase_mutations_directory,
                               'radamsa-%08d-%s' % (i + 1, original_filename))

    result = radamsa_runner.run_and_wait(
        ['-o', output_path, original_file_path], timeout=RADAMSA_TIMEOUT)
    if result.return_code or result.timed_out:
      logs.log_error(
          'Radamsa failed to mutate or timed out.', output=result.output)

    # Check if we exceeded our timeout. If yes, do no more mutations and break.
    if time.time() > expected_completion_time:
      break

  new_corpus_size = shell.get_directory_file_count(
      new_testcase_mutations_directory)
  logs.log('Added %d tests using Radamsa mutations.' %
           (new_corpus_size - old_corpus_size))


def generate_new_testcase_mutations_using_ml_rnn(
    corpus_directory, new_testcase_mutations_directory, fuzzer_name,
    generation_timeout):
  """Generate new testcase mutations using ML RNN model."""
  # No return value for now. Will add later if this is necessary.
  ml_rnn_generator.execute(corpus_directory, new_testcase_mutations_directory,
                           fuzzer_name, generation_timeout)


def get_radamsa_path():
  """Return path to radamsa binary for current platform."""
  bin_directory_path = os.path.join(
      os.path.dirname(os.path.realpath(__file__)), 'bin')
  platform = environment.platform()
  if platform == 'LINUX':
    return os.path.join(bin_directory_path, 'linux', 'radamsa')

  if platform == 'MAC':
    return os.path.join(bin_directory_path, 'mac', 'radamsa')

  return None


def remove_fuzzing_arguments(arguments):
  """Remove arguments used during fuzzing."""
  # Remove un-needed dictionary argument.
  fuzzer_utils.extract_argument(arguments, constants.DICT_FLAG)

  # 'max_len' option may shrink the testcase if its size greater than 'max_len'.
  fuzzer_utils.extract_argument(arguments, constants.MAX_LEN_FLAG)

  # Remove custom '-runs' argument.
  fuzzer_utils.extract_argument(arguments, constants.RUNS_FLAG)


def load_testcase_if_exists(fuzzer_runner,
                            testcase_file_path,
                            fuzzer_name,
                            use_minijail=False,
                            additional_args=None):
  """Loads a crash testcase if it exists."""
  # To ensure that we can run the fuzzer.
  os.chmod(fuzzer_runner.executable_path, stat.S_IRWXU | stat.S_IRGRP
           | stat.S_IXGRP)

  arguments = additional_args[:]

  remove_fuzzing_arguments(arguments)

  # Add retries for reliability.
  arguments.append('%s%d' % (constants.RUNS_FLAG, constants.RUNS_TO_REPRODUCE))

  result = fuzzer_runner.run_single_testcase(
      testcase_file_path, additional_args=arguments)

  print('Running command:', get_printable_command(
      result.command, fuzzer_runner.executable_path, use_minijail))
  output_lines = result.output.splitlines()

  # Parse performance features to extract custom crash flags.
  parsed_stats = stats.parse_performance_features(output_lines, [], [])
  add_custom_crash_state_if_needed(fuzzer_name, output_lines, parsed_stats)
  print('\n'.join(output_lines))


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


def expand_with_common_arguments(arguments):
  """Return list of arguments expanded by necessary common options."""
  # We prefer to add common arguments (either default or custom) in run.py, but
  # in order to maintain compatibility with previously found testcases, we do
  # add necessary common arguments here as well.
  common_arguments = []

  if not fuzzer_utils.extract_argument(
      arguments, constants.RSS_LIMIT_FLAG, remove=False):
    common_arguments.append(
        '%s%d' % (constants.RSS_LIMIT_FLAG, constants.DEFAULT_RSS_LIMIT_MB))

  if not fuzzer_utils.extract_argument(
      arguments, constants.TIMEOUT_FLAG, remove=False):
    common_arguments.append(
        '%s%d' % (constants.TIMEOUT_FLAG, constants.DEFAULT_TIMEOUT_LIMIT))

  return arguments + common_arguments


def get_fuzz_timeout(is_mutations_run):
  """Get the fuzz timeout."""
  fuzz_timeout = (
      engine_common.get_hard_timeout() -
      engine_common.get_merge_timeout(DEFAULT_MERGE_TIMEOUT) -
      get_dictionary_analysis_timeout())

  if is_mutations_run:
    fuzz_timeout -= get_new_testcase_mutations_timeout()

  return fuzz_timeout


def minimize_testcase(runner, testcase_file_path, minimize_to, minimize_timeout,
                      arguments, use_minijail):
  """Minimize testcase."""
  remove_fuzzing_arguments(arguments)

  # Write in-progress minimization testcases to temp dir.
  if use_minijail:
    arguments.append(constants.TMP_ARTIFACT_PREFIX_ARGUMENT)
  else:
    minimize_temp_dir = os.path.join(fuzzer_utils.get_temp_dir(),
                                     'minimize_temp')

    engine_common.recreate_directory(minimize_temp_dir)
    arguments.append(
        '%s%s/' % (constants.ARTIFACT_PREFIX_FLAG, minimize_temp_dir))

  # Call the fuzzer to minimize.
  result = runner.minimize_crash(
      testcase_file_path,
      minimize_to,
      minimize_timeout,
      additional_args=arguments)

  print('Running command:', get_printable_command(
      result.command, runner.executable_path, use_minijail))
  print(result.output)


def cleanse_testcase(runner, testcase_file_path, cleanse_to, cleanse_timeout,
                     arguments, use_minijail):
  """Cleanse testcase."""
  remove_fuzzing_arguments(arguments)

  # Write in-progress cleanse testcases to temp dir.
  if use_minijail:
    arguments.append(constants.TMP_ARTIFACT_PREFIX_ARGUMENT)
  else:
    cleanse_temp_dir = os.path.join(fuzzer_utils.get_temp_dir(), 'cleanse_temp')
    engine_common.recreate_directory(cleanse_temp_dir)
    arguments.append(
        '%s%s/' % (constants.ARTIFACT_PREFIX_FLAG, cleanse_temp_dir))

  # Call the fuzzer to cleanse.
  result = runner.cleanse_crash(
      testcase_file_path,
      cleanse_to,
      cleanse_timeout,
      additional_args=arguments)

  print('Running command:', get_printable_command(
      result.command, runner.executable_path, use_minijail))
  print(result.output)


def get_printable_command(command, fuzzer_path, use_minijail):
  """Return a printable version of the command."""
  if use_minijail:
    command = engine_common.strip_minijail_command(command, fuzzer_path)

  return engine_common.get_command_quoted(command)


def main(argv):
  """Run libFuzzer as specified by argv."""
  atexit.register(fuzzer_utils.cleanup)

  # Initialize variables.
  arguments = argv[1:]
  testcase_file_path = arguments.pop(0)
  target_name = arguments.pop(0)
  fuzzer_name = data_types.fuzz_target_project_qualified_name(
      utils.current_project(), target_name)

  # Initialize log handler.
  logs.configure(
      'run_fuzzer', {
          'fuzzer': fuzzer_name,
          'engine': 'libFuzzer',
          'job_name': environment.get_value('JOB_NAME')
      })

  # Make sure that the fuzzer binary exists.
  build_directory = environment.get_value('BUILD_DIR')
  fuzzer_path = engine_common.find_fuzzer_path(build_directory, target_name)
  if not fuzzer_path:
    # This is an expected case when doing regression testing with old builds
    # that do not have that fuzz target. It can also happen when a host sends a
    # message to an untrusted worker that just restarted and lost information on
    # build directory.
    logs.log_warn('Could not find fuzz target %s.' % target_name)
    return

  # Install signal handler.
  signal.signal(signal.SIGTERM, engine_common.signal_term_handler)

  # Set up temp dir.
  engine_common.recreate_directory(fuzzer_utils.get_temp_dir())

  # Setup minijail if needed.
  use_minijail = environment.get_value('USE_MINIJAIL')
  runner = libfuzzer.get_runner(
      fuzzer_path, temp_dir=fuzzer_utils.get_temp_dir())

  if use_minijail:
    minijail_chroot = runner.chroot
  else:
    minijail_chroot = None

  # Get corpus directory.
  corpus_directory = environment.get_value('FUZZ_CORPUS_DIR')

  # Add common arguments which are necessary to be used for every run.
  arguments = expand_with_common_arguments(arguments)

  # Add sanitizer options to environment that were specified in the .options
  # file and options that this script requires.
  set_sanitizer_options(fuzzer_path)

  # Minimize test argument.
  minimize_to = fuzzer_utils.extract_argument(arguments, MINIMIZE_TO_ARGUMENT)
  minimize_timeout = fuzzer_utils.extract_argument(arguments,
                                                   MINIMIZE_TIMEOUT_ARGUMENT)

  if minimize_to and minimize_timeout:
    minimize_testcase(runner, testcase_file_path, minimize_to,
                      int(minimize_timeout), arguments, use_minijail)
    return

  # Cleanse argument.
  cleanse_to = fuzzer_utils.extract_argument(arguments, CLEANSE_TO_ARGUMENT)
  cleanse_timeout = fuzzer_utils.extract_argument(arguments,
                                                  CLEANSE_TIMEOUT_ARGUMENT)

  if cleanse_to and cleanse_timeout:
    cleanse_testcase(runner, testcase_file_path, cleanse_to,
                     int(cleanse_timeout), arguments, use_minijail)
    return

  # If we don't have a corpus, then that means this is not a fuzzing run.
  if not corpus_directory:
    load_testcase_if_exists(runner, testcase_file_path, fuzzer_name,
                            use_minijail, arguments)
    return

  # We don't have a crash testcase, fuzz.

  # Check dict argument to make sure that it's valid.
  dict_argument = fuzzer_utils.extract_argument(
      arguments, constants.DICT_FLAG, remove=False)
  if dict_argument and not os.path.exists(dict_argument):
    logs.log_error('Invalid dict %s for %s.' % (dict_argument, fuzzer_name))
    fuzzer_utils.extract_argument(arguments, constants.DICT_FLAG)

  # If there's no dict argument, check for %target_binary_name%.dict file.
  if (not fuzzer_utils.extract_argument(
      arguments, constants.DICT_FLAG, remove=False)):
    default_dict_path = dictionary_manager.get_default_dictionary_path(
        fuzzer_path)
    if os.path.exists(default_dict_path):
      arguments.append(constants.DICT_FLAG + default_dict_path)

  fuzzing_strategies = []

  # Select a generator to use for existing testcase mutations.
  generator = _select_generator()
  is_mutations_run = generator != Generator.NONE

  # Timeout for fuzzer run.
  fuzz_timeout = get_fuzz_timeout(is_mutations_run)

  # Get list of corpus directories.
  corpus_directories = get_corpus_directories(
      corpus_directory, fuzzer_path, fuzzing_strategies, minijail_chroot)

  # Bind corpus directories in minijail.
  if use_minijail:
    artifact_prefix = constants.ARTIFACT_PREFIX_FLAG + '/'
  else:
    artifact_prefix = '%s%s/' % (constants.ARTIFACT_PREFIX_FLAG,
                                 os.path.abspath(
                                     os.path.dirname(testcase_file_path)))

  # Generate new testcase mutations using radamsa, etc.
  if is_mutations_run:
    new_testcase_mutations_directory = generate_new_testcase_mutations(
        corpus_directory, fuzzer_name, generator, fuzzing_strategies)
    corpus_directories.append(new_testcase_mutations_directory)
    if use_minijail:
      bind_corpus_dirs(minijail_chroot, [new_testcase_mutations_directory])

  max_len_argument = fuzzer_utils.extract_argument(
      arguments, constants.MAX_LEN_FLAG, remove=False)
  if not max_len_argument and do_random_max_length():
    max_length = random.SystemRandom().randint(1, MAX_VALUE_FOR_MAX_LENGTH)
    arguments.append('%s%d' % (constants.MAX_LEN_FLAG, max_length))
    fuzzing_strategies.append(strategy.RANDOM_MAX_LENGTH_STRATEGY)

  if do_recommended_dictionary():
    if add_recommended_dictionary(arguments, fuzzer_name, fuzzer_path):
      fuzzing_strategies.append(strategy.RECOMMENDED_DICTIONARY_STRATEGY)

  if do_value_profile():
    arguments.append(constants.VALUE_PROFILE_ARGUMENT)
    fuzzing_strategies.append(strategy.VALUE_PROFILE_STRATEGY)

  # Execute the fuzzer binary with original arguments.
  fuzz_result = runner.fuzz(
      corpus_directories,
      fuzz_timeout=fuzz_timeout,
      additional_args=arguments + [artifact_prefix])

  if (not use_minijail and
      fuzz_result.return_code == constants.LIBFUZZER_ERROR_EXITCODE):
    # Minijail returns 1 if the exit code is nonzero.
    # Otherwise: we can assume that a return code of 1 means that libFuzzer
    # itself ran into an error.
    logs.log_error(ENGINE_ERROR_MESSAGE, engine_output=fuzz_result.output)

  log_lines = fuzz_result.output.splitlines()
  # Output can be large, so save some memory by removing reference to the
  # original output which is no longer needed.
  fuzz_result.output = None

  # Check if we crashed, and get the crash testcase path.
  crash_testcase_file_path = None
  for line in log_lines:
    match = re.match(CRASH_TESTCASE_REGEX, line)
    if match:
      crash_testcase_file_path = match.group(1)
      break

  if crash_testcase_file_path:
    # Write the new testcase.
    if use_minijail:
      # Convert chroot relative path to host path. Remove the leading '/' before
      # joining.
      crash_testcase_file_path = os.path.join(minijail_chroot.directory,
                                              crash_testcase_file_path[1:])

    # Copy crash testcase contents into the main testcase path.
    shutil.move(crash_testcase_file_path, testcase_file_path)

  # Print the command output.
  log_header_format = ('Command: %s\n' 'Bot: %s\n' 'Time ran: %f\n')
  bot_name = environment.get_value('BOT_NAME', '')
  command = fuzz_result.command
  if use_minijail:
    # Remove minijail prefix.
    command = engine_common.strip_minijail_command(command, fuzzer_path)
  print(log_header_format % (engine_common.get_command_quoted(command),
                             bot_name, fuzz_result.time_executed))

  # Parse stats information based on libFuzzer output.
  parsed_stats = parse_log_stats(log_lines)

  # Extend parsed stats by additional performance features.
  parsed_stats.update(
      stats.parse_performance_features(log_lines, fuzzing_strategies,
                                       arguments))

  # Set some initial stat overrides.
  timeout_limit = fuzzer_utils.extract_argument(
      arguments, constants.TIMEOUT_FLAG, remove=False)

  expected_duration = runner.get_max_total_time(fuzz_timeout)
  actual_duration = int(fuzz_result.time_executed)
  fuzzing_time_percent = 100 * actual_duration / float(expected_duration)
  stat_overrides = {
      'timeout_limit': int(timeout_limit),
      'expected_duration': expected_duration,
      'actual_duration': actual_duration,
      'fuzzing_time_percent': fuzzing_time_percent,
  }

  # Make a decision on whether merge step is needed at all. If there are no
  # new units added by libFuzzer run, then no need to do merge at all.
  new_units_added = parsed_stats.get('new_units_added', 0)
  merge_error = None
  if new_units_added:
    # Merge the new units back into the corpus.
    # For merge, main corpus directory should be passed first of all corpus
    # directories.
    if corpus_directory in corpus_directories:
      corpus_directories.remove(corpus_directory)
    corpus_directories = [corpus_directory] + corpus_directories

    # If this times out, it's possible that we will miss some units. However, if
    # we're taking >10 minutes to load/merge the corpus something is going very
    # wrong and we probably don't want to make things worse by adding units
    # anyway.

    merge_tmp_dir = None
    if not use_minijail:
      merge_tmp_dir = os.path.join(fuzzer_utils.get_temp_dir(), 'merge_workdir')
      engine_common.recreate_directory(merge_tmp_dir)

    old_corpus_len = shell.get_directory_file_count(corpus_directory)
    merge_result = runner.merge(
        corpus_directories,
        merge_timeout=engine_common.get_merge_timeout(DEFAULT_MERGE_TIMEOUT),
        tmp_dir=merge_tmp_dir,
        additional_args=arguments)
    new_corpus_len = shell.get_directory_file_count(corpus_directory)
    new_units_added = 0

    merge_error = None
    if merge_result.timed_out:
      merge_error = 'Merging new testcases timed out:'
    elif merge_result.return_code != 0:
      merge_error = 'Merging new testcases failed:'
    else:
      new_units_added = new_corpus_len - old_corpus_len

    stat_overrides['new_units_added'] = new_units_added

    if merge_result.output:
      stat_overrides.update(
          stats.parse_stats_from_merge_log(merge_result.output.splitlines()))
  else:
    stat_overrides['new_units_added'] = 0
    logs.log('Skipped corpus merge since no new units added by fuzzing.')

  # Get corpus size after merge. This removes the duplicate units that were
  # created during this fuzzing session.
  stat_overrides['corpus_size'] = shell.get_directory_file_count(
      corpus_directory)

  # Delete all corpus directories except for the main one. These were temporary
  # directories to store new testcase mutations and have already been merged to
  # main corpus directory.
  if corpus_directory in corpus_directories:
    corpus_directories.remove(corpus_directory)
  for directory in corpus_directories:
    shutil.rmtree(directory, ignore_errors=True)

  if use_minijail:
    unbind_corpus_dirs(minijail_chroot, corpus_directories)

  # Apply overridden stats to the parsed stats prior to dumping.
  parsed_stats.update(stat_overrides)

  # Dump stats data for further uploading to BigQuery.
  engine_common.dump_big_query_data(parsed_stats, testcase_file_path,
                                    LIBFUZZER_PREFIX, fuzzer_name, command)

  # Add custom crash state based on fuzzer name (if needed).
  add_custom_crash_state_if_needed(fuzzer_name, log_lines, parsed_stats)
  for line in log_lines:
    print(line)

  # Add fuzzing strategies used.
  engine_common.print_fuzzing_strategies(fuzzing_strategies)

  # Add merge error (if any).
  if merge_error:
    print(data_types.CRASH_STACKTRACE_END_MARKER)
    print(merge_error)
    print('Command:', get_printable_command(merge_result.command, fuzzer_path,
                                            use_minijail))
    print(merge_result.output)

  # Remove dictionary argument used for fuzzing, it is not needed for analysis.
  fuzzer_utils.extract_argument(arguments, constants.DICT_FLAG)
  analyze_and_update_recommended_dictionary(runner, fuzzer_name, log_lines,
                                            corpus_directory, arguments)

  # Close minijail chroot.
  if use_minijail:
    minijail_chroot.close()

  # Whenever new units are added to corpus, record the stats to make them
  # easily searchable in stackdriver.
  if new_units_added:
    logs.log(
        'New units added to corpus: %d.' % new_units_added, stats=parsed_stats)


if __name__ == '__main__':
  main(sys.argv)

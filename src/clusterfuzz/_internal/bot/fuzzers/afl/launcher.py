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
"""Launcher script for afl++ based fuzzers."""

# pylint: disable=g-statement-before-imports
try:
  # ClusterFuzz dependencies.
  from clusterfuzz._internal.base import modules
  modules.fix_module_search_paths()
except ImportError:
  pass

import atexit
import collections
import os
import re
import shutil
import signal
import stat
import subprocess
import sys

import six

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import dictionary_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import options
from clusterfuzz._internal.bot.fuzzers import strategy_selection
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.afl import constants
from clusterfuzz._internal.bot.fuzzers.afl import stats
from clusterfuzz._internal.bot.fuzzers.afl.fuzzer import write_dummy_file
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import strategy
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import profiler
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import minijail
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell

# Allow 30 minutes to merge the testcases back into the corpus. This matches
# libFuzzer's merge timeout.
DEFAULT_MERGE_TIMEOUT = 30 * 60

BOT_NAME = environment.get_value('BOT_NAME', '')

STDERR_FILENAME = 'stderr.out'

MAX_OUTPUT_LEN = 1 * 1024 * 1024  # 1 MB

# .options file option for the number of persistent executions.
PERSISTENT_EXECUTIONS_OPTION = 'n'

# Grace period for the launcher to complete any processing before it's killed.
# This will no longer be needed when we migrate to the engine interface.
POSTPROCESSING_TIMEOUT = 30


class AflOptionType(object):
  ARG = 0
  ENV_VAR = 1


# Afl options have names and can either be commandline arguments or environment
# variables.
AflOption = collections.namedtuple('AflOption', ['name', 'type'])


class AflConfig(object):
  """Helper class that determines the arguments that should be passed to
  afl-fuzz, environment variables that should be set before running afl-fuzz,
  and the number of persistent executions that should be passed to the target
  Determines these mainly by parsing the .options file for the target."""

  # Mapping of libfuzzer option names to AflOption objects.
  LIBFUZZER_TO_AFL_OPTIONS = {
      'dict':
          AflOption(constants.DICT_FLAG, AflOptionType.ARG),
      'close_fd_mask':
          AflOption(constants.CLOSE_FD_MASK_ENV_VAR, AflOptionType.ENV_VAR),
  }

  def __init__(self):
    """Sets the configs to sane defaults. Use from_target_path if you want to
    use the .options file and possibly .dict to set the configs."""
    self.additional_afl_arguments = []
    self.additional_env_vars = {}
    self.num_persistent_executions = constants.MAX_PERSISTENT_EXECUTIONS

  @classmethod
  def from_target_path(cls, target_path):
    """Instantiates and returns an AFLConfig object. The object is configured
    based on |target_path|."""
    config = cls()
    config.parse_options(target_path)
    config.dict_path = fuzzer_utils.extract_argument(
        config.additional_afl_arguments, constants.DICT_FLAG, remove=False)

    config.use_default_dict(target_path)
    dictionary_manager.correct_if_needed(config.dict_path)

    return config

  def parse_options(self, target_path):
    """Parses a target's .options file (determined using |target_path|) if it
    exists and sets configs based on it."""
    fuzzer_options = options.get_fuzz_target_options(target_path)
    if not fuzzer_options:
      return

    self.additional_env_vars = fuzzer_options.get_env()

    # Try to convert libFuzzer arguments to AFL arguments or env vars.
    libfuzzer_options = fuzzer_options.get_engine_arguments('libfuzzer')
    for libfuzzer_name, value in six.iteritems(libfuzzer_options.dict()):
      if libfuzzer_name not in self.LIBFUZZER_TO_AFL_OPTIONS:
        continue

      afl_option = self.LIBFUZZER_TO_AFL_OPTIONS[libfuzzer_name]
      if afl_option.type == AflOptionType.ARG:
        self.additional_afl_arguments.append('%s%s' % (afl_option.name, value))
      else:
        assert afl_option.type == AflOptionType.ENV_VAR
        self.additional_env_vars[afl_option.name] = value

    # Get configs set specifically for AFL.
    afl_options = fuzzer_options.get_engine_arguments('AFL')
    self.num_persistent_executions = afl_options.get(
        PERSISTENT_EXECUTIONS_OPTION, constants.MAX_PERSISTENT_EXECUTIONS)

  def use_default_dict(self, target_path):
    """Set the dictionary argument in |self.additional_afl_arguments| to
    %target_binary_name%.dict if no dictionary argument is already specified.
    Also update |self.dict_path|."""
    if self.dict_path:
      return

    default_dict_path = dictionary_manager.get_default_dictionary_path(
        target_path)
    if not os.path.exists(default_dict_path):
      return

    self.dict_path = default_dict_path
    self.additional_afl_arguments.append(constants.DICT_FLAG + self.dict_path)


class AflFuzzOutputDirectory(object):
  """Helper class used by AflRunner to deal with AFL's output directory and its
  contents (ie: the -o argument to afl-fuzz)."""

  # AFL usually copies over old units from the corpus to the queue and adds the
  # string 'orig' to the new filename. Therefore we know that testcases
  # containing 'orig' are copied.
  COPIED_FILE_STRING = 'orig'

  TESTCASE_REGEX = re.compile(r'id:\d{6},.+')

  def __init__(self):
    self.output_directory = os.path.join(fuzzer_utils.get_temp_dir(),
                                         'afl_output_dir')

    engine_common.recreate_directory(self.output_directory)

  @classmethod
  def is_testcase(cls, path):
    """Is the path an AFL testcase file or something else."""
    return (os.path.isfile(path) and
            bool(re.match(cls.TESTCASE_REGEX, os.path.basename(path))))

  @property
  def instance_directory(self):
    """Returns afl-fuzz's instance directory."""
    return os.path.join(self.output_directory, constants.DEFAULT_INSTANCE_ID)

  @property
  def queue(self):
    """Returns afl-fuzz's queue directory."""
    return os.path.join(self.instance_directory, 'queue')

  def is_new_testcase(self, path):
    """Determine if |path| is a new unit."""
    # Clearly non-testcases can't be new testcases.
    return (self.is_testcase(path) and
            self.COPIED_FILE_STRING not in os.path.basename(path))

  def count_new_units(self, corpus_path):
    """Count the number of new units (testcases) in |corpus_path|."""
    corpus_files = os.listdir(corpus_path)
    num_new_units = 0

    for testcase in corpus_files:
      if self.is_new_testcase(os.path.join(corpus_path, testcase)):
        num_new_units += 1

    return num_new_units

  def copy_crash_if_needed(self, testcase_path):
    """Copy the first crash found by AFL to |testcase_path| (the input file
    created by run.py).
    """
    crash_paths = list_full_file_paths(
        os.path.join(self.instance_directory, 'crashes'))

    for crash_path in crash_paths:
      # AFL puts a README.txt file in the crashes directory. Just ignore it.
      if self.is_testcase(crash_path):
        shutil.copyfile(crash_path, testcase_path)
        break

  def remove_hang_in_queue(self, hang_filename):
    """Removes the hanging testcase from queue."""
    # AFL copies all inputs to the queue and renames them in the format
    # "id:NUMBER,orig:$hang_filename". So remove that file from the queue.
    # TODO(metzman): What about for the copied inputs without 'orig' in their
    # name that we have been seeing? Does this work anyway because AFL uses the
    # the full name of the file in the queue?
    queue_paths = list_full_file_paths(self.queue)
    hang_queue_path = [
        path for path in queue_paths if path.endswith(hang_filename)
    ][0]

    remove_path(hang_queue_path)

  @property
  def stats_path(self):
    """Returns the path of AFL's stats file: "fuzzer_stats"."""
    return os.path.join(self.instance_directory, 'fuzzer_stats')


class FuzzingStrategies(object):
  """Helper class used by AflRunner classes to decide what strategy to use
  and to record the decision for StatsGetter to use later."""

  # Probability for the level of CMPLOG to set. (-l X)
  CMPLOG_LEVEL_PROBS = [
      ('1', 0.6),  # Level 1
      ('2', 0.3),  # Level 2
      ('3', 0.1),  # Level 3
  ]

  # Probabilty for arithmetic CMPLOG calculations.
  CMPLOG_ARITH_PROB = 0.1

  # Probability for transforming CMPLOG solving.
  CMPLOG_TRANS_PROB = 0.1

  # Probability to disable trimming. (AFL_DISABLE_TRIM=1)
  DISABLE_TRIM_PROB = 0.75

  # Probability for increased havoc intensity. (AFL_EXPAND_HAVOC_NOW=1)
  EXPAND_HAVOC_PROB = 0.5

  # Probability to use the MOpt mutator. (-L0)
  MOPT_PROB = 0.4

  # Probability to use the original afl queue walking mechanism. (-Z)
  QUEUE_OLD_STRATEGY_PROB = 0.2

  # Probability to enable the schedule cycler. (AFL_CYCLE_SCHEDULES=1)
  SCHEDULER_CYCLE_PROB = 0.1

  # Propability which scheduler to select. (-p SCHEDULER)
  SCHEDULER_PROBS = [
      ('fast', .3),
      ('explore', .3),
      ('exploit', .2),
      ('coe', .1),
      ('rare', .1),
  ]

  # TODO(mbarbella): The codepath involving |strategy_dict| and the
  # to_strategy_dict function should be removed when everything is fully
  # converted to the engine pipeline. For now this allows the code to be shared
  # between both cases while still adhering to the new pipeline's API.
  def __init__(self, target_path, strategy_dict=None):
    self.corpus_subset_size = None
    self.candidate_generator = engine_common.Generator.NONE

    # If we have already generated a strategy dict, use that in favor of
    # creating a new pool and picking randomly.
    if strategy_dict is not None:
      self.use_corpus_subset = 'corpus_subset' in strategy_dict
      if self.use_corpus_subset:
        self.corpus_subset_size = strategy_dict['corpus_subset']

      if strategy_dict.get(strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name) == 1:
        self.candidate_generator = engine_common.Generator.RADAMSA
      elif strategy_dict.get(
          strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name) == 1:
        self.candidate_generator = engine_common.Generator.ML_RNN
    else:
      strategy_pool = strategy_selection.generate_weighted_strategy_pool(
          strategy_list=strategy.AFL_STRATEGY_LIST,
          use_generator=True,
          engine_name='afl')

      # Select a generator to attempt to use for existing testcase mutations.
      self.candidate_generator = engine_common.select_generator(
          strategy_pool, target_path)

      self.use_corpus_subset = strategy_pool.do_strategy(
          strategy.CORPUS_SUBSET_STRATEGY)

      if self.use_corpus_subset:
        self.corpus_subset_size = engine_common.random_choice(
            engine_common.CORPUS_SUBSET_NUM_TESTCASES)

    self.is_mutations_run = (
        self.candidate_generator != engine_common.Generator.NONE)

    # Generator that is actually used. Initialize to none, change if new
    # testcase mutations are properly generated by the candidate generator.
    self.generator_strategy = engine_common.Generator.NONE

  def to_strategy_dict(self):
    """Convert to a strategy dict in the format used by the engine pipeline."""
    # The decision on whether or not fast cal should be used is made during
    # fuzzing. This function is expected to be called whe preparing for fuzzing.
    strategies_dict = {}

    if self.generator_strategy == engine_common.Generator.RADAMSA:
      strategies_dict[strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name] = 1
    elif self.generator_strategy == engine_common.Generator.ML_RNN:
      strategies_dict[strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name] = 1

    if self.use_corpus_subset:
      strategies_dict['corpus_subset'] = self.corpus_subset_size

    return strategies_dict


class AflFuzzInputDirectory(object):
  """Helper class used by AflRunner to deal with the input directory passed to
  afl-fuzz as the -i argument.
  """

  # If the number of input files is less than this, don't bother skipping
  # deterministic steps since it won't take long.
  MIN_INPUTS_FOR_SKIP = 10

  MAX_COPIED_CORPUS_SIZE = 2**30  # 1 GB

  def __init__(self, input_directory, target_path, fuzzing_strategies):
    """Inits AflFuzzInputDirectory.

    Args:
      input_directory: Directory passed to afl-fuzz containing corpus.
      target_path: Path to the fuzzer executable. Used to find seed corpus.
      fuzzing_strategies: fuzzing strategies to use.
    """

    self.input_directory = input_directory
    self.strategies = fuzzing_strategies

    # We only need to use this when a temporary input directory is made.
    # (ie: when there is an oversized testcase in the input).
    self.original_input_directory = None

    engine_common.unpack_seed_corpus_if_needed(
        target_path, self.input_directory, max_bytes=constants.MAX_FILE_BYTES)

    # Ensure there is a usable testcase in the input directory. This is needed
    # because locally (and possibly for new fuzzers on CF) the dummy file is not
    # always in the input directory, which prevents AFL from running.
    if not list_full_file_paths(self.input_directory):
      write_dummy_file(self.input_directory)

  def restore_if_needed(self):
    """Restore the original input directory if self.original_input_directory is
    set. Used to by merge() to get rid of the temporary input directory if it
    exists and merge new units into the original input directory.
    """
    if self.original_input_directory is None:
      return

    # Remove the current input directory as it was only temporary.
    remove_path(self.input_directory)
    self.input_directory = self.original_input_directory
    self.original_input_directory = None


class AflRunnerCommon(object):
  """Afl runner common routines."""

  # Window of time for afl to exit gracefully before we kill it.
  AFL_CLEAN_EXIT_TIME = 10.0

  # Time to wait for SIGTERM handler.
  SIGTERM_WAIT_TIME = 10.0

  # Maximum number of times we will retry fuzzing after fixing an issue.
  MAX_FUZZ_RETRIES = 40

  # Maximum number of times we will retry fuzzing with a strict autocalibrated
  # timeout. After this number of fuzzing retries, if we see a hang we will set
  # the timeout to to '-t' + str(self.MANUAL_TIMEOUT_MILLISECONDS) + '+' to tell
  # AFL to skip testcases that take longer.
  MAX_FUZZ_RETRIES_WITH_STRICT_TIMEOUT = 20

  # The number of times we will retry fuzzing with the deferred fork server
  # after the first testcase hangs. Afterwards we will use
  # AFL_DRIVER_DONT_DEFER, since this is a common symptom of fuzzers that
  # cant use the deferred forkserver.
  MAX_FIRST_HANGS_WITH_DEFERRED_FORKSERVER = 5

  # The timeout we will use if autocalibrating results in too many hangs. This
  # is the maximum autocalibrated timeout afl-fuzz can set.
  MANUAL_TIMEOUT_MILLISECONDS = 5000

  # Regexes used to determine which file caused AFL to quit.
  CRASH_REGEX = re.compile(
      r'Test case \'id\:\d+,orig:(?P<orig_testcase_filename>.*)\' results in a'
      ' crash')

  HANG_REGEX = re.compile(
      r'Test case \'(?P<testcase_filename>.*)\' results in a (hang|timeout)')

  CPU_BIND_ERROR_REGEX = re.compile('PROGRAM ABORT :.*No more free CPU cores')

  # Log messages we format and log as error when afl-fuzz stops running.
  CRASH_LOG_MESSAGE = 'Testcase {0} in corpus causes a crash'
  HANG_LOG_MESSAGE = 'Testcase {0} in corpus causes a hang, retrying without it'

  SHOWMAP_FILENAME = 'afl_showmap_output'
  SHOWMAP_REGEX = re.compile(br'(?P<guard>\d{6}):(?P<hit_count>\d+)\n')

  def __init__(self,
               target_path,
               config,
               testcase_file_path,
               input_directory,
               timeout=None,
               afl_tools_path=None,
               strategy_dict=None):
    """Inits the AflRunner.

    Args:
      target_path: Path to the fuzz target.
      config: AflConfig object.
      testcase_file_path: File to write crashes to.
      input_directory: Corpus directory passed to afl-fuzz.
      afl_tools_path: Path that is used to locate afl-* tools.
    """

    self.target_path = target_path
    self.config = config
    self.testcase_file_path = testcase_file_path
    self._input_directory = input_directory
    self.timeout = timeout

    if afl_tools_path is None:
      afl_tools_path = os.path.dirname(target_path)

    # Set paths to afl tools.
    self.afl_fuzz_path = os.path.join(afl_tools_path, 'afl-fuzz')
    self.afl_showmap_path = os.path.join(afl_tools_path, 'afl-showmap')

    self._afl_input = None
    self._afl_output = None

    self.strategies = FuzzingStrategies(
        target_path, strategy_dict=strategy_dict)

    # Set this to None so we can tell if it has never been set or if it's just
    # empty.
    self._fuzzer_stderr = None

    self.initial_max_total_time = 0

    for env_var, value in six.iteritems(config.additional_env_vars):
      environment.set_value(env_var, value)

    self._showmap_output_path = None
    self.merge_timeout = engine_common.get_merge_timeout(DEFAULT_MERGE_TIMEOUT)
    self.showmap_no_output_logged = False
    self._fuzz_args = []

  @property
  def showmap_output_path(self):
    """Returns the showmap output path."""
    # Initialize _showmap_output_path lazily since MiniJailRunner needs to
    # execute its __init__ before it can be set.
    if self._showmap_output_path is None:
      if environment.get_value('USE_MINIJAIL'):
        self._showmap_output_path = os.path.join(self.chroot.directory,
                                                 self.SHOWMAP_FILENAME)
      else:
        self._showmap_output_path = os.path.join(fuzzer_utils.get_temp_dir(),
                                                 self.SHOWMAP_FILENAME)

    return self._showmap_output_path

  @property
  def stderr_file_path(self):
    """Returns the file for afl to output stack traces."""
    return os.path.join(fuzzer_utils.get_temp_dir(), STDERR_FILENAME)

  @property
  def fuzzer_stderr(self):
    """Returns the stderr of the fuzzer. Reads it first if it wasn't already
    read. Because ClusterFuzz terminates this process after seeing a stacktrace
    printed, make sure that printing this property is the last code a program
    expects to execute.
    """
    if self._fuzzer_stderr is not None:
      return self._fuzzer_stderr

    try:
      with open(self.stderr_file_path, 'rb') as file_handle:
        stderr_data = utils.decode_to_unicode(
            utils.read_from_handle_truncated(file_handle, MAX_OUTPUT_LEN))

      self._fuzzer_stderr = get_first_stacktrace(stderr_data)
    except IOError:
      self._fuzzer_stderr = ''
    return self._fuzzer_stderr

  def run_single_testcase(self, testcase_path):
    """Runs a single testcase.

    Args:
      testcase_path: Path to testcase to be run.

    Returns:
      A new_process.ProcessResult.
    """
    self._executable_path = self.target_path

    assert not testcase_path.isdigit(), ('We don\'t want to specify number of'
                                         ' executions by accident.')

    self.afl_setup()
    result = self.run_and_wait(additional_args=[testcase_path])
    print('Running command:', engine_common.get_command_quoted(result.command))
    if result.return_code not in [0, 1, -6]:
      logs.log_error(
          'AFL target exited with abnormal exit code: %s.' % result.return_code,
          output=result.output)

    return result

  def set_environment_variables(self):
    """Sets environment variables needed by afl."""
    # Tell afl_driver to duplicate stderr to STDERR_FILENAME.
    # Environment variable names and values that must be set before running afl.
    environment.set_value(constants.FORKSRV_INIT_TMOUT_ENV_VAR,
                          constants.FORKSERVER_TIMEOUT)
    environment.set_value(constants.FAST_CAL_ENV_VAR, 1)
    environment.set_value(constants.IGNORE_UNKNOWN_ENVS_ENV_VAR, 1)
    environment.set_value(constants.SKIP_CRASHES_ENV_VAR, 1)
    environment.set_value(constants.SKIP_CPUFREQ_ENV_VAR, 1)
    environment.set_value(constants.BENCH_UNTIL_CRASH_ENV_VAR, 1)
    environment.set_value(constants.EXPAND_HAVOC_NOW_VAR, 1)
    environment.set_value(constants.STDERR_FILENAME_ENV_VAR,
                          self.stderr_file_path)

  def afl_setup(self):
    """Make sure we can run afl. Delete any files that afl_driver needs to
    create and set any environmnet variables it needs.
    """
    self.set_environment_variables()
    remove_path(self.stderr_file_path)

  @staticmethod
  def set_resume(afl_args):
    """Changes afl_args so afl-fuzz will resume fuzzing rather than restarting.
    """
    return AflRunner.set_input_arg(afl_args, constants.RESUME_INPUT)

  @staticmethod
  def get_arg_index(afl_args, flag):
    for idx, arg in enumerate(afl_args):
      if arg.startswith(flag):
        return idx

    return -1

  @classmethod
  def set_arg(cls, afl_args, flag, value):
    """Sets the afl |flag| to |value| in |afl_args|. If |flag| is already
    in |afl_args|, then the old value is replaced by |value|, otherwise |flag|
    and |value| are added.
    """
    idx = cls.get_arg_index(afl_args, flag)
    if value:
      new_arg = flag + str(value)
    else:
      new_arg = flag

    # Arg is not already in afl_args, add it.
    if idx == -1:
      afl_args.insert(0, new_arg)
    else:
      afl_args[idx] = new_arg

    return afl_args

  @classmethod
  def remove_arg(cls, afl_args, flag):
    idx = cls.get_arg_index(afl_args, flag)
    if idx == -1:
      return
    del afl_args[idx]

  @classmethod
  def set_input_arg(cls, afl_args, new_input_value):
    """Changes the input argument (-i) in |afl_args| to |new_input_value|."""
    return cls.set_arg(afl_args, constants.INPUT_FLAG, new_input_value)

  @classmethod
  def set_timeout_arg(cls, afl_args, timeout_value, skip_hangs=False):
    timeout_value = str(int(timeout_value))
    if skip_hangs:
      timeout_value += '+'

    cls.set_arg(afl_args, constants.TIMEOUT_FLAG, timeout_value)
    return afl_args

  def do_offline_mutations(self):
    """Mutate the corpus offline using Radamsa or ML RNN if specified."""
    if not self.strategies.is_mutations_run:
      return

    target_name = os.path.basename(self.target_path)
    project_qualified_target_name = (
        data_types.fuzz_target_project_qualified_name(utils.current_project(),
                                                      target_name))
    # Generate new testcase mutations according to candidate generator. If
    # testcase mutations are properly generated, set generator strategy
    # accordingly.
    generator_used = engine_common.generate_new_testcase_mutations(
        self.afl_input.input_directory, self.afl_input.input_directory,
        project_qualified_target_name, self.strategies.candidate_generator)

    if generator_used:
      self.strategies.generator_strategy = self.strategies.candidate_generator

    # Delete large testcases created by generators.
    for input_path in shell.get_files_list(self.afl_input.input_directory):
      if os.path.getsize(input_path) >= constants.MAX_FILE_BYTES:
        remove_path(input_path)

  def generate_afl_args(self,
                        afl_input=None,
                        afl_output=None,
                        mem_limit=constants.MAX_MEMORY_LIMIT):
    """Generate arguments to pass to Process.run_and_wait.

    Args:
      afl_input: Initial corpus directory passed as -i parameter to the afl
      tool. Defaults to self.afl_input.input_directory.

      afl_output: Output directory where afl stores corpus and stats, passed as
      -o parameter to the afl tool. Defaults to
      self.afl_output.output_directory.

      mem_limit: Virtual memory limit afl enforces on target binary, passed as
      -m parameter to the afl tool. Defaults to constants.MAX_MEMORY_LIMIT.

    Returns:
      A list built from the function's arguments that can be passed as the
      additional_args argument to Process.run_and_wait.

    """

    if afl_input is None:
      afl_input = self.afl_input.input_directory

    if afl_output is None:
      afl_output = self.afl_output.output_directory

    afl_args = [
        constants.INSTANCE_ID_FLAG + constants.DEFAULT_INSTANCE_ID,
        constants.INPUT_FLAG + afl_input, constants.OUTPUT_FLAG + afl_output,
        constants.MEMORY_LIMIT_FLAG + str(mem_limit)
    ]

    afl_args.extend(self.config.additional_afl_arguments)

    afl_args.extend(
        [self.target_path,
         str(self.config.num_persistent_executions)])

    return afl_args

  def should_try_fuzzing(self, max_total_time, num_retries):
    """Returns True if we should try fuzzing, based on the number of times we've
    already tried, |num_retries|, and the amount of time we have left
    (calculated using |max_total_time|).
    """
    if max_total_time <= 0:
      logs.log_error('Tried fuzzing for {0} seconds. Not retrying'.format(
          self.initial_max_total_time))

      return False

    if num_retries > self.MAX_FUZZ_RETRIES:
      logs.log_error(
          'Tried to retry fuzzing {0} times. Fuzzer is likely broken'.format(
              num_retries))

      return False

    return True

  def run_afl_fuzz(self, fuzz_args):
    """Run afl-fuzz and if there is an input that causes afl-fuzz to hang
    or if it can't bind to a cpu, try fixing the issue and running afl-fuzz
    again. If there is a crash in the starting corpus then report it.
    Args:
      fuzz_args: The arguments passed to afl-fuzz. List may be modified if
        afl-fuzz runs into an error.
    Returns:
      A new_process.ProcessResult.
    """
    # Define here to capture in closures.
    max_total_time = self.initial_max_total_time
    fuzz_result = None

    def get_time_spent_fuzzing():
      """Gets the amount of time spent running afl-fuzz so far."""
      return self.initial_max_total_time - max_total_time

    def check_error_and_log(error_regex, log_message_format):
      """See if error_regex can match in fuzz_result.output. If it can, then it
      uses the match to format and print log_message and return the match.
      Otherwise returns None.
      """
      matches = re.search(error_regex, fuzz_result.output)
      if matches:
        erroring_filename = matches.groups()[0]
        message_format = (
            'Seconds spent fuzzing: {seconds}, ' + log_message_format)

        logs.log(
            message_format.format(
                erroring_filename, seconds=get_time_spent_fuzzing()))

        return erroring_filename
      return None  # else

    num_first_testcase_hangs = 0
    num_retries = 0
    while self.should_try_fuzzing(max_total_time, num_retries):
      # Increment this now so that we can just "continue" without incrementing.
      num_retries += 1

      self.afl_setup()

      # If the target was compiled for CMPLOG we need to set this.
      build_directory = environment.get_value('BUILD_DIR')
      cmplog_build_file = os.path.join(build_directory, 'afl_cmplog.txt')
      if os.path.exists(cmplog_build_file):
        self.set_arg(fuzz_args, constants.CMPLOG_FLAG, self.target_path)

      # If a compile time dictionary was created - load it.
      aflpp_dict_file = os.path.join(build_directory, 'afl++.dict')
      if os.path.exists(aflpp_dict_file):
        self.set_arg(fuzz_args, constants.DICT_FLAG, aflpp_dict_file)

      # In the following section we randomly select different strategies.

      # Randomly select a scheduler.
      self.set_arg(fuzz_args, constants.SCHEDULER_FLAG,
                   rand_schedule(self.strategies.SCHEDULER_PROBS))

      # Randomly set trimming vs no trimming.
      if engine_common.decide_with_probability(
          self.strategies.DISABLE_TRIM_PROB):
        environment.set_value(constants.DISABLE_TRIM_ENV_VAR, 1)

      # Randomly enable expanded havoc mutation.
      if engine_common.decide_with_probability(
          self.strategies.EXPAND_HAVOC_PROB):
        environment.set_value(constants.EXPAND_HAVOC_ENV_VAR, 1)

      # Always CMPLOG only new finds.
      environment.set_value(constants.CMPLOG_ONLY_NEW_ENV_VAR, 1)

      # Randomly set new vs. old queue selection mechanism.
      if engine_common.decide_with_probability(
          self.strategies.QUEUE_OLD_STRATEGY_PROB):
        self.set_arg(fuzz_args, constants.QUEUE_OLD_STRATEGY_FLAG, None)

      # Randomly select the MOpt mutator.
      if engine_common.decide_with_probability(self.strategies.MOPT_PROB):
        self.set_arg(fuzz_args, constants.MOPT_FLAG, '0')

      # Select the CMPLOG level (even if no cmplog is used, it does not hurt).
      self.set_arg(fuzz_args, constants.CMPLOG_LEVEL_FLAG,
                   rand_cmplog_level(self.strategies))

      # Attempt to start the fuzzer.
      fuzz_result = self.run_and_wait(
          additional_args=fuzz_args,
          timeout=max_total_time,
          terminate_before_kill=True,
          terminate_wait_time=self.SIGTERM_WAIT_TIME)

      # Reduce max_total_time by the amount of time the last attempt took.
      max_total_time -= fuzz_result.time_executed

      # Break now only if everything went well. Note that if afl finds a crash
      # from fuzzing (and not in the input) it will exit with a zero return
      # code.
      if fuzz_result.return_code == 0:
        # If afl-fuzz found a crash, copy it to the testcase_file_path.
        self.afl_output.copy_crash_if_needed(self.testcase_file_path)
        break

      # Else the return_code was not 0 so something didn't work out. Try fixing
      # this if afl-fuzz threw an error because it saw a crash, hang or large
      # file in the starting corpus.

      # If there was a crash in the input/corpus, afl-fuzz won't run, so let
      # ClusterFuzz know about this and quit.
      crash_filename = check_error_and_log(self.CRASH_REGEX,
                                           self.CRASH_LOG_MESSAGE)

      if crash_filename:
        crash_path = os.path.join(self.afl_input.input_directory,
                                  crash_filename)

        # Copy this file over so afl can reproduce the crash.
        shutil.copyfile(crash_path, self.testcase_file_path)
        break

      # afl-fuzz won't run if there is a hang in the input.
      hang_filename = check_error_and_log(self.HANG_REGEX,
                                          self.HANG_LOG_MESSAGE)

      if hang_filename:
        # Remove hang from queue and resume fuzzing
        self.afl_output.remove_hang_in_queue(hang_filename)

        # Now that the bad testcase has been removed, let's resume fuzzing so we
        # don't start again from the beginning of the corpus.
        self.set_resume(fuzz_args)

        if hang_filename.startswith('id:000000'):
          num_first_testcase_hangs += 1
          if (num_first_testcase_hangs >
              self.MAX_FIRST_HANGS_WITH_DEFERRED_FORKSERVER):
            logs.log_warn('First testcase hangs when not deferring.')

          elif (num_first_testcase_hangs ==
                self.MAX_FIRST_HANGS_WITH_DEFERRED_FORKSERVER):
            environment.set_value(constants.DONT_DEFER_ENV_VAR, 1)
            print('Instructing AFL not to defer forkserver.\nIf this fixes the '
                  'fuzzer, you should add this to the .options file:\n'
                  '[env]\n'
                  'afl_driver_dont_defer = 1')

        if num_retries - 1 > self.MAX_FUZZ_RETRIES_WITH_STRICT_TIMEOUT:
          skip_hangs = True
          self.set_timeout_arg(fuzz_args, self.MANUAL_TIMEOUT_MILLISECONDS,
                               skip_hangs)

        continue

      # If False: then prepare_retry_if_cpu_error can't solve the issue.
      if self.prepare_retry_if_cpu_error(fuzz_result):
        continue  # Try fuzzing again with the cpu error fixed.

      # If we can't do anything useful about the error, log it and don't try to
      # fuzz again.
      logs.log_error(
          ('Afl exited with a non-zero exitcode: %s. Cannot recover.' %
           fuzz_result.return_code),
          engine_output=fuzz_result.output)

      break

    return fuzz_result

  def prepare_retry_if_cpu_error(self, fuzz_result):
    """AFL will try to bind targets to a particular core for a speed
    improvement. If this isn't possible, then AFL won't run unless
    AFL_NO_AFFINITY=1. One way this can happen is if afl-fuzz leaves zombies
    around that are still bound to a core. Unfortunately AFL sometimes does
    this in persistent mode.
    See https://groups.google.com/forum/#!topic/afl-users/E37s4YDti7o
    """
    if re.search(self.CPU_BIND_ERROR_REGEX, fuzz_result.output) is None:
      return False

    # If we have already tried fixing this error but it is still happening,
    # log it and don't try again.
    current_no_affinity_value = environment.get_value(
        constants.NO_AFFINITY_ENV_VAR)

    if current_no_affinity_value is not None:
      logs.log_warn(('Already tried fixing CPU bind error\n'
                     '$AFL_NO_AFFINITY: %s\n'
                     'Not retrying.') % current_no_affinity_value)

      return False  # return False so this error is considered unhandled.

    # Log that this happened so someone can investigate/remediate the zombies
    # and then try fuzzing again, this time telling AFL not to bind.
    logs.log_error(
        'CPU binding error encountered by afl-fuzz\n'
        'Check bot: %s for zombies\n'
        'Trying again with AFL_NO_AFFINITY=1' % BOT_NAME,
        afl_output=fuzz_result.output)
    environment.set_value(constants.NO_AFFINITY_ENV_VAR, 1)
    return True

  @property
  def afl_input(self):
    """Don't create the object until we need it, since it isn't used for
    reproducing testcases."""
    if self._afl_input is None:
      self._afl_input = AflFuzzInputDirectory(self._input_directory,
                                              self.target_path, self.strategies)

    return self._afl_input

  @property
  def afl_output(self):
    """Don't create the object until we need it, since it isn't used for
    reproducing testcases."""

    if self._afl_output is None:
      self._afl_output = AflFuzzOutputDirectory()
    return self._afl_output

  def fuzz(self):
    """Running fuzzing command. Wrapper around run_afl_fuzz that performs one
    time setup.

    Returns:
      A new_process.ProcessResult.
    """
    # Ensure self.executable_path is afl-fuzz
    self._executable_path = self.afl_fuzz_path

    self.initial_max_total_time = (
        get_fuzz_timeout(
            self.strategies.is_mutations_run, full_timeout=self.timeout) -
        self.AFL_CLEAN_EXIT_TIME - self.SIGTERM_WAIT_TIME)

    assert self.initial_max_total_time > 0

    self._fuzz_args = self.generate_afl_args()

    self.do_offline_mutations()

    return self.run_afl_fuzz(self._fuzz_args)

  def get_file_features(self, input_file_path, showmap_args):
    """Get the features (edge hit counts) of |input_file_path| using
    afl-showmap."""
    # TODO(metzman): Figure out if we should worry about CPU affinity errors
    # here.
    showmap_result = self.run_and_wait(
        additional_args=showmap_args,
        input_data=engine_common.read_data_from_file(input_file_path),
        # TODO(metzman): Set a more reasonable per-file timeout. This is a must
        # to make timeouts smarter for afl-fuzz.
        timeout=self.merge_timeout,
        extra_env={constants.DEBUG_VAR: '1'})

    self.merge_timeout -= showmap_result.time_executed

    # TODO(metzman): Figure out why negative values are accepted by
    # self.run_and_wait.
    if showmap_result.timed_out or self.merge_timeout <= 0:
      return None, True

    # Log an error if showmap didn't write any coverage.
    if not os.path.exists(self.showmap_output_path):
      if not self.showmap_no_output_logged:
        self.showmap_no_output_logged = True
        logs.log_error(('afl-showmap didn\'t output any coverage for '
                        'file {file_path} ({file_size} bytes).\n'
                        'Command: {command}\n'
                        'Return code: {return_code}\n'
                        'Time executed: {time_executed}\n'
                        'Output: {output}').format(
                            file_path=input_file_path,
                            file_size=os.path.getsize(input_file_path),
                            command=showmap_result.command,
                            return_code=showmap_result.return_code,
                            time_executed=showmap_result.time_executed,
                            output=showmap_result.output))
      return None, True

    showmap_output = engine_common.read_data_from_file(self.showmap_output_path)

    features = set()
    for match in re.finditer(self.SHOWMAP_REGEX, showmap_output):
      d = match.groupdict()
      features.add((int(d['guard']), int(d['hit_count'])))
    logs.log('afl-showmap succeedded for '
             'file {file_path}: {features} features'.format(
                 file_path=input_file_path, features=len(features)))
    return frozenset(features), False

  def merge_corpus(self):
    """Merge new testcases into the input corpus."""
    logs.log('Merging corpus.')
    # Don't tell the fuzz target to write its stderr to the same file written
    # to during fuzzing. The target won't write its stderr anywhere.
    try:
      del os.environ[constants.STDERR_FILENAME_ENV_VAR]
    except KeyError:
      pass
    self._executable_path = self.afl_showmap_path
    # Hack around minijail.
    showmap_args = self._fuzz_args
    showmap_args[-1] = '1'
    # Remove arguments that are just for afl-fuzz.
    self.remove_arg(showmap_args, constants.DICT_FLAG)
    self.remove_arg(showmap_args, constants.INPUT_FLAG)
    self.remove_arg(showmap_args, constants.INSTANCE_ID_FLAG)
    self.remove_arg(showmap_args, constants.MOPT_FLAG)
    self.remove_arg(showmap_args, constants.CMPLOG_LEVEL_FLAG)
    self.remove_arg(showmap_args, constants.QUEUE_OLD_STRATEGY_FLAG)
    self.remove_arg(showmap_args, constants.SCHEDULER_FLAG)
    self.remove_arg(showmap_args, constants.CMPLOG_FLAG)

    # Replace -o argument.
    if environment.get_value('USE_MINIJAIL'):
      showmap_output_path = '/' + self.SHOWMAP_FILENAME
    else:
      showmap_output_path = self.showmap_output_path
    idx = self.get_arg_index(showmap_args, constants.OUTPUT_FLAG)
    assert idx != -1
    self.set_arg(showmap_args, constants.OUTPUT_FLAG, showmap_output_path)

    input_dir = self.afl_input.input_directory
    corpus = Corpus()
    input_inodes = set()
    input_filenames = set()
    for file_path in shell.get_files_list(input_dir):
      file_features, timed_out = self.get_file_features(file_path, showmap_args)
      if timed_out:
        logs.log_warn('Timed out in merge while processing initial corpus.')
        return 0

      input_inodes.add(os.stat(file_path).st_ino)
      input_filenames.add(os.path.basename(file_path))
      corpus.associate_features_with_file(file_features, file_path)

    for file_path in list_full_file_paths(self.afl_output.queue):
      # Don't waste time merging copied files.
      inode = os.stat(file_path).st_ino

      # TODO(metzman): Make is_new_testcase capable of checking for hard links
      # and same files.
      # TODO(metzman): Replace this with portable code.
      if (not self.afl_output.is_new_testcase(file_path) or
          inode in input_inodes or  # Is it a hard link?
          # Is it the same file?
          os.path.basename(file_path) in input_filenames):
        continue

      file_features, timed_out = self.get_file_features(file_path, showmap_args)
      if timed_out:
        logs.log_warn('Timed out in merge while processing output.')
        break

      corpus.associate_features_with_file(file_features, file_path)

    # Use destination file as hash of file contents to avoid overwriting
    # different files with the same name that were created from another
    # launcher instance.
    new_units_added = 0
    for src_path in corpus.element_paths:
      # Don't merge files into the initial corpus if they are already there.
      if os.path.dirname(src_path) == input_dir:
        continue
      dest_filename = utils.file_hash(src_path)
      dest_path = os.path.join(input_dir, dest_filename)
      if shell.move(src_path, dest_path):
        new_units_added += 1

    return new_units_added

  def libfuzzerize_corpus(self):
    """Make corpus directories libFuzzer compatible, merge new testcases
    if needed and return the number of new testcases added to corpus.
    """
    # Remove the input directory binding as it isn't needed for merging and
    # may actually break merging if it was temporary and gets deleted.
    if environment.get_value('USE_MINIJAIL'):
      input_directory = self.afl_input.input_directory
      input_bindings = [
          binding for binding in self.chroot.bindings
          if binding.src_path == input_directory
      ]

      assert len(input_bindings) == 1
      input_binding = input_bindings[0]
      self.chroot.bindings.remove(input_binding)

    self.afl_input.restore_if_needed()
    # Number of new units created during fuzzing.
    new_units_generated = self.afl_output.count_new_units(self.afl_output.queue)

    # Number of new units we add to the corpus after merging.
    new_units_added = new_units_generated

    if new_units_generated:
      new_units_added = self.merge_corpus()
      logs.log('Merge completed successfully.')

    # Get corpus size after merge. This removes the duplicate units that were
    # created during this fuzzing session.
    corpus_size = shell.get_directory_file_count(self.afl_input.input_directory)

    return new_units_generated, new_units_added, corpus_size


class AflRunner(AflRunnerCommon, new_process.UnicodeProcessRunner):
  """Afl runner."""

  def __init__(self,
               target_path,
               config,
               testcase_file_path,
               input_directory,
               timeout=None,
               afl_tools_path=None,
               strategy_dict=None):
    super().__init__(target_path, config, testcase_file_path, input_directory,
                     timeout, afl_tools_path, strategy_dict)

    new_process.ProcessRunner.__init__(self, self.afl_fuzz_path)


class MinijailAflRunner(AflRunnerCommon, new_process.UnicodeProcessRunnerMixin,
                        engine_common.MinijailEngineFuzzerRunner):
  """Minijail AFL runner."""

  def __init__(self,
               chroot,
               target_path,
               config,
               testcase_file_path,
               input_directory,
               timeout=None,
               afl_tools_path=None,
               strategy_dict=None):
    super().__init__(target_path, config, testcase_file_path, input_directory,
                     timeout, afl_tools_path, strategy_dict)

    minijail.MinijailProcessRunner.__init__(self, chroot, self.afl_fuzz_path)

  def _get_or_create_chroot_binding(self, corpus_directory):
    """Return chroot relative paths for the given corpus directories.

    Args:
      corpus_directories: A list of host corpus directories.

    Returns:
      A list of chroot relative paths.
    """
    chroot_rel_dir = os.path.relpath(corpus_directory, self.chroot.directory)
    if not chroot_rel_dir.startswith(os.pardir):
      # Already in chroot.
      return '/' + chroot_rel_dir

    binding = self.chroot.get_binding(corpus_directory)
    if binding:
      return binding.dest_path

    dest_path = '/' + os.path.basename(corpus_directory)
    self.chroot.add_binding(
        minijail.ChrootBinding(corpus_directory, dest_path, True))

    return dest_path

  def run_single_testcase(self, testcase_path):
    with self._chroot_testcase(testcase_path) as chroot_testcase_path:
      return super().run_single_testcase(chroot_testcase_path)

  def generate_afl_args(self,
                        afl_input=None,
                        afl_output=None,
                        mem_limit=constants.MAX_MEMORY_LIMIT):
    """Overriden generate_afl_args."""
    if afl_input:
      minijail_afl_input = self._get_or_create_chroot_binding(afl_input)
    else:
      minijail_afl_input = self._get_or_create_chroot_binding(
          self.afl_input.input_directory)

    if afl_output:
      minijail_afl_output = self._get_or_create_chroot_binding(afl_output)
    else:
      minijail_afl_output = self._get_or_create_chroot_binding(
          self.afl_output.output_directory)

    return super().generate_afl_args(minijail_afl_input, minijail_afl_output,
                                     mem_limit)

  @property
  def stderr_file_path(self):
    """Overriden stderr_file_path."""
    return os.path.join(self.chroot.directory, STDERR_FILENAME)

  def set_environment_variables(self):
    """Overridden set_environment_variables."""
    super().set_environment_variables()
    environment.set_value(constants.STDERR_FILENAME_ENV_VAR,
                          '/' + STDERR_FILENAME)


class CorpusElement(object):
  """An element (file) in a corpus."""

  def __init__(self, path):
    self.path = path
    self.size = os.path.getsize(self.path)


class Corpus(object):
  """A minimal set of input files (elements) for a fuzz target."""

  def __init__(self):
    self.features_and_elements = {}

  @property
  def element_paths(self):
    """Returns the filepaths of all elements in the corpus."""
    return set(
        element.path for element in six.itervalues(self.features_and_elements))

  def _associate_feature_with_element(self, feature, element):
    """Associate a feature with an element if the element is the smallest for
    the feature."""
    if feature not in self.features_and_elements:
      self.features_and_elements[feature] = element
      return

    # Feature already has an associated element.
    incumbent_element = self.features_and_elements[feature]
    if incumbent_element.size > element.size:
      self.features_and_elements[feature] = element

  def associate_features_with_file(self, features, path):
    """Associate features with a file when the file is the smallest for the
    features."""
    element = CorpusElement(path)
    for feature in features:
      self._associate_feature_with_element(feature, element)


def _verify_system_config():
  """Verifies system settings required for AFL."""

  def _check_core_pattern_file():
    """Verifies that core pattern file content is set to 'core'."""
    if not os.path.exists(constants.CORE_PATTERN_FILE_PATH):
      return False

    return open(constants.CORE_PATTERN_FILE_PATH).read().strip() == 'core'

  if _check_core_pattern_file():
    return

  return_code = subprocess.call(
      'sudo -n bash -c "echo core > {path}"'.format(
          path=constants.CORE_PATTERN_FILE_PATH),
      shell=True)
  if return_code or not _check_core_pattern_file():
    logs.log_fatal_and_exit(
        'Failed to set {path}. AFL needs {path} to be set to core.'.format(
            path=constants.CORE_PATTERN_FILE_PATH))


def load_testcase_if_exists(fuzzer_runner, testcase_file_path):
  """Loads a crash testcase if it exists."""
  # To ensure that we can run the fuzzer.
  os.chmod(fuzzer_runner.executable_path, stat.S_IRWXU | stat.S_IRGRP
           | stat.S_IXGRP)

  fuzzer_runner.run_single_testcase(testcase_file_path)
  print(fuzzer_runner.fuzzer_stderr)
  return True


def set_additional_sanitizer_options_for_afl_fuzz():
  """Set *SAN_OPTIONS to afl's liking.

  If ASAN_OPTIONS or MSAN_OPTION is set, they must contain certain options or
  afl-fuzz will refuse to fuzz. See check_asan_opts() in afl-fuzz.c in afl for
  more details.
  """
  # We need to check if ASAN_OPTIONS and/or MSAN_OPTIONS contain symbolize=0
  # because ClusterFuzz sets all sanitizers options equal to an empty string
  # before adding symbolize=0 to *either* ASAN_OPTIONS or MSAN_OPTIONS. Because
  # they will both be set but one will be empty, afl will think the empty one is
  # incorrect and quit if we don't do this.
  required_sanitizer_options = {
      'ASAN_OPTIONS': {
          'symbolize': 0,
          'abort_on_error': 1
      },
      'MSAN_OPTIONS': {
          'symbolize': 0,
          'exit_code': 86
      },
  }

  for options_env_var, option_values in six.iteritems(
      required_sanitizer_options):
    # If os.environ[options_env_var] is an empty string, afl will refuse to run,
    # because we haven't set the right options. Thus only continue if it does
    # not exist.
    if options_env_var not in os.environ:
      continue

    options_env_value = environment.get_memory_tool_options(options_env_var)
    options_env_value.update(option_values)
    environment.set_memory_tool_options(options_env_var, options_env_value)


def remove_path(path):
  """Remove |path| if it exists. Similar to running rm -rf |path|."""
  # Remove links to files and files.
  if os.path.isfile(path):
    os.remove(path)
  elif os.path.isdir(path):
    shutil.rmtree(path)
  # Else path doesn't exist. Do nothing.


def list_full_file_paths(directory):
  """List the absolute paths of files in |directory|."""
  directory_absolute_path = os.path.abspath(directory)
  paths = []
  for relative_path in os.listdir(directory):
    absolute_path = os.path.join(directory_absolute_path, relative_path)
    if os.path.isfile(absolute_path):  # Only return paths to files.
      paths.append(absolute_path)
  return paths


def get_first_stacktrace(stderr_data):
  """If |stderr_data| contains stack traces, only returns the first one.
  Otherwise returns the entire string."""

  # Use question mark after .+ for non-greedy, otherwise it will match more
  # than one stack trace.
  sanitizer_stacktrace_regex = r'ERROR: [A-z]+Sanitizer: .*\n(.|\n)+?ABORTING'
  match = re.search(sanitizer_stacktrace_regex, stderr_data)

  # If we can't find the first stacktrace, return the whole thing.
  if match is None:
    return stderr_data

  return stderr_data[:match.end()]


# TODO(mbarbella): After deleting the non-engine AFL code, remove this
# function and replace it with a simple check based on the timeout set in
# AFLEngine.fuzz. Mutations should also be moved to fuzz.
def get_fuzz_timeout(is_mutations_run, full_timeout=None):
  """Get the maximum amount of time that should be spent fuzzing."""
  fuzz_timeout = full_timeout

  # TODO(mbarbella): Delete this check once non-engine support is removed. The
  # engine pipeline always specifies a timeout.
  if fuzz_timeout is None:
    fuzz_timeout = engine_common.get_hard_timeout() - POSTPROCESSING_TIMEOUT

  # Subtract mutations timeout from the total timeout.
  if is_mutations_run:
    fuzz_timeout -= engine_common.get_new_testcase_mutations_timeout()

  # Subtract the merge timeout from the fuzz timeout in the non-engine case.
  if not full_timeout:
    fuzz_timeout -= engine_common.get_merge_timeout(DEFAULT_MERGE_TIMEOUT)

  assert fuzz_timeout > 0
  return fuzz_timeout


def prepare_runner(fuzzer_path,
                   config,
                   testcase_file_path,
                   input_directory,
                   timeout=None,
                   strategy_dict=None):
  """Common initialization code shared by the new pipeline and main."""
  # Set up temp dir.
  engine_common.recreate_directory(fuzzer_utils.get_temp_dir())

  if environment.get_value('USE_MINIJAIL'):
    # Set up chroot and runner.
    minijail_chroot = minijail.MinijailChroot(
        base_dir=fuzzer_utils.get_temp_dir())

    build_dir = environment.get_value('BUILD_DIR')

    # While it's possible for dynamic binaries to run without this, they need to
    # be accessible for symbolization etc. For simplicity we bind BUILD_DIR to
    # the same location within the chroot, which leaks the directory structure
    # of CF but this shouldn't be a big deal.
    minijail_chroot.add_binding(
        minijail.ChrootBinding(build_dir, build_dir, False))

    # AFL expects various things in /bin.
    minijail_chroot.add_binding(minijail.ChrootBinding('/bin', '/bin', False))

    # And /usr/bin.
    minijail_chroot.add_binding(
        minijail.ChrootBinding('/usr/bin', '/usr/bin', False))

    # Also bind the build dir to /out to make it easier to hardcode references
    # to data files.
    minijail_chroot.add_binding(
        minijail.ChrootBinding(build_dir, '/out', False))

    # map /proc/self/fd -> /dev/fd
    os.symlink('/proc/self/fd',
               os.path.join(minijail_chroot.directory, 'dev', 'fd'))

    runner = MinijailAflRunner(
        minijail_chroot,
        fuzzer_path,
        config,
        testcase_file_path,
        input_directory,
        timeout=timeout,
        strategy_dict=strategy_dict)

  else:
    runner = AflRunner(
        fuzzer_path,
        config,
        testcase_file_path,
        input_directory,
        timeout=timeout,
        strategy_dict=strategy_dict)

  # Make sure afl won't exit because of bad sanitizer options.
  set_additional_sanitizer_options_for_afl_fuzz()

  # Add *SAN_OPTIONS overrides from .options file.
  engine_common.process_sanitizer_options_overrides(fuzzer_path)

  return runner


def rand_schedule(scheduler_probs):
  """Returns a random queue scheduler."""
  schedule = 'fast'
  rnd = engine_common.get_probability()
  for schedule_opt, prob in scheduler_probs:
    if rnd > prob:
      rnd -= prob
    else:
      schedule = schedule_opt
      break
  return schedule


def rand_cmplog_level(strategies):
  """Returns a random CMPLOG intensity level."""
  cmplog_level = '2'
  rnd = engine_common.get_probability()
  for cmplog_level_opt, prob in strategies.CMPLOG_LEVEL_PROBS:
    if rnd > prob:
      rnd -= prob
    else:
      cmplog_level = cmplog_level_opt
      break
  if engine_common.decide_with_probability(strategies.CMPLOG_ARITH_PROB):
    cmplog_level += constants.CMPLOG_ARITH
  if engine_common.decide_with_probability(strategies.CMPLOG_TRANS_PROB):
    cmplog_level += constants.CMPLOG_TRANS
  return cmplog_level


# pylint: disable=too-many-function-args
def main(argv):
  """Run afl as specified by argv."""
  atexit.register(fuzzer_utils.cleanup)

  # Initialize variables.
  testcase_file_path = argv[1]
  target_name = environment.get_value('FUZZ_TARGET')
  input_directory = environment.get_value('FUZZ_CORPUS_DIR')

  # FIXME: Remove this once AFL is migrated to the new engine impl and runs in
  # same python process.
  logs.configure('run_fuzzer')
  _verify_system_config()
  profiler.start_if_needed('afl_launcher')

  build_directory = environment.get_value('BUILD_DIR')
  fuzzer_path = engine_common.find_fuzzer_path(build_directory, target_name)
  if not fuzzer_path:
    return

  # Install signal handler.
  signal.signal(signal.SIGTERM, engine_common.signal_term_handler)

  config = AflConfig.from_target_path(fuzzer_path)
  runner = prepare_runner(fuzzer_path, config, testcase_file_path,
                          input_directory)

  # If we don't have a corpus, then that means this is not a fuzzing run.
  if not input_directory:
    load_testcase_if_exists(runner, testcase_file_path)
    return

  # Execute afl-fuzz on the fuzzing target.
  fuzz_result = runner.fuzz()

  command = fuzz_result.command
  if environment.get_value('USE_MINIJAIL'):
    command = engine_common.strip_minijail_command(command,
                                                   runner.afl_fuzz_path)
  # Print info for the fuzzer logs.
  print(engine_common.get_log_header(command, fuzz_result.time_executed))

  print(fuzz_result.output)

  if fuzz_result.return_code:
    # If AFL returned a non-zero return code quit now without getting stats,
    # since they would be meaningless.
    print(runner.fuzzer_stderr)
    return

  stats_getter = stats.StatsGetter(runner.afl_output.stats_path,
                                   config.dict_path)
  try:
    new_units_generated, new_units_added, corpus_size = (
        runner.libfuzzerize_corpus())
    stats_getter.set_stats(fuzz_result.time_executed, new_units_generated,
                           new_units_added, corpus_size, runner.strategies,
                           runner.fuzzer_stderr, fuzz_result.output)

    engine_common.dump_big_query_data(stats_getter.stats, testcase_file_path,
                                      command)

  finally:
    print(runner.fuzzer_stderr)

  # Record the stats to make them easily searchable in stackdriver.
  if new_units_added:
    logs.log(
        'New units added to corpus: %d.' % new_units_added,
        stats=stats_getter.stats)
  else:
    logs.log('No new units found.', stats=stats_getter.stats)


if __name__ == '__main__':
  main(sys.argv)

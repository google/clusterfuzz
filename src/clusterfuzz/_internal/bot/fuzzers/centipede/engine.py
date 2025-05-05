# Copyright 2022 Google LLC
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
"""Centipede engine interface."""

from collections import namedtuple
import csv
import os
import pathlib
import re
import shutil
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from clusterfuzz._internal.bot.fuzzers import dictionary_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import options as fuzzer_options
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.centipede import constants
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell
from clusterfuzz.fuzz import engine
from clusterfuzz.stacktraces import constants as stacktraces_constants

_CLEAN_EXIT_SECS = 10

CRASH_REGEX = re.compile(r'[sS]aving input to:?\s*(.*)')
_CRASH_LOG_PREFIX = 'CRASH LOG: '
TargetBinaries = namedtuple('TargetBinaries', ['unsanitized', 'sanitized'])


class CentipedeError(Exception):
  """Base exception class."""


class CentipedeOptions(engine.FuzzOptions):
  """Centipede engine options."""

  def __init__(self, corpus_dir, arguments, strategies, workdir,
               new_corpus_dir):
    super().__init__(corpus_dir, arguments, strategies)
    # Directory to add new units
    self.new_corpus_dir = new_corpus_dir
    self.workdir = workdir


def _get_runner(target_path):
  """Gets the Centipede runner."""
  centipede_path = pathlib.Path(target_path).parent / 'centipede'
  if not centipede_path.exists():
    raise CentipedeError('Centipede not found in build')

  centipede_path = str(centipede_path)
  if environment.get_value('USE_UNSHARE'):
    return new_process.UnicodeModifierRunner(centipede_path)
  return new_process.UnicodeProcessRunner(centipede_path)


def _get_reproducer_path(log, reproducers_dir):
  """Gets the reproducer path, if any."""
  crash_match = CRASH_REGEX.search(log)
  if not crash_match:
    return None
  tmp_crash_path = pathlib.Path(crash_match.group(1))
  crash_path = pathlib.Path(reproducers_dir) / tmp_crash_path.name
  shutil.copy(tmp_crash_path, crash_path)
  return crash_path


def _set_sanitizer_options(fuzzer_path):
  """Sets sanitizer options based on .options file overrides."""
  engine_common.process_sanitizer_options_overrides(fuzzer_path)
  sanitizer_options_var = environment.get_current_memory_tool_var()
  sanitizer_options = environment.get_memory_tool_options(
      sanitizer_options_var, {})
  environment.set_memory_tool_options(sanitizer_options_var, sanitizer_options)


def _parse_centipede_stats(
    stats_file: str) -> Optional[Dict[str, Union[int, float]]]:
  """Parses the Centipede stats file and returns a dictionary with labels
  and their respective values.

  Args:
      stats_file: the path to Centipede stats file.

  Returns:
      a dictionary containing the stats.
  """
  try:
    with open(stats_file, 'r') as statsfile:
      csvreader = csv.reader(statsfile)
      rows = list(csvreader)
      # If the binary could not run at all, the file will be empty or with only
      # the column description line.
      if len(rows) <= 1:
        return None
      # The format we're parsing looks like this:
      # NumCoveredPcs_Min,NumCoveredPcs_Max,NumCoveredPcs_Avg,NumExecs_Min,[...]
      # 0,0,0,0,[...]
      # 123,1233,43234,5433
      # The stats a periodically dumped, hence there can be multiple lines. The
      # stats are cumulative, so taking the last line will give us the latest
      # numbers.
      desc = rows[0][:-1]
      latest_stats = rows[-1][:-1]

      def to_number(x: str) -> Union[int, float]:
        return int(x) if x.isdigit() else float(x)

      return {desc[i]: to_number(latest_stats[i]) for i in range(0, len(desc))}
  except Exception as e:
    logs.error(f'Failed to parse centipede stats file: {str(e)}')
    return None


def _parse_centipede_logs(log_lines: List[str]) -> Dict[str, int]:
  """Parses Centipede outputs and generates stats for it.

  Args:
      log_lines: the log lines.

  Returns:
      the stats.
  """
  stats = {
      'crash_count': 0,
      'timeout_count': 0,
      'oom_count': 0,
      'leak_count': 0,
  }
  for line in log_lines:
    if re.search(stacktraces_constants.CENTIPEDE_TIMEOUT_REGEX, line):
      stats['timeout_count'] = 1
      continue
    if re.search(stacktraces_constants.OUT_OF_MEMORY_REGEX, line):
      stats['oom_count'] = 1
      continue
    if re.search(CRASH_REGEX, line):
      stats['crash_count'] = 1
      continue
  return stats


class Engine(engine.Engine):
  """Centipede engine implementation."""

  @property
  def name(self):
    return 'centipede'

  def _get_arguments(self, fuzzer_path):
    """Gets the fuzzer arguments.
    Returns default arguments and arguments specified by the options field.
    Args:
      fuzzer_path: Path to the main target in a string.

    Returns:
      A FuzzerArguments object.
    """
    arguments = fuzzer_options.FuzzerArguments({})
    options = fuzzer_options.get_fuzz_target_options(fuzzer_path)

    if options:
      arguments = options.get_engine_arguments('centipede')

    # We ignore this parameter in the options file because it doesn't really
    # make sense not to crash on errors.
    arguments[constants.EXIT_ON_CRASH_FLAGNAME] = 1

    for key, val in constants.get_default_arguments().items():
      if key not in arguments:
        arguments[key] = val

    return arguments

  def fuzz_additional_processing_timeout(self, options):
    """Return the maximum additional timeout in seconds for additional
    operations in fuzz() (e.g. merging back new items).

    Args:
      options: A FuzzOptions object.

    Returns:
      An int representing the number of seconds required.
    """
    del options
    return engine_common.get_merge_timeout(engine_common.DEFAULT_MERGE_TIMEOUT)

  # pylint: disable=unused-argument
  def prepare(self, corpus_dir, target_path, build_dir):
    """Prepares for a fuzzing session, by generating options.

    Args:
      corpus_dir: The main corpus directory.
      target_path: Path to the target.
      build_dir: Path to the build directory.

    Returns:
      A FuzzOptions object.
   """
    arguments = self._get_arguments(target_path)
    dict_path = pathlib.Path(
        dictionary_manager.get_default_dictionary_path(target_path))
    if dict_path.exists():
      arguments[constants.DICTIONARY_FLAGNAME] = str(dict_path)

    # Directory workdir saves:
    # 1. Centipede-readable corpus file;
    # 2. Centipede-readable feature file;
    # 3. Crash reproducing inputs.
    workdir = engine_common.create_temp_fuzzing_dir('workdir')
    arguments[constants.WORKDIR_FLAGNAME] = str(workdir)

    # Directory to place new units. While fuzzing, the new corpus
    # elements are written to the first dir in the list of corpus directories.
    new_corpus_dir = engine_common.create_temp_fuzzing_dir('new')
    arguments[constants.CORPUS_DIR_FLAGNAME] = f'{new_corpus_dir},{corpus_dir}'

    target_binaries = self._get_binary_paths(target_path)
    if target_binaries.unsanitized is None:
      # Assuming the only binary is always sanitized (e.g., from Chrome).
      arguments[constants.BINARY_FLAGNAME] = str(target_binaries.sanitized)
      logs.warning('Unable to find unsanitized target binary.')
    else:
      arguments[constants.BINARY_FLAGNAME] = str(target_binaries.unsanitized)
      arguments[constants.EXTRA_BINARIES_FLAGNAME] = str(
          target_binaries.sanitized)

    return CentipedeOptions(corpus_dir, arguments.list(), {}, workdir,
                            new_corpus_dir)

  def _get_binary_paths(self, target_path):
    """Gets the paths to the main and auxiliary binaries based on |target_path|
    Args:
      target_path: Path to the main target in a string.

    Returns:
      A named tuple containing paths to both target binaries as pathlib.Path.
    """
    # Centipede expects one or two target binaries:
    # |-------------------------------------------------------|
    # |            | main target path | auxiliary target path |
    # |-------------------------------------------------------|
    # | 1 binary   | sanitized        | -                     |
    # |-------------------------------------------------------|
    # | 2 binaries | unsanitized      | sanitized             |
    # |-------------------------------------------------------|

    main_target_path = pathlib.Path(target_path)
    auxiliary_target_path = self._get_auxiliary_target_path(target_path)

    if main_target_path.exists() and auxiliary_target_path.exists():
      # 2 binaries were provided.
      target_binaries = TargetBinaries(main_target_path, auxiliary_target_path)
    elif main_target_path.exists():
      # 1 binary was provided.
      target_binaries = TargetBinaries(None, main_target_path)
    else:
      assert not auxiliary_target_path.exists()
      raise RuntimeError('No fuzz target: Centipede cannot find main target '
                         f'{main_target_path}, or auxiliary target '
                         f'{auxiliary_target_path}.')

    return target_binaries

  def _get_auxiliary_target_path(self, target_path):
    """Gets the auxiliary target path based on the main |target_path|.
    When exists, it points to the sanitized binary, which is required by fuzzing
    (as an auxiliary) and crash reproduction.

    Args:
      target_path: Path to the main target in a string.

    Returns:
      Path to the auxiliary binary as a pathlib.Path.
    """
    # Assuming they will be in child dirs named by fuzzer_utils.EXTRA_BUILD_DIR.
    build_dir = environment.get_value('BUILD_DIR')
    auxiliary_target_name = pathlib.Path(target_path).name
    auxiliary_target_path = pathlib.Path(
        build_dir, fuzzer_utils.EXTRA_BUILD_DIR, auxiliary_target_name)
    return auxiliary_target_path

  def fuzz(self, target_path, options, reproducers_dir, max_time):  # pylint: disable=unused-argument
    """Runs a fuzz session.

    Args:
      target_path: Path to the target.
      options: The FuzzOptions object returned by prepare().
      reproducers_dir: The directory to put reproducers in when crashes
          are found.
      max_time: Maximum allowed time for the fuzzing to run.

   Returns:
      A FuzzResult object.
    """
    runner = _get_runner(target_path)
    _set_sanitizer_options(target_path)
    timeout = max_time + _CLEAN_EXIT_SECS

    old_corpus_len = shell.get_directory_file_count(options.corpus_dir)
    logs.info(f'Corpus length before fuzzing: {old_corpus_len}')
    logs.info(f'Launching a fuzzer run with arguments: {options.arguments}')
    fuzz_result = runner.run_and_wait(
        additional_args=options.arguments, timeout=timeout)
    log_lines = fuzz_result.output.splitlines()
    fuzz_result.output = Engine.trim_logs(fuzz_result.output)

    logs.info('Fuzzing run completed.', fuzzing_logs=log_lines)

    workdir = options.workdir
    reproducer_path = _get_reproducer_path(fuzz_result.output, reproducers_dir)
    crashes = []
    if reproducer_path:
      # Centipde doesn't remove carshing inputs from the corpus, this workaround
      # removes the crashing input in case it's present in the corpus directory.
      crash_input_in_corpus = pathlib.Path(
          options.corpus_dir) / os.path.basename(reproducer_path)
      if crash_input_in_corpus.exists():
        crash_input_in_corpus.unlink()
        logs.info(f'Removed {crash_input_in_corpus} from the corpus')
      crashes.append(
          engine.Crash(
              str(reproducer_path), fuzz_result.output, [],
              int(fuzz_result.time_executed)))

    stats_filename = f'fuzzing-stats-{os.path.basename(target_path)}.000000.csv'

    stats_file = os.path.join(workdir, stats_filename)
    stats = _parse_centipede_stats(stats_file)
    if not stats:
      stats = {}
    actual_duration = int(
        stats.get('FuzzTimeSec_Avg', fuzz_result.time_executed or 0.0))
    fuzzing_time_percent = 100 * actual_duration / float(max_time)
    stats.update({
        'expected_duration': int(max_time),
        'actual_duration': actual_duration,
        'fuzzing_time_percent': fuzzing_time_percent,
    })
    fuzz_time_secs_avg = stats.get('FuzzTimeSec_Avg', 1.0)
    if fuzz_time_secs_avg == 0.0:
      fuzz_time_secs_avg = 1.0
    num_execs_avg = stats.get('NumExecs_Avg', 0.0)
    stats['average_exec_per_sec'] = num_execs_avg / fuzz_time_secs_avg
    stats.update(_parse_centipede_logs(log_lines))

    try:
      self.minimize_corpus(
          target_path=target_path,
          arguments=[],
          # New units, in addition to the main corpus units,
          # are placed in new_corpus_dir. Minimize and merge back
          # to the main corpus_dir.
          input_dirs=[options.new_corpus_dir],
          output_dir=options.corpus_dir,
          reproducers_dir=reproducers_dir,
          max_time=engine_common.get_merge_timeout(
              engine_common.DEFAULT_MERGE_TIMEOUT),
          # Use the same workdir that was used for fuzzing.
          # This allows us to skip rerunning the fuzzing inputs.
          workdir=workdir)
    except:
      # TODO(alhijazi): Convert to a warning if this becomes a problem
      # caused by user code rather than by ClusterFuzz or Centipede.
      logs.error('Corpus minimization failed.')
      # If we fail to minimize, fall back to moving the new units
      # from the new corpus_dir to the main corpus_dir.
      engine_common.move_mergeable_units(options.new_corpus_dir,
                                         options.corpus_dir)

    new_corpus_len = shell.get_directory_file_count(options.corpus_dir)
    logs.info(f'Corpus length after fuzzing: {new_corpus_len}')
    new_units_added = new_corpus_len - old_corpus_len
    stats['new_units_added'] = new_units_added
    return engine.FuzzResult(fuzz_result.output, fuzz_result.command, crashes,
                             stats, fuzz_result.time_executed)

  @staticmethod
  def trim_logs(fuzz_log):
    """Strips the 'CRASH LOG:' prefix that breaks stacktrace parsing.

    Args:
      fuzz_result: The ProcessResult returned by running fuzzer binary.
    """
    trimmed_log_lines = [
        line[len(_CRASH_LOG_PREFIX):]
        if line.startswith(_CRASH_LOG_PREFIX) else line
        for line in fuzz_log.splitlines()
    ]
    return '\n'.join(trimmed_log_lines)

  def reproduce(self, target_path, input_path, arguments, max_time):  # pylint: disable=unused-argument
    """Reproduces a crash given an input.

    Args:
      target_path: Path to the target.
      input_path: Path to the reproducer input.
      arguments: Additional arguments needed for reproduction.
      max_time: Maximum allowed time for the reproduction.

    Returns:
      A ReproduceResult.
    """
    _set_sanitizer_options(target_path)
    target_binaries = self._get_binary_paths(target_path)
    sanitized_target = str(target_binaries.sanitized)

    fuzzer_arguments = self._get_arguments(target_path)

    existing_runner_flags = os.environ.get('CENTIPEDE_RUNNER_FLAGS')
    if not existing_runner_flags:
      rss_limit = constants.RSS_LIMIT_MB_DEFAULT
      if constants.RSS_LIMIT_MB_FLAGNAME in fuzzer_arguments:
        rss_limit = fuzzer_arguments[constants.RSS_LIMIT_MB_FLAGNAME]
      timeout = constants.TIMEOUT_PER_INPUT_REPR_DEFAULT
      if constants.TIMEOUT_PER_INPUT_FLAGNAME in fuzzer_arguments:
        timeout = fuzzer_arguments[constants.TIMEOUT_PER_INPUT_FLAGNAME]
      os.environ['CENTIPEDE_RUNNER_FLAGS'] = (
          f':{constants.RSS_LIMIT_MB_FLAGNAME}={rss_limit}'
          f':{constants.TIMEOUT_PER_INPUT_FLAGNAME}={timeout}:')

    logs.info(
        'Attempting to reproduce',
        centipede_runner_flags=os.environ['CENTIPEDE_RUNNER_FLAGS'])

    if environment.get_value('FUZZTEST_MODE'):
      runner = new_process.UnicodeProcessRunner(sanitized_target)
      result = runner.run_and_wait(
          timeout=max_time, extra_env={'FUZZTEST_REPLAY': input_path})
    else:
      runner = new_process.UnicodeProcessRunner(sanitized_target, [input_path])
      result = runner.run_and_wait(timeout=max_time)

    if existing_runner_flags:
      os.environ['CENTIPEDE_RUNNER_FLAGS'] = existing_runner_flags
    else:
      os.unsetenv('CENTIPEDE_RUNNER_FLAGS')
    result.output = Engine.trim_logs(result.output)

    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

  def _strip_fuzzing_arguments(self, arguments):
    """Remove arguments only needed for fuzzing."""
    for argument in [
        constants.FORK_SERVER_FLAGNAME,
        constants.MAX_LEN_FLAGNAME,
        constants.NUM_RUNS_FLAGNAME,
        constants.EXIT_ON_CRASH_FLAGNAME,
        constants.BATCH_SIZE_FLAGNAME,
    ]:
      if argument in arguments:
        del arguments[argument]

    return arguments

  def minimize_corpus(self,
                      target_path,
                      arguments,
                      input_dirs,
                      output_dir,
                      reproducers_dir,
                      max_time,
                      workdir=None):
    """Runs corpus minimization.
    Args:
      target_path: Path to the target.
      arguments: Additional arguments needed for corpus minimization.
      input_dirs: Input corpora.
      output_dir: Output directory to place minimized corpus.
      reproducers_dir: The directory to put reproducers in when crashes are
          found.
      max_time: Maximum allowed time for the minimization.

    Returns:
      A FuzzResult object.
    """
    logs.info(f'Starting corpus minimization with timeout {max_time}.')
    runner = _get_runner(target_path)
    _set_sanitizer_options(target_path)

    minimize_arguments = self._get_arguments(target_path)
    self._strip_fuzzing_arguments(minimize_arguments)

    # Step 1: Generate corpus file for Centipede.
    # When calling this during a fuzzing session, use the existing workdir.
    # This avoids us having to re-run inputs and waste time unnecessarily.
    # This saves a lot of time when the input corpus contains thousands
    # of files.
    full_corpus_workdir = workdir
    if not full_corpus_workdir:
      full_corpus_workdir = engine_common.create_temp_fuzzing_dir(
          'full_corpus_workdir')
    input_dirs_param = ','.join(str(dir) for dir in input_dirs)
    args = minimize_arguments.list() + [
        f'--workdir={full_corpus_workdir}',
        f'--binary={target_path}',
        f'--corpus_dir={input_dirs_param}',
        '--num_runs=0',
    ]
    logs.info(f'Running Generate Corpus file for Centipede with args: {args}')
    result = runner.run_and_wait(additional_args=args, timeout=max_time)
    max_time -= result.time_executed

    if result.timed_out or max_time < 0:
      logs.warning(
          ('Corpus minimization timed out: Failed to generate Centipede corpus '
           'file'),
          fuzzer_output=result.output)
      raise TimeoutError('Minimization timed out.')

    # Step 2: Distill.
    args = minimize_arguments.list() + [
        f'--workdir={full_corpus_workdir}',
        f'--binary={target_path}',
        '--distill=true',
    ]
    logs.info(f'Running Corpus Distillation with args: {args}')
    result = runner.run_and_wait(additional_args=args, timeout=max_time)
    max_time -= result.time_executed

    if result.timed_out or max_time < 0:
      logs.warning(
          'Corpus minimization timed out: Failed to distill',
          fuzzer_output=result.output)
      raise TimeoutError('Minimization corpus timed out.')

    logs.info('Corpus distillation finished.', fuzzer_output=result.output)

    # Step 3: Generate corpus files for output_dir.
    os.makedirs(output_dir, exist_ok=True)
    minimized_corpus_workdir = engine_common.create_temp_fuzzing_dir(
        'minimized_corpus_workdir')
    logs.info(f'Created a temporary minimized corpus '
              f'workdir {minimized_corpus_workdir}')
    distilled_file = os.path.join(
        full_corpus_workdir,
        f'distilled-{os.path.basename(target_path)}.000000')
    corpus_file = os.path.join(minimized_corpus_workdir, 'corpus.000000')
    shutil.copyfile(distilled_file, corpus_file)

    args = minimize_arguments.list() + [
        f'--workdir={minimized_corpus_workdir}',
        f'--corpus_to_files={output_dir}',
    ]
    logs.info(f'Converting corpus to files with the following args: {args}')
    result = runner.run_and_wait(additional_args=args, timeout=max_time)

    if result.timed_out or max_time < 0:
      logs.warning(
          ('Corpus minimization timed out: Failed to generate output corpus '
           'files'),
          fuzzer_output=result.output)
      raise TimeoutError('Minimization timed out.')

    logs.info('Converted corpus to files.', fuzzer_output=result.output)

    # Step 4: Copy reproducers from full_corpus_workdir.
    os.makedirs(reproducers_dir, exist_ok=True)
    crashes_dir = os.path.join(full_corpus_workdir, 'crashes')

    if os.path.exists(crashes_dir):
      for file in os.listdir(crashes_dir):
        crasher_path = os.path.join(crashes_dir, file)
        shutil.copy(crasher_path, reproducers_dir)

    shutil.rmtree(minimized_corpus_workdir)
    if not workdir:
      # Only remove this directory if it was created in this method.
      shutil.rmtree(full_corpus_workdir)

    return engine.FuzzResult(result.output, result.command, [], None,
                             result.time_executed, result.timed_out)

  def _get_smallest_crasher(self, workdir_path):
    """Returns the path to the smallest crash in Centipede's |workdir_path|."""
    if not os.path.isdir(workdir_path):
      logs.error(f'Work directory does not exist: {workdir_path}')
      return None
    crashes_path = os.path.join(workdir_path, 'crashes')
    if not os.path.isdir(crashes_path):
      logs.error(f'Crashes directory does not exist: {crashes_path}')
      return None

    testcases = [
        os.path.join(crashes_path, t)
        for t in os.listdir(crashes_path)
        if os.path.isfile(os.path.join(crashes_path, t))
    ]
    if not testcases:
      logs.error(f'No crash testcases under: {crashes_path}')
      return None

    minimum_testcase = min(testcases, key=os.path.getsize)
    return minimum_testcase

  def minimize_testcase(self, target_path, arguments, input_path, output_path,
                        max_time):
    """Minimizes a testcase.
    Args:
      target_path: Path to the target.
      arguments: Additional arguments needed for testcase minimization.
      input_path: Path to the reproducer input.
      output_path: Path to the minimized output.
      max_time: Maximum allowed time for the minimization.
    Returns:
      A ReproduceResult.
    Raises:
      TimeoutError: If the testcase minimization exceeds max_time.
    """
    runner = _get_runner(target_path)
    workdir = engine_common.create_temp_fuzzing_dir('workdir')
    args = [
        f'--binary={target_path}',
        f'--workdir={workdir}',
        f'--minimize_crash={input_path}',
        f'--num_runs={constants.NUM_RUNS_PER_MINIMIZATION}',
        '--seed=1',
    ]
    result = runner.run_and_wait(additional_args=args, timeout=max_time)
    if result.timed_out:
      logs.warning(
          'Testcase minimization timed out.', fuzzer_output=result.output)
      raise TimeoutError('Minimization timed out.')
    minimum_testcase = self._get_smallest_crasher(workdir)
    if minimum_testcase:
      shutil.copyfile(minimum_testcase, output_path)
    else:
      shutil.copyfile(input_path, output_path)
    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

  def cleanse(self, target_path, arguments, input_path, output_path, max_time):
    """Cleanses a testcase.
    Args:
      target_path: Path to the target.
      arguments: Additional arguments needed for testcase cleanse.
      input_path: Path to the reproducer input.
      output_path: Path to the cleansed output.
      max_time: Maximum allowed time for the cleanse.
    Returns:
      A ReproduceResult.
    Raises:
      TimeoutError: If the cleanse exceeds max_time.
    """
    raise NotImplementedError

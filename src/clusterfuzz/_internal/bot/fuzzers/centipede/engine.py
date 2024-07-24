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
import os
import pathlib
import re
import shutil

from clusterfuzz._internal.bot.fuzzers import dictionary_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import options as fuzzer_options
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.centipede import constants
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz.fuzz import engine

_CLEAN_EXIT_SECS = 10

CRASH_REGEX = re.compile(r'[sS]aving input to:?\s*(.*)')
_CRASH_LOG_PREFIX = 'CRASH LOG: '
TargetBinaries = namedtuple('TargetBinaries', ['unsanitized', 'sanitized'])


class CentipedeError(Exception):
  """Base exception class."""


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
    workdir = self._create_temp_dir('workdir')
    arguments[constants.WORKDIR_FLAGNAME] = str(workdir)

    # Directory corpus_dir saves the corpus files required by ClusterFuzz.
    arguments[constants.CORPUS_DIR_FLAGNAME] = corpus_dir

    target_binaries = self._get_binary_paths(target_path)
    if target_binaries.unsanitized is None:
      # Assuming the only binary is always sanitized (e.g., from Chrome).
      arguments[constants.BINARY_FLAGNAME] = str(target_binaries.sanitized)
      logs.warning('Unable to find unsanitized target binary.')
    else:
      arguments[constants.BINARY_FLAGNAME] = str(target_binaries.unsanitized)
      arguments[constants.EXTRA_BINARIES_FLAGNAME] = str(
          target_binaries.sanitized)

    return engine.FuzzOptions(corpus_dir, arguments.list(), {})

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
    fuzz_result = runner.run_and_wait(
        additional_args=options.arguments, timeout=timeout)
    fuzz_result.output = Engine.trim_logs(fuzz_result.output)

    reproducer_path = _get_reproducer_path(fuzz_result.output, reproducers_dir)
    crashes = []
    if reproducer_path:
      crashes.append(
          engine.Crash(
              str(reproducer_path), fuzz_result.output, [],
              int(fuzz_result.time_executed)))

    # Stats report is not available in Centipede yet.
    stats = None
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

    existing_runner_flags = os.environ.get('CENTIPEDE_RUNNER_FLAGS')
    if not existing_runner_flags:
      rss_limit = constants.RSS_LIMIT_MB_DEFAULT
      timeout = constants.TIMEOUT_PER_INPUT_REPR_DEFAULT
      os.environ['CENTIPEDE_RUNNER_FLAGS'] = (
          f':{constants.RSS_LIMIT_MB_FLAGNAME}={rss_limit}'
          f':{constants.TIMEOUT_PER_INPUT_FLAGNAME}={timeout}:')

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

  def _create_temp_dir(self, name):
    """Creates temporary directory for fuzzing."""
    new_directory = pathlib.Path(fuzzer_utils.get_temp_dir(), name)
    engine_common.recreate_directory(new_directory)
    return new_directory

  def minimize_corpus(self, target_path, arguments, input_dirs, output_dir,
                      reproducers_dir, max_time):
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
    runner = _get_runner(target_path)

    # Step 1: Generate corpus file for Centipede.
    full_corpus_workdir = self._create_temp_dir('full_corpus_workdir')
    input_dirs_param = ','.join(str(dir) for dir in input_dirs)
    args = [
        f'--workdir={full_corpus_workdir}',
        f'--binary={target_path}',
        f'--corpus_dir={input_dirs_param}',
        '--num_runs=0',
    ]
    result = runner.run_and_wait(additional_args=args, timeout=max_time)
    max_time -= result.time_executed

    if result.timed_out or max_time < 0:
      logs.warning(
          ('Corpus minimization timed out: Failed to generate Centipede corpus '
           'file'),
          fuzzer_output=result.output)
      raise TimeoutError('Minimization timed out.')

    # Step 2: Distill.
    args = [
        f'--workdir={full_corpus_workdir}',
        f'--binary={target_path}',
        '--distill',
    ]
    result = runner.run_and_wait(additional_args=args, timeout=max_time)
    max_time -= result.time_executed

    if result.timed_out or max_time < 0:
      logs.warning(
          'Corpus minimization timed out: Failed to distill',
          fuzzer_output=result.output)
      raise TimeoutError('Minimization corpus timed out.')

    # Step 3: Generate corpus files for output_dir.
    os.makedirs(output_dir, exist_ok=True)
    minimized_corpus_workdir = self._create_temp_dir('minimized_corpus_workdir')
    distilled_file = os.path.join(
        full_corpus_workdir,
        f'distilled-{os.path.basename(target_path)}.000000')
    corpus_file = os.path.join(minimized_corpus_workdir, 'corpus.000000')
    shutil.copyfile(distilled_file, corpus_file)

    args = [
        f'--workdir={minimized_corpus_workdir}',
        f'--corpus_to_files={output_dir}',
    ]
    result = runner.run_and_wait(additional_args=args, timeout=max_time)

    if result.timed_out or max_time < 0:
      logs.warning(
          ('Corpus minimization timed out: Failed to generate output corpus '
           'files'),
          fuzzer_output=result.output)
      raise TimeoutError('Minimization timed out.')

    # Step 4: Copy reproducers from full_corpus_workdir.
    os.makedirs(reproducers_dir, exist_ok=True)
    crashes_dir = os.path.join(full_corpus_workdir, 'crashes')
    for file in os.listdir(crashes_dir):
      crasher_path = os.path.join(crashes_dir, file)
      shutil.copy(crasher_path, reproducers_dir)
    shutil.rmtree(full_corpus_workdir)
    shutil.rmtree(minimized_corpus_workdir)

    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

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
    workdir = self._create_temp_dir('workdir')
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

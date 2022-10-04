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

from pathlib import Path
import re
import shutil

from clusterfuzz._internal.bot.fuzzers import dictionary_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz.fuzz import engine

_CLEAN_EXIT_SECS = 10
_TIMEOUT = 25
_SERVER_COUNT = 1
_RSS_LIMIT = 4096
_RLIMIT_AS = 5120
_ADDRESS_SPACE_LIMIT = 0
_DEFAULT_ARGUMENTS = [
    '--exit_on_crash=1',
    f'--timeout={_TIMEOUT}',
    f'--fork_server={_SERVER_COUNT}',
    f'--rss_limit_mb={_RSS_LIMIT}',
    f'--address_space_limit_mb={_ADDRESS_SPACE_LIMIT}',
]

_CRASH_REGEX = re.compile(r'Crash detected, saving input to (.*)')


class CentipedeError(Exception):
  """Base exception class."""


def _get_runner():
  """Gets the Centipede runner."""
  centipede_path = Path(environment.get_value('BUILD_DIR'), 'centipede')
  if not centipede_path.exists():
    raise CentipedeError('Centipede not found in build')

  centipede_path = str(centipede_path)
  if environment.get_value('USE_UNSHARE'):
    return new_process.UnicodeModifierRunner(centipede_path)
  return new_process.UnicodeProcessRunner(centipede_path)


def _get_reproducer_path(log, reproducers_dir):
  """Gets the reproducer path, if any."""
  crash_match = _CRASH_REGEX.search(log)
  if not crash_match:
    return None
  tmp_crash_path = Path(crash_match.group(1))
  crash_path = Path(reproducers_dir) / tmp_crash_path.name
  shutil.copy(tmp_crash_path, crash_path)
  return crash_path


class Engine(engine.Engine):
  """Centipede engine implementation."""

  @property
  def name(self):
    return 'centipede'

  def prepare(self, corpus_dir, target_path, build_dir):
    """Prepares for a fuzzing session, by generating options.

    Args:
      corpus_dir: The main corpus directory.
      target_path: Path to the target.
      build_dir: Path to the build directory.

    Returns:
      A FuzzOptions object.
    """
    arguments = []
    dict_path = Path(
        dictionary_manager.get_default_dictionary_path(target_path))
    if dict_path.exists():
      arguments.append(f'--dictionary={dict_path}')

    # Directory workdir saves:
    # 1. Centipede-readable corpus file;
    # 2. Centipede-readable feature file;
    # 3. Crash reproducing inputs.
    workdir = self._create_temp_dir('workdir')
    arguments.append(f'--workdir={workdir}')

    # Directory corpus_dir saves the corpus files required by ClusterFuzz.
    arguments.append(f'--corpus_dir={corpus_dir}')

    # The unsanitized binary, Centipede requires it to be the main fuzz target.
    arguments.append(f'--binary={target_path}')

    # Extra sanitized binaries, Centipede requires to build them separately.
    # Assuming they will be in child dirs named by fuzzer_utils.EXTRA_BUILD_DIR.
    sanitized_target_name = Path(target_path).name
    sanitized_target_path = Path(build_dir, fuzzer_utils.EXTRA_BUILD_DIR,
                                 sanitized_target_name)
    if sanitized_target_path.exists():
      arguments.append(f'--extra_binaries={sanitized_target_path}')
    else:
      logs.log_warn('Unable to find sanitized target binary.')

    return engine.FuzzOptions(corpus_dir, arguments, {})

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
    runner = _get_runner()
    arguments = _DEFAULT_ARGUMENTS.copy()
    arguments.extend(options.arguments)

    timeout = max_time + _CLEAN_EXIT_SECS
    fuzz_result = runner.run_and_wait(
        additional_args=arguments, timeout=timeout)

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
    runner = new_process.UnicodeProcessRunner(target_path, [input_path])
    result = runner.run_and_wait(timeout=max_time)

    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

  def _create_temp_dir(self, name):
    """Creates temporary directory for fuzzing."""
    new_directory = Path(fuzzer_utils.get_temp_dir(), name)
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
    raise NotImplementedError

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
    raise NotImplementedError

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

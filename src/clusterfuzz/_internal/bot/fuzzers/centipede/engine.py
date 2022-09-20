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

import glob
import os
import re
import shutil

from pathlib import Path

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import dictionary_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell
from clusterfuzz.fuzz import engine

_CLEAN_EXIT_SECS = 10
_TIMEOUT = 1200
_SERVER_COUNT = 1
_RSS_LIMIT = 4096
_RLIMIT_AS = 5120
_ADDRESS_SPACE_LIMIT = 0
_DEFAULT_ARGUMENTS = [
    '--exit_on_crash=1',  # I guess this should set to exit on crash?
    f'--timeout={_TIMEOUT}',
    f'--fork_server={_SERVER_COUNT}',
    f'--rss_limit_mb={_RSS_LIMIT}',
    f'--rlimit_as_mb={_RLIMIT_AS}',
    f'--address_space_limit_mb={_ADDRESS_SPACE_LIMIT}',
]

_CRASH_REGEX = re.compile(
    'centipede.cc:572] ReportCrash[0]: crash detected, saving input to (.*)')


class CentipedeError(Exception):
  """Base exception class."""


def _get_runner():
  """Get the Centipede runner."""
  centipede_path = os.path.join(environment.get_value('BUILD_DIR'), 'centipede')
  if not os.path.exists(centipede_path):
    raise CentipedeError('Centipede not found in build')

  os.chmod(centipede_path, 0o755)
  if environment.get_value('USE_UNSHARE'):
    return new_process.UnicodeModifierRunner(centipede_path)

  return new_process.UnicodeProcessRunner(centipede_path)


def _get_reproducer_path(line):
  """Get the reproducer path, if any."""
  crash_match = _CRASH_REGEX.match(line)
  if not crash_match:
    return None

  return crash_match.group(1)


class Engine(engine.Engine):
  """Centipede engine implementation."""

  @property
  def name(self):
    return 'centipede'

  def prepare(self, corpus_dir, target_path, build_dir):  # pylint: disable=unused-argument
    """Prepare for a fuzzing session, by generating options. Returns a
    FuzzOptions object.

    Args:
      corpus_dir: The main corpus directory.
      target_path: Path to the target.
      build_dir: Path to the build directory.

    Returns:
      A FuzzOptions object.
    """
    os.chmod(target_path, 0o775)
    arguments = []
    dict_path = dictionary_manager.get_default_dictionary_path(target_path)
    if os.path.exists(dict_path):
      arguments.append(f'--dictionary={dict_path}')

    # Is it OK to create workdir with this function?
    # workdir saves centipede-readable corpus&feature files, and crashes
    workdir = _create_temp_dir('workdir')
    # Will the workdir always exist?
    arguments.append(f'--workdir={workdir}')

    # Will the corpus directory always exist?
    Path(corpus_dir).mkdir(exist_ok=True)
    arguments.append(f'--corpus_dir={corpus_dir}')

    # Download sanitized binaries.
#  for stacktrace_path in glob.glob(
#      os.path.join(reproducers_dir, _HF_SANITIZER_LOG_PREFIX + '*')):
    sanitized_binaries = [
        sanitized_binary for sanitized_binary in
        glob.glob(os.path.join(build_dir, '*_*', os.path.basename(target_path)))
    ]
    arguments.append(f'--extra_binaries={",".join(sanitized_binaries)}')

    return engine.FuzzOptions(corpus_dir, arguments, {})

  def fuzz(self, target_path, options, reproducers_dir, max_time):
    """Run a fuzz session.

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
    arguments = _DEFAULT_ARGUMENTS[:]
    arguments.extend(options.arguments)
    arguments.extend([
        f'--binary={target_path}',
    ])

    fuzz_result = runner.run_and_wait(
        additional_args=arguments,
        timeout=max_time + _CLEAN_EXIT_SECS,
        extra_env=centipede_env)
    log_lines = fuzz_result.output.splitlines()
    fuzz_logs = '\n'.join(log_lines)

    crashes = []
    # Stats report is not available in Centipede yet
    stats = None
    for line in log_lines:
      reproducer_path = _get_reproducer_path(line)
      if reproducer_path:

        crashes.append(engine.Crash(
            reproducer_path, fuzz_logs, [], int(fuzz_result.time_executed)))
        continue

      #stats = _get_stats(line)

    #if stats is None:
    #  stats = {}

    return engine.FuzzResult(fuzz_result.output, fuzz_result.command, crashes,
                             stats, fuzz_result.time_executed)

  def reproduce(self, target_path, input_path, arguments, max_time):  # pylint: disable=unused-argument
    """Reproduce a crash given an input.

    Args:
      target_path: Path to the target.
      input_path: Path to the reproducer input.
      arguments: Additional arguments needed for reproduction.
      max_time: Maximum allowed time for the reproduction.

    Returns:
      A ReproduceResult.
    """
    os.chmod(target_path, 0o775)
    runner = new_process.UnicodeProcessRunner(target_path)
    with open(input_path, 'rb') as f:
      result = runner.run_and_wait(timeout=max_time, stdin=f)

    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

  def _create_temp_dir(self, name):
    """Creates temporary corpus directory."""
    new_directory = os.path.join(fuzzer_utils.get_temp_dir(), name)
    engine_common.recreate_directory(new_directory)
    return new_directory

  def minimize_corpus(self, target_path, arguments, input_dirs, output_dir,
                      reproducers_dir, max_time):
    """Optional (but recommended): run corpus minimization.

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
    """Not yet implemented by Centipede"""
    raise NotImplementedError


  def minimize_testcase(self, target_path, arguments, input_path, output_path,
                        max_time):
    """Optional (but recommended): Minimize a testcase.
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
    """Not yet implemented by Centipede"""
    raise NotImplementedError

  def cleanse(self, target_path, arguments, input_path, output_path, max_time):
    """Optional (but recommended): Cleanse a testcase.
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
    """Not yet implemented by Centipede"""
    raise NotImplementedError

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
"""honggfuzz engine interface."""

import glob
import os
import re

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import dictionary_manager
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz.fuzz import engine

_CLEAN_EXIT_SECS = 10
_RSS_LIMIT = 2560
_TIMEOUT = 25
_DEFAULT_ARGUMENTS = [
    '-n',
    '1',  # single threaded
    '--exit_upon_crash',
    '-v',  # output to stderr
    '-z',  # use clang instrumentation
    '-P',  # persistent mode
    '-S',  # enable sanitizers
    '--rlimit_rss',
    str(_RSS_LIMIT),
    '--timeout',
    str(_TIMEOUT),
]

_CRASH_REGEX = re.compile('Crash: saved as \'(.*)\'')
_HF_SANITIZER_LOG_PREFIX = 'HF.sanitizer.log'
_STATS_PREFIX = 'Summary '


class HonggfuzzError(Exception):
  """Base exception class."""


def _get_runner():
  """Get the honggfuzz runner."""
  honggfuzz_path = os.path.join(environment.get_value('BUILD_DIR'), 'honggfuzz')
  if not os.path.exists(honggfuzz_path):
    raise HonggfuzzError('honggfuzz not found in build')

  os.chmod(honggfuzz_path, 0o755)
  return new_process.UnicodeProcessRunner(honggfuzz_path)


def _find_sanitizer_stacktrace(reproducers_dir):
  """Find the sanitizer stacktrace from the reproducers dir."""
  for stacktrace_path in glob.glob(
      os.path.join(reproducers_dir, _HF_SANITIZER_LOG_PREFIX + '*')):
    with open(stacktrace_path, 'rb') as f:
      return utils.decode_to_unicode(f.read())

  return None


def _get_reproducer_path(line):
  """Get the reproducer path, if any."""
  crash_match = _CRASH_REGEX.match(line)
  if not crash_match:
    return None

  return crash_match.group(1)


def _get_stats(line):
  """Get stats, if any."""
  if not line.startswith(_STATS_PREFIX):
    return None

  parts = line[len(_STATS_PREFIX):].split()
  stats = {}

  for part in parts:
    if ':' not in part:
      logs.log_error('Invalid stat part.', value=part)

    key, value = part.split(':', 2)
    try:
      stats[key] = int(value)
    except (ValueError, TypeError):
      logs.log_error('Invalid stat value.', key=key, value=value)

  return stats


class HonggfuzzEngine(engine.Engine):
  """honggfuzz engine implementation."""

  @property
  def name(self):
    return 'honggfuzz'

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
      arguments.extend(['--dict', dict_path])

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
        '--input',
        options.corpus_dir,
        '--workspace',
        reproducers_dir,
        '--run_time',
        str(max_time),
        '--',
        target_path,
    ])

    fuzz_result = runner.run_and_wait(
        additional_args=arguments, timeout=max_time + _CLEAN_EXIT_SECS)
    log_lines = fuzz_result.output.splitlines()
    sanitizer_stacktrace = _find_sanitizer_stacktrace(reproducers_dir)

    crashes = []
    stats = None
    for line in log_lines:
      reproducer_path = _get_reproducer_path(line)
      if reproducer_path:
        crashes.append(
            engine.Crash(reproducer_path, sanitizer_stacktrace or '', [],
                         int(fuzz_result.time_executed)))
        continue

      stats = _get_stats(line)

    if stats is None:
      stats = {}

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
    with open(input_path) as f:
      result = runner.run_and_wait(timeout=max_time, stdin=f)

    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

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
    # TODO(ochang): Implement this.
    raise NotImplementedError

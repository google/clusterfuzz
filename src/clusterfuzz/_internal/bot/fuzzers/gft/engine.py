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

import os
import re

from clusterfuzz._internal.system import new_process
from clusterfuzz.fuzz import engine

_CRASH_REGEX = re.compile(r'^Reproducer file written to\s*(.*)$')


class GFTError(Exception):
  """Base exception class."""


def _get_reproducer_path(line):
  """Get the reproducer path, if any."""
  crash_match = _CRASH_REGEX.match(line)
  if not crash_match:
    return None

  return crash_match.group(1)


class GFTEngine(engine.Engine):
  """GFT engine implementation."""

  @property
  def name(self):
    return 'gft'

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
    return engine.FuzzOptions(corpus_dir, [], {})

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
    runner = new_process.UnicodeProcessRunner(target_path)

    fuzz_result = runner.run_and_wait(
        timeout=max_time,
        extra_env={
            'FUZZTEST_DB': options.corpus_dir,
        },
        cwd=reproducers_dir)
    log_lines = fuzz_result.output.splitlines()

    crashes = []
    for line in log_lines:
      reproducer_path = _get_reproducer_path(line)
      if reproducer_path:
        crashes.append(
            engine.Crash(reproducer_path, fuzz_result.output, [],
                         int(fuzz_result.time_executed)))
        continue

    # TODO(ochang): Implement this.
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
    result = runner.run_and_wait(
        timeout=max_time, extra_env={'FUZZTEST_REPLAY': input_path})

    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

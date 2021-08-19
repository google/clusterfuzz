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
"""GFT engine interface."""

import os
import re

from clusterfuzz._internal.system import new_process
from clusterfuzz.fuzz import engine

_CRASH_REGEX = re.compile(r'.*Reproducer file written to:\s*(.*)$')


class GoogleFuzzTestError(Exception):
  """Base exception class."""


def _get_reproducer_path(line):
  """Get the reproducer path, if any."""
  crash_match = _CRASH_REGEX.match(line)
  if not crash_match:
    return None

  return crash_match.group(1)


class GoogleFuzzTestEngine(engine.Engine):
  """GFT engine implementation."""

  @property
  def name(self):
    return 'googlefuzztest'

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
    del options  # Unused.
    runner = new_process.UnicodeProcessRunner(target_path)

    fuzz_result = runner.run_and_wait(
        timeout=max_time,
        extra_env={
            'FUZZTEST_REPRODUCERS_OUT_DIR': reproducers_dir,
        })
    log_lines = fuzz_result.output.splitlines()

    crashes = []
    for line in log_lines:
      reproducer_path = _get_reproducer_path(line)
      if reproducer_path:
        crashes.append(
            engine.Crash(
                reproducer_path,
                fuzz_result.output,
                reproduce_args=[],
                crash_time=int(fuzz_result.time_executed)))
        continue

    # TODO(ochang): Implement stats parsing.
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

    Raises:
      TimeoutError: If the corpus minimization exceeds max_time.
      Error: If the merge failed in some other way.
    """
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
    raise NotImplementedError

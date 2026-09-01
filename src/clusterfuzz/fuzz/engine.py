# Copyright 2020 Google LLC
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
"""Fuzzing engine interface."""

from typing import Any

_ENGINES: dict[str, type['Engine']] = {}


class Error(Exception):
  """Engine error."""


class FuzzOptions:
  """Represents options passed to the engine. Can be overridden to provide more
  options."""

  corpus_dir: str
  arguments: list[str]
  strategies: Any

  def __init__(self, corpus_dir: str, arguments: list[str],
               strategies: Any) -> None:
    self.corpus_dir = corpus_dir
    self.arguments = arguments
    self.strategies = strategies


class Crash:
  """Represents a crash found by the fuzzing engine."""

  input_path: str
  stacktrace: str
  reproduce_args: list[str]
  crash_time: float

  def __init__(self, input_path: str, stacktrace: str,
               reproduce_args: list[str], crash_time: float) -> None:
    self.input_path = input_path
    self.stacktrace = stacktrace
    self.reproduce_args = reproduce_args
    self.crash_time = crash_time


class FuzzResult:
  """Represents a result of a fuzzing session: a list of crashes found and the
  stats generated."""

  logs: str
  command: Any
  crashes: list[Crash]
  stats: Any
  time_executed: Any
  timed_out: bool | None

  def __init__(self,
               logs: str,
               command: Any,
               crashes: list[Crash],
               stats: Any,
               time_executed: Any,
               timed_out: bool | None = None) -> None:
    self.logs = logs
    self.command = command
    self.crashes = crashes
    self.stats = stats
    self.time_executed = time_executed
    self.timed_out = timed_out


class ReproduceResult:
  """Results from running a testcase against a target."""

  command: Any
  return_code: Any
  time_executed: Any
  output: str

  def __init__(self, command: Any, return_code: Any, time_executed: Any,
               output: str) -> None:
    self.command = command
    self.return_code = return_code
    self.time_executed = time_executed
    self.output = output


class Engine:
  """Base interface for a grey box fuzzing engine."""

  do_strategies: bool

  def __init__(self) -> None:
    self.do_strategies = True

  @property
  def name(self) -> str:
    """Get the name of the engine."""
    raise NotImplementedError

  def fuzz_additional_processing_timeout(self, options: Any) -> int:
    """Return the maximum additional timeout in seconds for additional
    operations in fuzz() (e.g. merging back new items).

    Args:
      options: A FuzzOptions object.

    Returns:
      An int representing the number of seconds required.
    """
    del options
    return 0

  def prepare(self, corpus_dir: str, target_path: str,
              build_dir: str) -> FuzzOptions:
    """Prepare for a fuzzing session, by generating options. Returns a
    FuzzOptions object.

    Args:
      corpus_dir: The main corpus directory.
      target_path: Path to the target.
      build_dir: Path to the build directory.

    Returns:
      A FuzzOptions object.
    """
    raise NotImplementedError

  def fuzz(self, target_path: str, options: Any, reproducers_dir: str,
           max_time: Any) -> FuzzResult:
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
    raise NotImplementedError

  def reproduce(self, target_path: str, input_path: str, arguments: list[str],
                max_time: Any) -> ReproduceResult:
    """Reproduce a crash given an input.

    Args:
      target_path: Path to the target.
      input_path: Path to the reproducer input.
      arguments: Additional arguments needed for reproduction.
      max_time: Maximum allowed time for the reproduction.

    Returns:
      A ReproduceResult.

    Raises:
      TimeoutError: If the reproduction exceeds max_time.
    """
    raise NotImplementedError

  def minimize_corpus(self, target_path: str, arguments: list[str],
                      input_dirs: list[str], output_dir: str,
                      reproducers_dir: str, max_time: Any) -> FuzzResult:
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

  def minimize_testcase(self, target_path: str, arguments: list[str],
                        input_path: str, output_path: str,
                        max_time: Any) -> ReproduceResult:
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

  def cleanse(self, target_path: str, arguments: list[str], input_path: str,
              output_path: str, max_time: Any) -> ReproduceResult:
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


def register(name: str, engine_class: type[Engine]) -> None:
  """Register a fuzzing engine."""
  if name in _ENGINES:
    raise ValueError('Engine {name} is already registered'.format(name=name))

  _ENGINES[name] = engine_class


def get(name: str | None) -> Engine | None:
  """Gets an implementation of a fuzzing engine, or None if one does not
  exist."""
  if not name:
    return None
  engine_class = _ENGINES.get(name)
  if engine_class:
    return engine_class()

  return None

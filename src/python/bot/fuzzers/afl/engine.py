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
"""AFL engine interface."""
import os

from bot.fuzzers import engine_common
from bot.fuzzers.afl import launcher
from bot.fuzzers.afl import stats
from lib.clusterfuzz.fuzz import engine
from system import environment


def _get_command_from_fuzz_result(fuzz_result, runner):
  """Get the command string without showing unnecessary minijail commands."""
  command = fuzz_result.command
  if environment.get_value('USE_MINIJAIL'):
    command = engine_common.strip_minijail_command(command,
                                                   runner.afl_fuzz_path)

  return command


class AFLEngine(engine.Engine):
  """AFL engine implementation."""

  @property
  def name(self):
    return 'afl'

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
    afl_config = launcher.AflConfig.from_target_path(target_path)
    arguments = afl_config.additional_afl_arguments
    # TODO(mbarbella): Select all strategies here instead of deferring to fuzz.
    strategies = launcher.FuzzingStrategies(target_path).to_strategy_dict()
    return engine.FuzzOptions(corpus_dir, arguments, strategies)

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
    environment.set_value('FUZZ_TEST_TIMEOUT', max_time)

    config = launcher.AflConfig.from_target_path(target_path)
    config.additional_afl_arguments = options.arguments
    testcase_file_path = os.path.join(reproducers_dir, 'testcase')

    runner = launcher.prepare_runner(
        target_path,
        config,
        testcase_file_path,
        options.corpus_dir,
        strategy_dict=options.strategies)

    fuzz_result = runner.fuzz()

    command = _get_command_from_fuzz_result(fuzz_result, runner)
    time_executed = fuzz_result.time_executed
    logs = fuzz_result.output.splitlines() + runner.fuzzer_stderr.splitlines()

    # Bail out if AFL returns a nonzero status code.
    if fuzz_result.return_code:
      return engine.FuzzResult(logs, command, [], {}, time_executed)

    stats_getter = stats.StatsGetter(runner.afl_output.stats_path,
                                     config.dict_path)
    new_units_generated, new_units_added, corpus_size = (
        runner.libfuzzerize_corpus())
    stats_getter.set_stats(fuzz_result.time_executed, new_units_generated,
                           new_units_added, corpus_size, runner.strategies,
                           runner.fuzzer_stderr, fuzz_result.output)
    stats = stats_getter.stats

    # TODO(mbarbella): This will not continue fuzzing properly when a crash is
    # found. Address this when refactoring the launcher to remove the old
    # codepath.
    crashes = []
    if os.path.exists(testcase_file_path):
      crash = engine.Crash(testcase_file_path, fuzz_result.output, [],
                           fuzz_result.crash_time)
      crashes.append(crash)

    return engine.FuzzResult(logs, command, crashes, stats, time_executed)

  def reproduce(self, target_path, input_path, arguments, max_time):
    """Reproduce a crash given an input.

    Args:
      target_path: Path to the target.
      input_path: Path to the reproducer input.
      arguments: Additional arguments needed for reproduction.
      max_time: Maximum allowed time for the reproduction.

    Returns:
      A ReproduceResult.
    """
    environment.set_value('FUZZ_TEST_TIMEOUT', max_time)

    config = launcher.AflConfig.from_target_path(target_path)
    input_directory = None  # Not required for reproduction.
    runner = launcher.prepare_runner(target_path, config, input_path,
                                     input_directory)

    launcher.load_testcase_if_exists(runner, input_path)
    fuzz_result = runner.fuzz()

    command = _get_command_from_fuzz_result(fuzz_result, runner)
    return_code = fuzz_result.return_code
    time_executed = fuzz_result.time_executed
    output = '\n'.join([fuzz_result.output, runner.fuzzer_stderr])

    return engine.ReproduceResult(command, return_code, time_executed, output)

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
    # TODO(mbarbella): Implement this.
    raise NotImplementedError

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
import stat

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.afl import launcher
from clusterfuzz._internal.bot.fuzzers.afl import stats
from clusterfuzz._internal.metrics import logs
from clusterfuzz.fuzz import engine


def _run_single_testcase(fuzzer_runner, testcase_file_path):
  """Loads a crash testcase if it exists."""
  # To ensure that we can run the fuzzer.
  os.chmod(fuzzer_runner.executable_path, stat.S_IRWXU | stat.S_IRGRP
           | stat.S_IXGRP)

  return fuzzer_runner.run_single_testcase(testcase_file_path)


class AFLEngine(engine.Engine):
  """AFL engine implementation."""

  @property
  def name(self):
    return 'afl'

  def prepare(self, corpus_dir, target_path, build_dir):  # pylint: disable=unused-argument
    """Prepare for a fuzzing session, by generating options.

    Returns a FuzzOptions object.

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

    if self.do_strategies:
      strategies = launcher.FuzzingStrategies(target_path).to_strategy_dict()
    else:
      strategies = {}

    return engine.FuzzOptions(corpus_dir, arguments, strategies)

  def fuzz(self, target_path, options, reproducers_dir, max_time):
    """Run a fuzz session.

    Args:
      target_path: Path to the target.
      options: The FuzzOptions object returned by prepare().
      reproducers_dir: The directory to put reproducers in when crashes are
        found.
      max_time: Maximum allowed time for the fuzzing to run.

   Returns:
      A FuzzResult object.
    """
    config = launcher.AflConfig.from_target_path(target_path)
    config.additional_afl_arguments = options.arguments

    testcase_file_path = os.path.join(reproducers_dir, 'crash')
    runner = launcher.prepare_runner(
        target_path,
        config,
        testcase_file_path,
        options.corpus_dir,
        max_time,
        strategy_dict=options.strategies)

    fuzz_result = runner.fuzz()

    command = fuzz_result.command
    time_executed = fuzz_result.time_executed
    fuzzing_logs = fuzz_result.output + runner.fuzzer_stderr

    # Bail out if AFL returns a nonzero status code.
    if fuzz_result.return_code:
      target = engine_common.get_project_qualified_fuzzer_name(target_path)
      logs.log_error(
          f'afl: engine encountered an error (target={target})',
          engine_output=fuzz_result.output)
      return engine.FuzzResult(fuzzing_logs, command, [], {}, time_executed)

    stats_getter = stats.StatsGetter(runner.afl_output.stats_path,
                                     config.dict_path)
    new_units_generated, new_units_added, corpus_size = (
        runner.libfuzzerize_corpus())
    stats_getter.set_stats(fuzz_result.time_executed, new_units_generated,
                           new_units_added, corpus_size, runner.strategies,
                           runner.fuzzer_stderr, fuzz_result.output)

    crashes = []
    if os.path.exists(testcase_file_path):
      crash = engine.Crash(testcase_file_path, runner.fuzzer_stderr, [],
                           fuzz_result.time_executed)
      crashes.append(crash)

    return engine.FuzzResult(fuzzing_logs, command, crashes, stats_getter.stats,
                             time_executed)

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
    del arguments
    del max_time
    config = launcher.AflConfig.from_target_path(target_path)
    input_directory = None  # Not required for reproduction.
    runner = launcher.prepare_runner(target_path, config, input_path,
                                     input_directory)

    reproduce_result = _run_single_testcase(runner, input_path)

    command = reproduce_result.command
    return_code = reproduce_result.return_code
    time_executed = reproduce_result.time_executed
    output = runner.fuzzer_stderr

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

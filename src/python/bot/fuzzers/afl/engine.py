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

from bot.fuzzers.afl import launcher
from lib.clusterfuzz.fuzz import engine


# TODO(mbarbella): Remove this check once this file is fully implemented.
# pylint: disable=unused-variable
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
    afl_config = launcher.AFLConfig.from_target_path(target_path)
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
    config = launcher.AFLConfig.from_target_path(target_path)
    config.additional_afl_arguments = options.arguments
    input_path = None  # Not required for fuzzing.
    runner = launcher.prepare_runner(
        target_path,
        config,
        input_path,
        options.corpus_dir,
        strategy_dict=options.strategies)

    # TODO(mbarbella): Use the runner to start a fuzzing session.
    raise NotImplementedError

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
    config = launcher.AFLConfig.from_target_path(target_path)
    input_directory = None  # Not required for reproduction.
    runner = launcher.prepare_runner(target_path, config, input_path,
                                     input_directory)

    # TODO(mbarbella): Use the runner to reproduce the test case.
    raise NotImplementedError

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

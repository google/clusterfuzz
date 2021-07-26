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
"""Fuzzing engine definition for generic blackbox fuzzers."""

import os

from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell
from clusterfuzz.fuzz import engine

TESTCASE_PREFIX = 'fuzz-'
OUTPUT_PREFIX = 'output-'


def _get_arguments(app_path, app_args):
  """Get arguments shared between multiple run types."""
  return [f'--app_path={app_path}', f'--app_args={app_args}']


def _run_with_interpreter_if_needed(fuzzer_path, args, max_time):
  """Execute the fuzzer script with an interpreter, or invoke it directly."""
  interpreter = shell.get_interpreter(fuzzer_path)
  if interpreter:
    executable = interpreter
    args.insert(0, fuzzer_path)
  else:
    executable = fuzzer_path

  runner = new_process.UnicodeProcessRunner(executable)
  return runner.run_and_wait(timeout=max_time, additional_args=args)


class BlackboxEngine(engine.Engine):
  """Generic blackbox fuzzer engine implementation.

  Blackbox fuzzers are scripts which accept the following arguments:
    --app_path: The path to a binary which will be invoked when testing.
    --app_args: Arguments to pass to the test binary.
    --input_dir: An optional corpus containing test data.
    --output_dir: If specified, write generated test cases to this directory
                  along with their output. This is specified during fuzzing but
                  not reproduction. Only the crashes must be written, but
                  crashes will be identified automatically if the fuzzer does
                  not detect them itself. Tests should have the prefix "fuzz-",
                  and their output should have the same name as the test but
                  with the prefix "output-" instead of "fuzz-".
    --testcase_path: If specified, a path to a test case to reproduce. Output
                     should be written directly to stdout or stderr.
  """

  @property
  def name(self):
    return 'blackbox'

  def prepare(self, corpus_dir, target_path, build_dir):  # pylint: disable=unused-argument
    """Prepare for a fuzzing session by generating options.

    Though blackbox fuzzers follow the engine interface, they must be launched
    in a different manner from most other engine fuzzers. Instead of running a
    target directly, these fuzzers tend to be wrapper scripts which generate
    test cases and pass them to a binary that is managed by the infrastructure.

    Args:
      corpus_dir: The main corpus directory.
      target_path: Path to the fuzzer script or binary.
      build_dir: Path to the build directory.
    Returns:
      A FuzzOptions object.
    """
    return engine.FuzzOptions(corpus_dir, [], {})

  # TODO(mbarbella): As implemented, this will not work for untrusted workers.
  # We would need to copy fuzzer binaries to workers.
  def fuzz(self, target_path, options, reproducers_dir, max_time):
    """Run a fuzzing session.
    Args:
      target_path: Path to the fuzzer script or binary.
      options: The FuzzOptions object returned by prepare().
      reproducers_dir: The directory to put reproducers in when crashes
          are found.
      max_time: Maximum allowed time for the fuzzing to run.
   Returns:
      A FuzzResult object.
    """
    # For blackbox fuzzers, |target_path| supplies the path to the fuzzer script
    # rather than a target in the build archive.
    fuzzer_path = target_path
    os.chmod(fuzzer_path, 0o775)

    app_path = environment.get_value('APP_PATH')
    app_args = testcase_manager.get_command_line_for_application(
        get_arguments_only=True).strip()
    corpus_dir = options.corpus_dir
    command_line_args = _get_arguments(app_path, app_args)
    command_line_args.append(f'--input_dir={corpus_dir}')

    result = _run_with_interpreter_if_needed(fuzzer_path, command_line_args,
                                             max_time)
    crashes = []
    for testcase_path in os.listdir(reproducers_dir):
      if not testcase_path.startswith(TESTCASE_PREFIX):
        continue

      output_path = OUTPUT_PREFIX + testcase_path[len(TESTCASE_PREFIX):]
      absolute_output_path = os.path.join(reproducers_dir, output_path)

      # If no output was written for a test case, skip it.
      if not os.path.exists(absolute_output_path):
        continue

      with open(absolute_output_path, 'r', errors='replace') as handle:
        output = handle.read()

      # Filter obviously non-crashing test cases. Crashes still follow the
      # normal flow in fuzz task to ensure that the state should not be ignored
      # for other reasons, but we don't want to log every test case for the
      # fuzzers that don't do their own crash processing.
      state = stack_analyzer.get_crash_data(output)
      if not state.crash_type:
        continue

      full_testcase_path = os.path.join(reproducers_dir, testcase_path)
      crash = engine.Crash(full_testcase_path, output, options.arguments,
                           int(result.time_executed))
      crashes.append(crash)

    # TODO(mbarbella): Support stats.
    stats = {}

    return engine.FuzzResult(result.output, result.command, crashes, stats,
                             result.time_executed)

  def reproduce(self, target_path, input_path, arguments, max_time):
    """Reproduce a crash given an input.
    Args:
      target_path: Path to the fuzzer script or binary.
      input_path: Path to the reproducer input.
      arguments: Additional arguments needed for reproduction.
      max_time: Maximum allowed time for the reproduction.
    Returns:
      A ReproduceResult.
    """
    del arguments
    # For blackbox fuzzers, |target_path| supplies the path to the fuzzer script
    # rather than a target in the build archive.
    fuzzer_path = target_path
    os.chmod(fuzzer_path, 0o775)

    app_path = environment.get_value('APP_PATH')
    app_args = testcase_manager.get_command_line_for_application(
        get_arguments_only=True).strip()

    args = _get_arguments(app_path, app_args)
    args.append(f'--testcase_path={input_path}')

    result = _run_with_interpreter_if_needed(fuzzer_path, args, max_time)
    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

  def minimize_corpus(self, target_path, arguments, input_dirs, output_dir,
                      reproducers_dir, max_time):
    """Run corpus minimization.
    Args:
      target_path: Path to the fuzzer script or binary.
      arguments: Additional arguments needed for corpus minimization.
      input_dirs: Input corpora.
      output_dir: Output directory to place minimized corpus.
      reproducers_dir: The directory to put reproducers in when crashes are
          found.
      max_time: Maximum allowed time for the minimization.
    Returns:
      A FuzzResult object.
    """
    # Blackbox fuzzers follow something closer to the traditional model, and as
    # of now do not rely on corpora.
    raise NotImplementedError(
        'Corpus minimization is not supported for blackbox fuzzers.')

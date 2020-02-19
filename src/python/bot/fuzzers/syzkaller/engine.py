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

from bot.fuzzers import engine
from bot.fuzzers import engine_common
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.syzkaller import runner
from builtins import object
from metrics import profiler
from system import environment
import os

BIN_FOLDER_PATH = 'bin'
_ENGINES = {}


class SyzkallerError(Exception):
  """Base exception class."""


class SyzkallerOptions(engine.FuzzOptions):
  """Represents options passed to the engine. Can be overridden to provide more
  options."""

  def __init__(self, corpus_dir, arguments, strategies, fuzz_corpus_dirs,
               extra_env):
    super(SyzkallerOptions, self).__init__(corpus_dir, arguments, strategies)
    self.fuzz_corpus_dirs = fuzz_corpus_dirs
    self.extra_env = extra_env


class SyzkallerEngine(object):
  """Syzkaller fuzzing engine implementation."""

  @property
  def name(self):
    return 'syzkaller'

  def prepare(self, corpus_dir, target_path, unused_build_dir):
    """Prepare for a fuzzing session, by generating options and making
    syzkaller binaries executable.

    Args:
      corpus_dir: The main corpus directory.
      target_path: Path to the target.
      build_dir: Path to the build directory.

    Returns:
      A FuzzOptions object.
    """
    syzkaller_path = os.path.join(
        environment.get_value('BUILD_DIR'), 'syzkaller')
    if not os.path.exists(syzkaller_path):
      raise SyzkallerError('syzkaller not found in build')
    binary_full_path = os.path.join(syzkaller_path, BIN_FOLDER_PATH)
    for filename in os.listdir(binary_full_path):
      os.chmod(os.path.join(binary_full_path, filename), 0o755)

    # TODO(hzawawy): Add strategies here

    arguments = runner.get_arguments(target_path)
    return SyzkallerOptions(corpus_dir, arguments, None, None, None)

  def _create_temp_corpus_dir(self, name):
    """Create temporary corpus directory."""
    new_corpus_directory = os.path.join(fuzzer_utils.get_temp_dir(), name)
    engine_common.recreate_directory(new_corpus_directory)
    return new_corpus_directory

  def fuzz(self, target_path, options, unused_reproducers_dir=None, max_time=0):
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
    profiler.start_if_needed('syzkaller_kasan')
    syzkaller_runner = runner.get_runner(target_path)

    # Directory to place new units.
    self._create_temp_corpus_dir('new')

    return syzkaller_runner.fuzz(max_time, additional_args=options.arguments)

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
    raise NotImplementedError

  def minimize_corpus(self, target_path, arguments, input_dirs, output_dir,
                      unused_reproducers_dir, unused_max_time):
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
    """
    raise NotImplementedError

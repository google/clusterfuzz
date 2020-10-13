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

import os
import shutil

from bot.fuzzers import engine_common
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.syzkaller import constants
from bot.fuzzers.syzkaller import runner
from lib.clusterfuzz.fuzz import engine
from metrics import profiler
from system import environment
from system import shell

BIN_FOLDER_PATH = 'bin'
REPRO_TIME = 70
CORPUS_DB_FILENAME = 'corpus.db'


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


class SyzkallerEngine(engine.Engine):
  """Syzkaller fuzzing engine implementation."""

  @property
  def name(self):
    return 'syzkaller'

  def prepare_binary_path(self):
    """Prepares the path for the syzkaller binary.

    Returns:
      The full path of the binary folder.
    """
    syzkaller_path = os.path.join(
        environment.get_value('BUILD_DIR'), 'syzkaller')
    if not os.path.exists(syzkaller_path):
      raise SyzkallerError('syzkaller not found in build')
    binary_folder = os.path.join(syzkaller_path, BIN_FOLDER_PATH)

    for root, _, filenames in os.walk(binary_folder):
      for filename in filenames:
        absolute_file_path = os.path.join(root, filename)
        os.chmod(absolute_file_path, 0o755)

    return binary_folder

  def prepare(self, corpus_dir, target_path, unused_build_dir):  # pylint: disable=unused-argument
    """Prepare for a fuzzing session, by generating options and making
    syzkaller binaries executable.

    Args:
      corpus_dir: The main corpus directory.
      target_path: Path to the target.
      build_dir: Path to the build directory.

    Returns:
      A FuzzOptions object."""
    self.prepare_binary_path()
    config = runner.get_config()
    return SyzkallerOptions(
        corpus_dir,
        config,
        strategies={},
        fuzz_corpus_dirs=None,
        extra_env=None)

  def _create_temp_corpus_dir(self, name):
    """Create temporary corpus directory."""
    new_corpus_directory = os.path.join(fuzzer_utils.get_temp_dir(), name)
    engine_common.recreate_directory(new_corpus_directory)
    return new_corpus_directory

  def _get_device_corpus_db_filename(self):
    """Return device-specific corpus db filename."""
    return environment.get_value('ANDROID_SERIAL') + '.db'

  def save_corpus(self, source_dir, destination_dir):
    """Saves syzkaller to folder so it is backed up to the cloud.

    Args:
      source_dir: Folder where syzkaller corpus is.
      destination_dir: Folder where the corpus is synced with the cloud.
    """
    source_file = os.path.join(source_dir, CORPUS_DB_FILENAME)
    shell.create_directory(destination_dir)
    destination_file = os.path.join(destination_dir,
                                    self._get_device_corpus_db_filename())
    if os.path.isfile(source_file) and (
        not os.path.exists(destination_file) or
        (os.path.getsize(source_file) > os.path.getsize(destination_file))):
      shutil.copy(source_file, destination_file)

  def init_corpus(self, source_dir, destination_dir):
    """Uses corpus from the cloud to initialize syzkaller corpus.

    Args:
      source_dir: Folder where the corpus is downloaded from the cloud.
      destination_dir: Folder where syzkaller will be looking for corpus.
    """
    source_file = os.path.join(source_dir,
                               self._get_device_corpus_db_filename())
    shell.create_directory(destination_dir)
    destination_file = os.path.join(destination_dir, CORPUS_DB_FILENAME)
    if os.path.isfile(source_file):
      shutil.copy(source_file, destination_file)

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

    args = options.arguments
    args += ['--coverfile', runner.get_cover_file_path()]

    self.init_corpus(options.corpus_dir, runner.get_work_dir())
    fuzz_result = syzkaller_runner.fuzz(max_time, additional_args=args)
    self.save_corpus(runner.get_work_dir(), options.corpus_dir)
    return fuzz_result

  def reproduce(self, target_path, input_path, arguments, max_time):  # pylint: disable=unused-argument
    """Reproduce a crash given an input.
       Example: ./syz-crush -config my.cfg -infinite=false -restart_time=20s
        crash-qemu-1-1455745459265726910

    Args:
      target_path: Path to the target.
      input_path: Path to the reproducer input.
      arguments: Additional arguments needed for reproduction.
      max_time: Maximum allowed time for the reproduction.

    Returns:
      A ReproduceResult.
    """
    binary_dir = self.prepare_binary_path()
    syzkaller_runner = runner.get_runner(
        os.path.join(binary_dir, constants.SYZ_REPRO))
    repro_args = runner.get_config()
    repro_args.extend(
        ['-infinite=false', '-restart_time={}s'.format(REPRO_TIME), input_path])
    result = syzkaller_runner.repro(max_time, repro_args=repro_args)

    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

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

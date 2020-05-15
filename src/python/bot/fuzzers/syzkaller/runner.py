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
"""syzkaller fuzzer."""
from __future__ import absolute_import
from base import utils
from bot.fuzzers import engine
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.syzkaller import config
from bot.fuzzers.syzkaller import constants
from builtins import str
from metrics import logs
from system import environment
from system import new_process
import copy
import fnmatch
import os
import tempfile


def get_config():
  """Get arguments for a given fuzz target."""
  build_dir = environment.get_value('BUILD_DIR')
  device_serial = environment.get_value('ANDROID_SERIAL')
  json_config_path = os.path.join('/tmp', device_serial, 'config.json')
  config.generate(
      serial=device_serial,
      work_dir_path=constants.SYZKALLER_WORK_FOLDER,
      binary_path=os.path.join(build_dir, 'syzkaller'),
      vmlinux_path=constants.VMLINUX_FOLDER,
      config_path=json_config_path,
      kcov=True,
      reproduce=False)
  return ['-config', json_config_path]


def get_runner(fuzzer_path):
  """Return a syzkaller runner object."""
  build_dir = environment.get_value('BUILD_DIR')
  return AndroidSyzkallerRunner(fuzzer_path, build_dir)


class AndroidSyzkallerRunner(new_process.ProcessRunner):
  """Syzkaller runner."""

  def __init__(self, executable_path, default_args=None):
    """Inits the AndroidSyzkallerRunner.

    Args:
      executable_path: Path to the fuzzer executable.
      default_args: Default arguments to always pass to the fuzzer.
    """
    super(AndroidSyzkallerRunner, self).__init__(
        executable_path=executable_path, default_args=None)

  def get_command(self, additional_args=None):
    """Process.get_command override."""
    base_command = super(AndroidSyzkallerRunner,
                         self).get_command(additional_args=additional_args)

    return base_command

  def _create_empty_testcase_file(self):
    """Create an empty testcase file in temporary directory."""
    _, path = tempfile.mkstemp(dir=fuzzer_utils.get_temp_dir())
    return path

  def repro(self, repro_timeout, repro_args):
    """This is where crash repro'ing is done.
    Args:
      repro_timeout: The maximum time in seconds that repro job is allowed
          to run for.
      repro_args: A sequence of arguments to be passed to the executable.
    """
    logs.log('Running Syzkaller testcase.')
    additional_args = copy.copy(repro_args)
    result = self.run_and_wait(additional_args, timeout=repro_timeout)
    logs.log('Syzkaller testcase stopped.')
    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, str(result.output))

  def fuzz(self,
           fuzz_timeout,
           additional_args,
           unused_additional_args=None,
           unused_extra_env=None):
    """This is where actual syzkaller fuzzing is done.
    Args:
      fuzz_timeout: The maximum time in seconds that fuzz job is allowed
          to run for.
      additional_args: A sequence of additional arguments to be passed to
          the executable.
    """
    logs.log('Running Syzkaller!')
    additional_args = copy.copy(additional_args)
    fuzz_result = self.run_and_wait(additional_args, timeout=fuzz_timeout)
    logs.log('Syzkaller Stopped! Fuzzing timed out: {}'.format(fuzz_timeout))
    fuzz_logs = ''

    visited = set()
    for subdir, _, files in os.walk(constants.SYZKALLER_WORK_FOLDER):
      for file in files:
        # Each crash typically have 2 files: reportN and logN. Similar crashes
        # are grouped together in subfolders. unique_crash puts together the
        # subfolder name (without './' (hence the [2:])) and reportN.
        unique_crash = subdir[len('./'):] + file
        if fnmatch.fnmatch(file, 'report*') and unique_crash not in visited:
          visited.add(unique_crash)
          log_lines = utils.read_data_from_file(
              os.path.join(subdir, file), eval_data=False)
          fuzz_result.output = str(log_lines)

          # Since each crash (report file) has a corresponding log file
          # that contains the syscalls that caused the crash. This file is
          # located in the same subfolder and has the same number.
          # E.g. ./439c37d288d4f26a33a6c7e5c57a97791453a447/report15 and
          # ./439c37d288d4f26a33a6c7e5c57a97791453a447/log15.
          crash_testcase_file_path = os.path.join(subdir,
                                                  'log' + file[len('report'):])

          fuzz_logs = fuzz_result.output

          # TODO(hzawawy): Parse stats information and add them to FuzzResult
          parsed_stats = []

          crashes = []
          if crash_testcase_file_path:
            reproduce_arguments = [unique_crash]
            actual_duration = int(fuzz_result.time_executed)
            # Write the new testcase.
            # Copy crash testcase contents into the main testcase path.
            crashes.append(
                engine.Crash(crash_testcase_file_path, log_lines,
                             reproduce_arguments, actual_duration))

    logs.log('Returning fuzz result')
    return engine.FuzzResult(fuzz_logs, fuzz_result.command, crashes,
                             parsed_stats, fuzz_result.time_executed)

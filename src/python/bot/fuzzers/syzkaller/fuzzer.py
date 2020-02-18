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
from system import environment
from system import new_process
import copy
import os
import re
import tempfile


def get_arguments(unused_fuzzer_path):
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
  return ['--config', json_config_path]


def get_runner(fuzzer_path):
  """Return a suzkaller runner object."""
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

  def get_testcase_path(self, log_lines):
    """Get testcase path from log lines."""
    #TODO(hzawawy) when a crash is detected extract testcase from report.
    for line in log_lines:
      match = re.match(constants.KASAN_CRASH_TESTCASE_REGEX, line)
      if match:
        return match.group(1)

    return None

  def fuzz(self,
           fuzz_timeout,
           additional_args,
           unused_additional_args=None,
           unused_extra_env=None):
    """This is where actual syzkaller fuzzing is done."""
    additional_args = copy.copy(additional_args)
    fuzz_result = self.run_and_wait(additional_args, timeout=fuzz_timeout)

    log_lines = utils.decode_to_unicode(fuzz_result.output).splitlines()
    fuzz_result.output = None
    crash_testcase_file_path = self.get_testcase_path(log_lines)

    #TODO(hzawawy): remove once syzkaller code is completed.
    if not crash_testcase_file_path and fuzz_result.return_code:
      crash_testcase_file_path = self._create_empty_testcase_file()

    fuzz_logs = '\n'.join(log_lines)

    # TODO(hzawawy): Parse stats information and add them to FuzzResult
    parsed_stats = []

    crashes = []
    if crash_testcase_file_path:
      #TODO(hzawawy): add repro arguments
      reproduce_arguments = []
      actual_duration = int(fuzz_result.time_executed)
      # Write the new testcase.
      # Copy crash testcase contents into the main testcase path.
      crashes.append(
          engine.Crash(crash_testcase_file_path, fuzz_logs, reproduce_arguments,
                       actual_duration))

    return engine.FuzzResult(fuzz_logs, fuzz_result.command, crashes,
                             parsed_stats, fuzz_result.time_executed)

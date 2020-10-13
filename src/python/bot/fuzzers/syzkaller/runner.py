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
import copy
import fnmatch
import os
import re
import tempfile

from base import utils
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.syzkaller import config
from lib.clusterfuzz.fuzz import engine
from metrics import logs
from system import environment
from system import new_process

REPRODUCE_REGEX = re.compile(r'reproduced (\d+) crashes')


def get_work_dir():
  """Return work directory for Syzkaller."""
  return os.path.join(environment.get_value('FUZZ_INPUTS_DISK'), 'syzkaller')


def get_config():
  """Get arguments for a given fuzz target."""
  device_serial = environment.get_value('ANDROID_SERIAL')
  build_dir = environment.get_value('BUILD_DIR')
  temp_dir = fuzzer_utils.get_temp_dir()

  binary_path = os.path.join(build_dir, 'syzkaller')
  json_config_path = os.path.join(temp_dir, 'config.json')
  default_vmlinux_path = os.path.join('/tmp', device_serial, 'vmlinux')
  vmlinux_path = environment.get_value('VMLINUX_PATH', default_vmlinux_path)

  syzhub_address = environment.get_value('SYZHUB_ADDRESS')
  syzhub_client = environment.get_value('SYZHUB_CLIENT')
  syzhub_key = environment.get_value('SYZHUB_KEY')

  config.generate(
      serial=device_serial,
      work_dir_path=get_work_dir(),
      binary_path=binary_path,
      vmlinux_path=vmlinux_path,
      config_path=json_config_path,
      kcov=True,
      reproduce=False,
      syzhub_address=syzhub_address,
      syzhub_client=syzhub_client,
      syzhub_key=syzhub_key)
  return ['-config', json_config_path]


def get_cover_file_path():
  """Return location of coverage file for Syzkaller."""
  return os.path.join(get_work_dir(), 'coverfile')


def get_runner(fuzzer_path):
  """Return a syzkaller runner object."""
  return AndroidSyzkallerRunner(fuzzer_path)


class AndroidSyzkallerRunner(new_process.UnicodeProcessRunner):
  """Syzkaller runner."""

  def __init__(self, executable_path):
    """Inits the AndroidSyzkallerRunner.

    Args:
      executable_path: Path to the fuzzer executable.
      default_args: Default arguments to always pass to the fuzzer.
    """
    super(AndroidSyzkallerRunner,
          self).__init__(executable_path=executable_path)

  def get_command(self, additional_args=None):
    """Process.get_command override."""
    base_command = super(AndroidSyzkallerRunner,
                         self).get_command(additional_args=additional_args)

    return base_command

  def _create_empty_testcase_file(self):
    """Create an empty testcase file in temporary directory."""
    _, path = tempfile.mkstemp(dir=fuzzer_utils.get_temp_dir())
    return path

  def _crash_was_reproducible(self, output):
    reproducible = False
    if 'all done.' in output:
      search = REPRODUCE_REGEX.search(output)
      if search and search.group(1) and search.group(1) > '0':
        reproducible = True
    return int(reproducible)

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
    result.return_code = self._crash_was_reproducible(result.output)

    if result.return_code:
      logs.log('Successfully reproduced crash.')
    else:
      logs.log('Failed to reproduce crash.')
    logs.log('Syzkaller repro testcase stopped.')
    return engine.ReproduceResult(result.command, result.return_code,
                                  result.time_executed, result.output)

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

    def _filter_log(content):
      """Filter unneeded content from log."""
      result = ''
      strip_regex = re.compile(r'^c\d+\s+\d+\s')
      for line in content.splitlines():
        result += strip_regex.sub('', line) + '\n'
      return result

    logs.log('Running Syzkaller.')
    additional_args = copy.copy(additional_args)
    fuzz_result = self.run_and_wait(additional_args, timeout=fuzz_timeout)
    logs.log('Syzkaller stopped, fuzzing timed out: {}'.format(
        fuzz_result.time_executed))

    fuzz_logs = (fuzz_result.output or '') + '\n'
    crashes = []
    parsed_stats = {}
    visited = set()
    for subdir, _, files in os.walk(get_work_dir()):
      for file in files:
        # Each crash typically have 2 files: reportN and logN. Similar crashes
        # are grouped together in subfolders. unique_crash puts together the
        # subfolder name and reportN.
        unique_crash = os.path.join(subdir, file)
        if fnmatch.fnmatch(file, 'report*') and unique_crash not in visited:
          visited.add(unique_crash)
          log_content = _filter_log(
              utils.read_data_from_file(
                  os.path.join(subdir, file), eval_data=False).decode('utf-8'))
          fuzz_logs += log_content + '\n'

          # Since each crash (report file) has a corresponding log file
          # that contains the syscalls that caused the crash. This file is
          # located in the same subfolder and has the same number.
          # E.g. ./439c37d288d4f26a33a6c7e5c57a97791453a447/report15 and
          # ./439c37d288d4f26a33a6c7e5c57a97791453a447/log15.
          crash_testcase_file_path = os.path.join(subdir,
                                                  'log' + file[len('report'):])

          # TODO(hzawawy): Parse stats information and add them to FuzzResult.

          if crash_testcase_file_path:
            reproduce_arguments = [unique_crash]
            actual_duration = int(fuzz_result.time_executed)
            # Write the new testcase.
            # Copy crash testcase contents into the main testcase path.
            crashes.append(
                engine.Crash(crash_testcase_file_path, log_content,
                             reproduce_arguments, actual_duration))

    return engine.FuzzResult(fuzz_logs, fuzz_result.command, crashes,
                             parsed_stats, fuzz_result.time_executed)

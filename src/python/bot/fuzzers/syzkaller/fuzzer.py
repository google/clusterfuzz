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
"""syzkaller fuzzer."""
from __future__ import absolute_import
from base import utils
from bot.fuzzers import builtin
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.syzkaller import constants
from bot.fuzzers.syzkaller import generate_config
from builtins import object
from system import environment
from system import new_process
import copy
import re
import tempfile

# Regex to find testcase path from a crash.
KASAN_CRASH_TESTCASE_REGEX = (r'.*Test unit written to\s*'
                              r'(Read|Write) of .*')


def get_arguments(fuzzer_path):
  """Get arguments for a given fuzz target."""
  del fuzzer_path
  build_dir = environment.get_value('BUILD_DIR')
  device_serial = environment.get_value('ANDROID_SERIAL')
  json_config_path = '/tmp/' + device_serial + '/config.json'
  generate_config.run(
      serial=device_serial,
      work_dir_path='/tmp/syzkaller',
      binary_path=build_dir + '/syzkaller',
      vmlinux_path='/tmp/syzkaller/vmlinux',
      config_path=json_config_path,
      kcov=True,
      reproduce=False)
  arguments = ['--config', json_config_path]
  return arguments


def get_runner(fuzzer_path):
  """Return a suzkaller runner object."""
  build_dir = environment.get_value('BUILD_DIR')
  return SyzkallerRunner(fuzzer_path, build_dir)


class Syzkaller(builtin.EngineFuzzer):
  """Builtin syzkaller fuzzing engine."""

  def generate_arguments(self, fuzzer_path):
    """Generate arguments for fuzzer using .options file or default values."""
    return ' '.join(get_arguments(fuzzer_path))


class SyzkallerRunner(new_process.ProcessRunner):
  """Syzkaller runner."""

  def __init__(self, executable_path, default_args=None):
    """Inits the SyzkallerRunner.

    Args:
      executable_path: Path to the fuzzer executable.
      default_args: Default arguments to always pass to the fuzzer.
    """
    super(SyzkallerRunner, self).__init__(
        executable_path=executable_path, default_args=None)

  def get_command(self, additional_args=None):
    """Process.get_command override."""
    base_command = super(SyzkallerRunner,
                         self).get_command(additional_args=additional_args)

    return base_command

  def _create_empty_testcase_file(self):
    """Create an empty testcase file in temporary directory."""
    _, path = tempfile.mkstemp(dir=fuzzer_utils.get_temp_dir())
    return path

  def get_testcase_path(self, log_lines):
    """Get testcase path from log lines."""
    for line in log_lines:
      match = re.match(KASAN_CRASH_TESTCASE_REGEX, line)
      if match:
        return match.group(1)

    return None

  def fix_timeout_argument_for_reproduction(self, arguments):
    """Changes timeout argument for reproduction. This is higher than default to
    avoid noise with smaller fuzzing defaults."""
    fuzzer_utils.extract_argument(arguments, constants.TIMEOUT_FLAG)
    arguments.append(
        '%s%d' % (constants.TIMEOUT_FLAG, constants.REPRODUCTION_TIMEOUT_LIMIT))

  def fuzz(self,
           corpus_directories,
           fuzz_timeout,
           artifact_prefix=None,
           additional_args=None,
           extra_env=None):
    """This is where actual syzkaller fuzzing is done."""
    del corpus_directories, artifact_prefix, extra_env
    additional_args = copy.copy(additional_args)
    fuzz_result = self.run_and_wait(
        additional_args=additional_args, timeout=fuzz_timeout)

    log_lines = utils.decode_to_unicode(fuzz_result.output).splitlines()
    fuzz_result.output = None
    crash_testcase_file_path = self.get_testcase_path(log_lines)

    if not crash_testcase_file_path and fuzz_result.return_code:
      crash_testcase_file_path = self._create_empty_testcase_file()

    fuzz_logs = '\n'.join(log_lines)

    # TODO: Parse stats information and add them to FuzzResult
    parsed_stats = []

    crashes = []
    if crash_testcase_file_path:
      arguments = additional_args[:]
      #libfuzzer.remove_fuzzing_arguments(arguments)
      arguments = additional_args[:]
      reproduce_arguments = arguments[:]
      self.fix_timeout_argument_for_reproduction(reproduce_arguments)
      actual_duration = int(fuzz_result.time_executed)
      # Write the new testcase.
      # Copy crash testcase contents into the main testcase path.
      crashes.append(
          Crash(crash_testcase_file_path, fuzz_logs, reproduce_arguments,
                actual_duration))

    return FuzzResult(fuzz_logs, fuzz_result.command, crashes, parsed_stats,
                      fuzz_result.time_executed)


class Crash(object):
  """Represents a crash found by the fuzzing engine."""

  def __init__(self, input_path, stacktrace, reproduce_args, crash_time):
    self.input_path = input_path
    self.stacktrace = stacktrace
    self.reproduce_args = reproduce_args
    self.crash_time = crash_time


class FuzzResult(object):
  """Represents a result of a fuzzing session: a list of crashes found and the
  statistics generated."""

  def __init__(self, logs, command, crashes, statistics, time_executed):
    self.logs = logs
    self.command = command
    self.crashes = crashes
    self.stats = statistics
    self.time_executed = time_executed

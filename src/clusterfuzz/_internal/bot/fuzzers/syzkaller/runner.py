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
import threading
import time

import requests

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.syzkaller import config
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.android import kernel_utils
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz.fuzz import engine

LOCAL_HOST = '127.0.0.1'
RAWCOVER_RETRIEVE_INTERVAL = 180  # retrieve rawcover every 180 seconds
REPRODUCE_REGEX = re.compile(r'reproduced (\d+) crashes')


def get_work_dir():
  """Return work directory for Syzkaller."""
  work_dir = os.path.join(
      environment.get_value('FUZZ_INPUTS_DISK'), 'syzkaller')

  os.makedirs(work_dir, exist_ok=True)
  return work_dir


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
  on_cuttlefish = environment.is_android_cuttlefish()

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
      syzhub_key=syzhub_key,
      on_cuttlefish=on_cuttlefish)
  return ['-config', json_config_path]


def get_cover_file_path():
  """Return location of coverage file for Syzkaller."""
  return os.path.join(get_work_dir(), 'coverfile')


def get_runner(fuzzer_path):
  """Return a syzkaller runner object."""
  return AndroidSyzkallerRunner(fuzzer_path)


def _upload_kernel_coverage_data(kcov_path, kernel_bid):
  """Upload kcov data to a cloud storage bucket."""
  bucket_name = local_config.ProjectConfig().get('coverage.reports.bucket')
  if not bucket_name:
    return

  formatted_date = str(utils.utcnow().date().isoformat())
  identifier = environment.get_value('BOT_NAME') + str(
      utils.utcnow().isoformat())

  gcs_url = (f'gs://{bucket_name}/syzkaller/{formatted_date}/{kernel_bid}/'
             f'{identifier}')
  if storage.copy_file_to(kcov_path, gcs_url):
    logs.log(f'Copied kcov data to {gcs_url}.')


class LoopingTimer(threading.Timer):
  """Extend Timer to loop every interval seconds."""

  def __init__(self, interval, function, args=None, kwargs=None):
    super(LoopingTimer, self).__init__(
        interval, function, args=args, kwargs=kwargs)

  def run(self):
    # loops until self.cancel()
    while not self.finished.is_set():
      self.finished.wait(self.interval)
      self.function(*self.args, **self.kwargs)


class AndroidSyzkallerRunner(new_process.UnicodeProcessRunner):
  """Syzkaller runner."""

  def __init__(self, executable_path):
    """Inits the AndroidSyzkallerRunner.

    Args:
      executable_path: Path to the fuzzer executable.
    """
    super().__init__(executable_path=executable_path)
    self._port = None

  def get_command(self, additional_args=None):
    """Process.get_command override."""
    base_command = super().get_command(additional_args=additional_args)

    return base_command

  def get_port(self, pid: int) -> int or None:
    """Find localhost port where syzkaller is connected."""

    if self._port is not None:
      return self._port

    import psutil  # pylint: disable=g-import-not-at-top

    for connection in psutil.net_connections():
      if connection.pid != pid:
        continue

      local_address = connection.laddr
      if (local_address.ip == LOCAL_HOST and
          connection.status == psutil.CONN_LISTEN):
        self._port = local_address.port
        logs.log(f'Syzkaller listening at: http://localhost:{self._port}')
        return self._port

    # No connection found
    return None

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

  def save_rawcover_output(self, pid: int):
    """Find syzkaller port and write rawcover data to a file."""

    port = self.get_port(pid)
    if port is None:
      logs.log_warn('Could not find Syzkaller port')
      return

    try:
      rawcover = requests.get(f'http://localhost:{port}/rawcover').text
    except requests.exceptions.ConnectionError:
      logs.log_warn('Connection to Syzkaller Failed')
      return

    if not rawcover or rawcover.startswith('coverage is not ready'):
      logs.log_warn('Syzkaller rawcover not yet loaded')
      return

    file_path = get_cover_file_path()
    with open(file_path, 'w+') as f:
      f.write(rawcover)
      logs.log(f'Writing syzkaller rawcover to {file_path}')

  def run_and_loop(self, *args, timeout=None,
                   **kwargs) -> new_process.ProcessResult:
    """Adds looping call to run_and_wait method.

    This method adds LoopingTimer() that continuously executes a function
    that gets / saves rawcover data from Syzkaller.

    Args:
      *args: args for self.run()
      timeout: timeout in seconds to stop Syzkaller
      **kwargs: kwargs for self.run()
    Returns:
      new_process.ProcessResult from Syzkaller
    """
    process = self.run(*args, **kwargs)
    pid = process.popen.pid
    logs.log(f'Syzkaller pid = {pid}')

    looping_timer = LoopingTimer(
        RAWCOVER_RETRIEVE_INTERVAL,
        self.save_rawcover_output,
        args=[pid],
    )
    looping_timer.start()

    try:
      if not timeout:
        start_time = time.time()
        output = process.communicate()[0]
        return new_process.ProcessResult(process.command, process.poll(),
                                         output,
                                         time.time() - start_time, False)

      result = new_process.wait_process(
          process,
          timeout=timeout,
          input_data=None,
          terminate_before_kill=False,
          terminate_wait_time=None,
      )
      result.command = process.command
      result.output = str(result.output)

      return result
    finally:
      looping_timer.cancel()

  def fuzz(
      self,
      fuzz_timeout,
      additional_args,
      unused_additional_args=None,
      unused_extra_env=None,
  ) -> engine.FuzzResult:
    """This is where actual syzkaller fuzzing is done.

    Args:
      fuzz_timeout (float): The maximum time in seconds that fuzz job is allowed
          to run for.
      additional_args: A sequence of additional arguments to be passed to
          the executable.
    Returns:
      engine.FuzzResult
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

    # Save kernel_bid for later in case the device is down.
    _, kernel_bid = kernel_utils.get_kernel_hash_and_build_id()

    fuzz_result = self.run_and_loop(additional_args, timeout=fuzz_timeout)
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

    _upload_kernel_coverage_data(get_cover_file_path(), kernel_bid)
    return engine.FuzzResult(fuzz_logs, fuzz_result.command, crashes,
                             parsed_stats, fuzz_result.time_executed)

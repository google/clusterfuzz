# Copyright 2021 Google LLC
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
"""Helper functions for running commands on emulated Android devices."""

import os
import re
import subprocess
import tempfile

from google_cloud_utils import storage
from metrics import logs
from platforms.android import adb
from system import archive
from system import environment
from system import shell

try:
  from system import new_process
except ImportError:
  # On App Engine.
  new_process = None

# Output pattern to parse stdout for serial number
DEVICE_SERIAL_RE = re.compile(r'DEVICE_SERIAL: (.+)')


class EmulatorError(Exception):
  """Error for errors handling the Android emulator."""


class EmulatorProcess(object):
  """A EmulatorProcess encapsulates the creation, running, and destruction
  of Android emulator processes."""

  def __init__(self):
    self.process_runner = None
    self.process = None
    self.logfile = None

    log_path = os.path.join(tempfile.gettempdir(), 'android-emulator.log')
    self.logfile = open(log_path, 'wb')

  def create(self, work_dir):
    """Configures a emulator process which can subsequently be `run`."""
    # Download emulator image.
    if not environment.get_value('ANDROID_EMULATOR_BUCKET_PATH'):
      logs.log_error('ANDROID_EMULATOR_BUCKET_PATH is not set.')
      return
    archive_src_path = environment.get_value('ANDROID_EMULATOR_BUCKET_PATH')
    archive_dst_path = os.path.join(work_dir, 'emulator_bundle.zip')
    storage.copy_file_from(archive_src_path, archive_dst_path)

    # Extract emulator image.
    self.emulator_path = os.path.join(work_dir, 'emulator')
    archive.unpack(archive_dst_path, self.emulator_path)
    shell.remove_file(archive_dst_path)

    # Stop any stale emulator instances.
    stop_script_path = os.path.join(self.emulator_path, 'stop')
    stop_proc = new_process.ProcessRunner(stop_script_path)
    stop_proc.run_and_wait()

    # Run emulator.
    run_script_path = os.path.join(self.emulator_path, 'run')
    self.process_runner = new_process.ProcessRunner(run_script_path)

  def run(self):
    """Actually runs a emulator, assuming `create` has already been called."""
    if not self.process_runner:
      raise EmulatorError('Attempted to `run` emulator before calling `create`')

    logs.log('Starting emulator.')
    self.process = self.process_runner.run(
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    device_serial = None
    while not device_serial:
      line = self.process.popen.stdout.readline().decode()
      match = DEVICE_SERIAL_RE.match(line)
      if match:
        device_serial = match.group(1)

    logs.log('Found serial ID: %s.' % device_serial)
    environment.set_value('ANDROID_SERIAL', device_serial)

    logs.log('Waiting on device')
    adb.wait_until_fully_booted()
    logs.log('Device is online')

  def kill(self):
    """ Kills the currently-running emulator, if there is one. """
    if self.process:
      logs.log('Stopping emulator.')
      self.process.kill()
      self.process = None

    if self.logfile:
      self.logfile.close()
      self.logfile = None

    if self.emulator_path:
      shell.remove_directory(self.emulator_path)

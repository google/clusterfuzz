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

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.system import environment

try:
  from clusterfuzz._internal.system import new_process
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

  def create(self, work_dir):
    """Configures a emulator process which can subsequently be `run`."""
    self.process_runner = new_process.ProcessRunner(
        os.path.join(work_dir, '../emulator/run'))

  def run(self):
    """Actually runs a emulator, assuming `create` has already been called."""
    if not self.process_runner:
      raise EmulatorError('Attempted to `run` emulator before calling `create`')

    logs.log('Starting emulator.')
    self.process = self.process_runner.run(
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    device_serial = None
    while not device_serial:
      line = self.process.popen.stdout.readline().decode()
      match = DEVICE_SERIAL_RE.match(line)
      if match:
        device_serial = match.group(1)

    # Close the pipe so we don't hang.
    self.process.popen.stdout.close()

    logs.log('Found serial ID: %s.' % device_serial)
    environment.set_value('ANDROID_SERIAL', device_serial)

    logs.log('Waiting on device')
    adb.wait_for_device()
    logs.log('Device is online')

  def kill(self):
    """ Kills the currently-running emulator, if there is one. """
    if self.process:
      logs.log('Stopping emulator.')
      self.process.kill()
      self.process = None

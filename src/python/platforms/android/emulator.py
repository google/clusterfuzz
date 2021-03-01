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
import subprocess
import tempfile
import time

from google_cloud_utils import storage
from metrics import logs
from platforms.android import adb
from system import archive
from system import environment
from system import new_process
from system import shell

_WAIT_SECONDS = 10

_emu_proc = None
_emu_users = 0


class EmulatorError(Exception):
  """Error for errors handling the Android emulator."""


class EmulatorProcess(object):
  """A EmulatorProcess encapsulates the creation, running, and destruction
  of Android emulator processes."""

  def __init__(self):
    self.process_runner = None
    self.popen = None
    self.logfile = None

    log_path = os.path.join(tempfile.gettempdir(), 'android-emulator.log')
    self.logfile = open(log_path, 'wb')

  def create(self):
    """Configures a emulator process which can subsequently be `run`."""
    # Download emulator image.
    if not environment.get_value('BOT_TMPDIR'):
      logs.log_error('BOT_TMPDIR is not set.')
      return
    temp_directory = environment.get_value('BOT_TMPDIR')
    archive_src_path = environment.get_value('ANDROID_EMULATOR_BUCKET_PATH')
    archive_dst_path = os.path.join(temp_directory, 'emulator_bundle.zip')
    storage.copy_file_from(archive_src_path, archive_dst_path)

    # Extract emulator image.
    self.emulator_path = os.path.join(temp_directory, 'emulator')
    archive.unpack(archive_dst_path, self.emulator_path)
    shell.remove_file(archive_dst_path)

    # Run emulator.
    script_path = os.path.join(self.emulator_path, 'run')
    self.process_runner = new_process.ProcessRunner(script_path)

  def run(self):
    """Actually runs a emulator, assuming `create` has already been called."""
    if not self.process_runner:
      raise EmulatorError('Attempted to `run` emulator before calling `create`')

    devices_before = adb.get_devices()
    new_device = False

    logs.log('Starting emulator.')
    self.popen = self.process_runner.run(
        stdout=self.logfile, stderr=subprocess.PIPE)

    logs.log('Waiting for emulated device to come online.')
    while not new_device:
      time.sleep(_WAIT_SECONDS)
      for device in adb.get_devices():
        if device not in devices_before:
          environment.set_value('ANDROID_SERIAL', device)
          new_device = True
          logs.log('New device online with serial %s' % device)

  def kill(self):
    """ Kills the currently-running emulator, if there is one. """
    if self.popen:
      logs.log('Stopping emulator.')
      self.popen.kill()
      self.popen = None

    if self.logfile:
      self.logfile.close()
      self.logfile = None

    if self.emulator_path:
      shell.remove_directory(self.emulator_path)


def start_emulator():
  """Start emulator."""
  global _emu_proc
  global _emu_users
  _emu_users += 1
  if _emu_users == 1:
    _emu_proc = EmulatorProcess()
    _emu_proc.create()
    _emu_proc.run()
    adb.run_as_root()


def stop_emulator():
  """Stop emulator."""
  global _emu_proc
  global _emu_users
  _emu_users -= 1
  if _emu_users == 0:
    _emu_proc.kill()

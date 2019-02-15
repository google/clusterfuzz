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
"""The initialization script for Windows. It is run before running a task."""

import os
import subprocess

from base import retry
from base import utils
from bot.init_scripts import init_runner
from metrics import logs
from system import environment
from system import shell

DEFAULT_FAIL_RETRIES = 5
DEFAULT_FAIL_WAIT = 5

TEMP_DIRECTORIES = [
    r'%TEMP%', r'%USERPROFILE%\AppVerifierLogs', r'%USERPROFILE%\Downloads',
    r'%WINDIR%\Temp',
    r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\sym',
    r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym'
]


def clean_temp_directories():
  """Clean temporary directories."""
  for temp_directory in TEMP_DIRECTORIES:
    temp_directory_full_path = os.path.abspath(
        os.path.expandvars(temp_directory))
    shell.remove_directory(
        temp_directory_full_path, recreate=True, ignore_errors=True)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='init_scripts.windows.remount_if_needed')
def remount_if_needed():
  """Remount nfs volume if it is not working."""
  nfs_root = environment.get_value('NFS_ROOT')
  if not nfs_root:
    return

  nfs_host = environment.get_value('NFS_HOST')
  nfs_volume = environment.get_value('NFS_VOLUME')

  check_file_path = os.path.join(nfs_root, 'check')
  if os.path.exists(check_file_path):
    # Volume is mounted correctly and readable, bail out.
    return

  # Un-mount the nfs drive first. Ignore the return code as we might have
  # not mounted the drive at all.
  subprocess.call(['umount', '-f', nfs_root])

  # Mount the nfs drive.
  logs.log_warn('Trying to remount the NFS volume.')

  nfs_volume_path = '%s:/%s' % (nfs_host, nfs_volume)
  subprocess.check_call([
      'mount', '-o', 'anon', '-o', 'nolock', '-o', 'retry=10', nfs_volume_path,
      nfs_root
  ])

  if os.path.exists(check_file_path):
    # Volume is mounted correctly and readable, bail out.
    return

  # Update check file if needed.
  utils.write_data_to_file('ok', check_file_path)

  # Make sure that check file exists.
  if not os.path.exists(check_file_path):
    raise Exception('Failed to write check file on nfs volume.')


def run():
  """Run the initialization for Windows."""
  init_runner.run()
  clean_temp_directories()
  remount_if_needed()

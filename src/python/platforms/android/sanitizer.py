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
"""Sanitizer related functions."""

import os

from . import adb
from . import constants
from . import settings
from metrics import logs
from system import environment

ASAN_SCRIPT_TIMEOUT = 15 * 60
SANITIZER_TOOL_TO_FILE_MAPPINGS = {
    'ASAN': 'asan.options',
}


def get_options_file_path(sanitizer_tool_name):
  """Return path for the sanitizer options file."""
  # If this a full sanitizer system build, then update the options file in
  # /system, else just put it in device temp directory.
  sanitizer_directory = ('/system' if settings.get_sanitizer_tool_name() else
                         constants.DEVICE_TMP_DIR)

  sanitizer_filename = SANITIZER_TOOL_TO_FILE_MAPPINGS[sanitizer_tool_name]
  return os.path.join(sanitizer_directory, sanitizer_filename)


def set_options(sanitizer_tool_name, sanitizer_options):
  """Set sanitizer options on the disk file."""
  sanitizer_options_file_path = get_options_file_path(sanitizer_tool_name)
  adb.write_data_to_file(sanitizer_options, sanitizer_options_file_path)


def setup_asan_if_needed():
  """Set up asan on device."""
  if not environment.get_value('ASAN_DEVICE_SETUP'):
    # Only do this step if explicitly enabled in the job type. This cannot be
    # determined from libraries in application directory since they can go
    # missing in a bad build, so we want to catch that.
    return

  if settings.get_sanitizer_tool_name():
    # If this is a sanitizer build, no need to setup ASAN (incompatible).
    return

  app_directory = environment.get_value('APP_DIR')
  if not app_directory:
    # No app directory -> No ASAN runtime library. No work to do, bail out.
    return

  # Initialize variables.
  android_directory = environment.get_platform_resources_directory()
  device_id = environment.get_value('ANDROID_SERIAL')

  # Execute the script.
  logs.log('Executing ASan device setup script.')
  asan_device_setup_script_path = os.path.join(android_directory, 'third_party',
                                               'asan_device_setup.sh')
  asan_runtime_library_argument = '--lib %s' % app_directory
  device_argument = '--device %s' % device_id
  asan_options_file_path = get_options_file_path('ASAN')
  extra_asan_options = (
      '--extra-options include_if_exists=%s' % asan_options_file_path)
  command = '%s %s %s %s' % (asan_device_setup_script_path, device_argument,
                             asan_runtime_library_argument, extra_asan_options)
  adb.execute_command(command, timeout=ASAN_SCRIPT_TIMEOUT)

  # Wait until fully booted as otherwise shell restart followed by a quick
  # reboot can trigger data corruption in /data/data.
  adb.wait_until_fully_booted()

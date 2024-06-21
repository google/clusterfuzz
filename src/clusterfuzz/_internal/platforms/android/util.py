# Copyright 2022 Google LLC
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
"""Utility functions for Android device."""

import os

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.system import environment


def get_device_path(local_path):
  """Returns device path for the given local path."""
  root_directory = environment.get_root_directory()
  return os.path.join(android.constants.DEVICE_FUZZING_DIR,
                      os.path.relpath(local_path, root_directory))


def get_local_path(device_path):
  """Returns local path for the given device path."""
  if not device_path.startswith(android.constants.DEVICE_FUZZING_DIR + '/'):
    logs.error('Bad device path: ' + device_path)
    return None

  root_directory = environment.get_root_directory()
  return os.path.join(
      root_directory,
      os.path.relpath(device_path, android.constants.DEVICE_FUZZING_DIR))


def is_testcase_deprecated(platform_id=None):
  """Whether or not the Android device is deprecated."""

  # Platform ID for Android is of the form as shown below
  # |android:{codename}_{sanitizer}:{build_version}|
  platform_id_fields = platform_id.split(':')
  if len(platform_id_fields) != 3:
    return False

  codename_fields = platform_id_fields[1].split('_')

  # Check if device is deprecated
  if codename_fields[0] in android.constants.DEPRECATED_DEVICE_LIST:
    return True

  # Check if branch is deprecated
  # Currently only "main" or "m" is active
  # All other branches including "master" have been deprecated
  branch = platform_id_fields[2]
  if (branch <= 'v' or branch == 'master') and branch != 'm':
    return True

  return False


def can_testcase_run_on_platform(testcase_platform_id, current_platform_id):
  """Whether or not the testcase can run on the current Android device."""

  del testcase_platform_id  # Unused argument for now

  # Platform ID for Android is of the form as shown below
  # |android:{codename}_{sanitizer}:{build_version}|
  current_platform_id_fields = current_platform_id.split(':')
  if len(current_platform_id_fields) != 3:
    return False

  # Deprecated testcase should run on any latest device and on main
  # So ignore device information and check for current version
  # If the current version is 'm' or main, run the test case
  if current_platform_id_fields[2] == 'm':
    return True

  return False

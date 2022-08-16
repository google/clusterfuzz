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
    logs.log_error('Bad device path: ' + device_path)
    return None

  root_directory = environment.get_root_directory()
  return os.path.join(
      root_directory,
      os.path.relpath(device_path, android.constants.DEVICE_FUZZING_DIR))

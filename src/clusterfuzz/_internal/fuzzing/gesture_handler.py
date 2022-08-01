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
"""Gestures handler."""

from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.platforms import linux
from clusterfuzz._internal.platforms import windows
from clusterfuzz._internal.system import environment


def get_gestures(gesture_count):
  """Return a list of random gestures."""
  plt = environment.platform()

  if environment.is_android(plt):
    return android.gestures.get_random_gestures(gesture_count)
  if plt == 'LINUX':
    return linux.gestures.get_random_gestures(gesture_count)
  if plt == 'WINDOWS':
    return windows.gestures.get_random_gestures(gesture_count)

  return []

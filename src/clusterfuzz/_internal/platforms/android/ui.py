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
"""UI related functions."""

import time

from . import adb


def clear_notifications():
  """Clear all pending notifications."""
  adb.run_shell_command(['service', 'call', 'notification', '1'])


def unlock_screen():
  """Unlocks the screen if it is locked."""
  window_dump_output = adb.run_shell_command(['dumpsys', 'window'])
  if 'mShowingLockscreen=true' not in window_dump_output:
    # Screen is not locked, no work to do.
    return

  # Quick power on and off makes this more reliable.
  adb.run_shell_command(['input', 'keyevent', 'KEYCODE_POWER'])
  adb.run_shell_command(['input', 'keyevent', 'KEYCODE_POWER'])

  # This key does the unlock.
  adb.run_shell_command(['input', 'keyevent', 'KEYCODE_MENU'])

  # Artificial delay to let the unlock to complete.
  time.sleep(1)

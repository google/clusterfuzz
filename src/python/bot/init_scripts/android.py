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
"""Android init scripts."""

from bot.init_scripts import init_runner
from platforms import android


def run():
  """Run Android initialization."""
  init_runner.run()

  # Check if we need to reflash device to latest build.
  android.device.flash_to_latest_build_if_needed()

  # Make sure that device is in a good condition before we move forward.
  android.adb.wait_until_fully_booted()

  # See if we need to need to wait for battery charge to complete before
  # starting fuzzing.
  android.device.wait_for_battery_charge_if_needed()

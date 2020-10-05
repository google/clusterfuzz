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
"""Battery functions."""

import datetime
import re
import time

from . import adb
from . import settings
from base import dates
from base import persistent_cache
from metrics import logs
from system import environment

BATTERY_CHARGE_INTERVAL = 30 * 60  # 0.5 hour.
BATTERY_CHECK_INTERVAL = 15 * 60  # 15 minutes.
EXPECTED_BATTERY_LEVEL = 60  # A percentage.
EXPECTED_BATTERY_TEMPERATURE = 35.0  # Degrees Celsius.
LOW_BATTERY_LEVEL_THRESHOLD = 30  # A percentage.
MAX_BATTERY_TEMPERATURE_THRESHOLD = 37.0  # Don't change this or battery swells.

LAST_BATTERY_CHECK_TIME_KEY = 'android_last_battery_check'


def get_battery_level_and_temperature():
  """Return device's battery and temperature levels."""
  output = adb.run_shell_command(['dumpsys', 'battery'])

  # Get battery level.
  m_battery_level = re.match(r'.*level: (\d+).*', output, re.DOTALL)
  if not m_battery_level:
    logs.log_error('Error occurred while getting battery status.')
    return None

  # Get battery temperature.
  m_battery_temperature = re.match(r'.*temperature: (\d+).*', output, re.DOTALL)
  if not m_battery_temperature:
    logs.log_error('Error occurred while getting battery temperature.')
    return None

  level = int(m_battery_level.group(1))
  temperature = float(m_battery_temperature.group(1)) / 10.0
  return {'level': level, 'temperature': temperature}


def wait_until_good_state():
  """Check battery and make sure it is charged beyond minimum level and
  temperature thresholds."""
  # Battery levels are not applicable on GCE.
  if adb.is_gce() or settings.is_automotive():
    return

  # Make sure device is online.
  adb.wait_for_device()

  # Skip battery check if done recently.
  last_battery_check_time = persistent_cache.get_value(
      LAST_BATTERY_CHECK_TIME_KEY,
      constructor=datetime.datetime.utcfromtimestamp)
  if last_battery_check_time and not dates.time_has_expired(
      last_battery_check_time, seconds=BATTERY_CHECK_INTERVAL):
    return

  # Initialize variables.
  battery_level_threshold = environment.get_value('LOW_BATTERY_LEVEL_THRESHOLD',
                                                  LOW_BATTERY_LEVEL_THRESHOLD)
  battery_temperature_threshold = environment.get_value(
      'MAX_BATTERY_TEMPERATURE_THRESHOLD', MAX_BATTERY_TEMPERATURE_THRESHOLD)
  device_restarted = False

  while True:
    battery_information = get_battery_level_and_temperature()
    if battery_information is None:
      logs.log_error('Failed to get battery information, skipping check.')
      return

    battery_level = battery_information['level']
    battery_temperature = battery_information['temperature']
    logs.log('Battery information: level (%d%%), temperature (%.1f celsius).' %
             (battery_level, battery_temperature))
    if (battery_level >= battery_level_threshold and
        battery_temperature <= battery_temperature_threshold):
      persistent_cache.set_value(LAST_BATTERY_CHECK_TIME_KEY, time.time())
      return

    logs.log('Battery in bad battery state, putting device in sleep mode.')

    if not device_restarted:
      adb.reboot()
      device_restarted = True

    # Change thresholds to expected levels (only if they were below minimum
    # thresholds).
    if battery_level < battery_level_threshold:
      battery_level_threshold = EXPECTED_BATTERY_LEVEL
    if battery_temperature > battery_temperature_threshold:
      battery_temperature_threshold = EXPECTED_BATTERY_TEMPERATURE

    # Stopping shell should help with shutting off a lot of services that would
    # otherwise use up the battery. However, we need to turn it back on to get
    # battery status information.
    adb.stop_shell()
    time.sleep(BATTERY_CHARGE_INTERVAL)
    adb.start_shell()

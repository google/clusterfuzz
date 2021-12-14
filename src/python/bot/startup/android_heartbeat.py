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
"""Android Heartbeat script that monitors
   whether Android device is still running or not."""

# Before any other imports, we must fix the path. Some libraries might expect
# to be able to import dependencies directly, but we must store these in
# subdirectories of common so that they are shared with App Engine.
from clusterfuzz._internal.base import modules

modules.fix_module_search_paths()

import time

from clusterfuzz._internal.base import dates
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.system import environment


def main():
  """Run a cycle of heartbeat checks to ensure Android device is running."""
  logs.configure('android_heartbeat')
  dates.initialize_timezone_from_environment()
  environment.set_bot_environment()
  monitor.initialize()

  if environment.is_android_cuttlefish():
    android.adb.set_cuttlefish_device_serial()
  device_serial = environment.get_value('ANDROID_SERIAL')

  while True:
    state = android.adb.get_device_state()
    if state == android.adb.DEVICE_NOT_FOUND_STRING.format(
        serial=device_serial):
      android.adb.connect_to_cuttlefish_device()
      state = android.adb.get_device_state()
    logs.log('Android device %s state: %s' % (device_serial, state))

    monitoring_metrics.ANDROID_UPTIME.increment_by(
        int(state == 'device'), {
            'serial': device_serial or '',
            'platform': environment.get_platform_group() or '',
        })
    time.sleep(data_types.ANDROID_HEARTBEAT_WAIT_INTERVAL)

    if data_handler.bot_run_timed_out():
      break


if __name__ == '__main__':
  main()
  monitor.stop()

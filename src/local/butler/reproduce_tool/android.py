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
"""Android emulator installation and management."""

import os
import time

from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.platforms.android import device
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from local.butler.reproduce_tool import errors
from local.butler.reproduce_tool import prompts

ADB_DEVICES_SEPARATOR_STRING = 'List of devices attached'
EMULATOR_RELATIVE_PATH = os.path.join('local', 'bin', 'android-sdk', 'emulator',
                                      'emulator')


def start_emulator():
  """Return a ProcessRunner configured to start the Android emulator."""
  root_dir = environment.get_value('ROOT_DIR')

  runner = new_process.ProcessRunner(
      os.path.join(root_dir, EMULATOR_RELATIVE_PATH),
      ['-avd', 'TestImage', '-writable-system', '-partition-size', '2048'])
  emulator_process = runner.run()

  # If we run adb commands too soon after the emulator starts, we may see
  # flake or errors. Delay a short while to account for this.
  # TODO(mbarbella): This is slow and flaky, but wait-for-device isn't usable if
  # another device is connected (as we don't know the serial yet). Find a better
  # solution.
  time.sleep(30)

  return emulator_process


def get_devices():
  """Get a list of all connected Android devices."""
  adb_runner = new_process.ProcessRunner(adb.get_adb_path())
  result = adb_runner.run_and_wait(additional_args=['devices'])

  if result.return_code:
    raise errors.ReproduceToolUnrecoverableError('Unable to run adb.')

  # Ignore non-device lines (those before "List of devices attached").
  store_devices = False
  devices = []
  for line in result.output.splitlines():
    if line == ADB_DEVICES_SEPARATOR_STRING:
      store_devices = True
      continue
    if not store_devices or not line:
      continue

    devices.append(line.split()[0])

  return devices


def prepare_environment(disable_android_setup):
  """Additional environment overrides needed to run on an Android device."""
  environment.set_value('OS_OVERRIDE', 'ANDROID')

  # Bail out if we can't determine which Android device to use.
  serial = environment.get_value('ANDROID_SERIAL')
  if not serial:
    devices = get_devices()
    if len(devices) == 1:
      serial = devices[0]
      environment.set_value('ANDROID_SERIAL', serial)
    elif not devices:
      raise errors.ReproduceToolUnrecoverableError(
          'No connected Android devices were detected. Run with the -e '
          'argument to use an emulator.')
    else:
      raise errors.ReproduceToolUnrecoverableError(
          'You have multiple Android devices or emulators connected. Please '
          'set the ANDROID_SERIAL environment variable and try again.\n\n'
          'Attached devices: ' + ', '.join(devices))

  print('Warning: this tool will make changes to settings on the connected '
        'Android device with serial {serial} that could result in data '
        'loss.'.format(serial=serial))
  willing_to_continue = prompts.get_boolean(
      'Are you sure you want to continue?')
  if not willing_to_continue:
    raise errors.ReproduceToolUnrecoverableError(
        'Bailing out to avoid changing settings on the connected device.')

  # Push the test case and build APK to the device.
  apk_path = environment.get_value('APP_PATH')
  device.update_build(
      apk_path, should_initialize_device=not disable_android_setup)

  device.push_testcases_to_device()

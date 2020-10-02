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
"""Flash related functions."""
import datetime
import os
import socket
import time

from . import adb
from . import constants
from . import fetch_artifact
from . import settings
from base import dates
from base import persistent_cache
from datastore import locks
from metrics import logs
from system import archive
from system import environment
from system import shell

FLASH_IMAGE_REGEXES = [
    r'.*[.]img',
    r'.*-img-.*[.]zip',
]
FLASH_IMAGE_FILES = [
    # Order is important here.
    ('bootloader', 'bootloader*.img'),
    ('radio', 'radio*.img'),
    ('boot', 'boot.img'),
    ('system', 'system.img'),
    ('recovery', 'recovery.img'),
    ('vendor', 'vendor.img'),
    ('cache', 'cache.img'),
    ('vbmeta', 'vbmeta.img'),
    ('dtbo', 'dtbo.img'),
    ('userdata', 'userdata.img'),
]
FLASH_INTERVAL = 1 * 24 * 60 * 60
FLASH_RETRIES = 3
FLASH_REBOOT_BOOTLOADER_WAIT = 15
FLASH_REBOOT_WAIT = 5 * 60


def flash_to_latest_build_if_needed():
  """Wipes user data, resetting the device to original factory state."""
  if environment.get_value('LOCAL_DEVELOPMENT'):
    # Don't reimage local development devices.
    return

  run_timeout = environment.get_value('RUN_TIMEOUT')
  if run_timeout:
    # If we have a run timeout, then we are already scheduled to bail out and
    # will be probably get re-imaged. E.g. using frameworks like Tradefed.
    return

  # Check if a flash is needed based on last recorded flash time.
  last_flash_time = persistent_cache.get_value(
      constants.LAST_FLASH_TIME_KEY,
      constructor=datetime.datetime.utcfromtimestamp)
  needs_flash = last_flash_time is None or dates.time_has_expired(
      last_flash_time, seconds=FLASH_INTERVAL)
  if not needs_flash:
    return

  build_info = {}
  if adb.is_gce():
    adb.recreate_gce_device()
  else:
    # Physical device.
    is_google_device = settings.is_google_device()
    if is_google_device is None:
      logs.log_error('Unable to query device. Reimaging failed.')
      adb.bad_state_reached()

    elif not is_google_device:
      # We can't reimage these, skip.
      logs.log('Non-Google device found, skipping reimage.')
      return

    else:
      # For Google devices.
      # Check if both |BUILD_BRANCH| and |BUILD_TARGET| environment variables
      # are set. If not, we don't have enough data for reimaging and hence
      # we bail out.
      branch = environment.get_value('BUILD_BRANCH')
      target = environment.get_value('BUILD_TARGET')
      if not target:
        # We default to userdebug configuration.
        build_params = settings.get_build_parameters()
        if build_params:
          target = build_params.get('target') + '-userdebug'

          # Cache target in environment. This is also useful for cases when
          # device is bricked and we don't have this information available.
          environment.set_value('BUILD_TARGET', target)

      if not branch or not target:
        logs.log_warn(
            'BUILD_BRANCH and BUILD_TARGET are not set, skipping reimage.')
        return

      # Download the latest build artifact for this branch and target.
      build_info = fetch_artifact.get_latest_artifact_info(branch, target)
      if not build_info:
        logs.log_error(
            'Unable to fetch information on latest build artifact for '
            'branch %s and target %s.' % (branch, target))
        return

      # Check if our local build matches the latest build. If not, we will
      # download it.
      build_id = build_info['bid']
      target = build_info['target']
      image_directory = environment.get_value('IMAGES_DIR')
      last_build_info = persistent_cache.get_value(
          constants.LAST_FLASH_BUILD_KEY)
      if not last_build_info or last_build_info['bid'] != build_id:
        # Clean up the images directory first.
        shell.remove_directory(image_directory, recreate=True)

        # We have a new build, download the build artifacts for it.
        for image_regex in FLASH_IMAGE_REGEXES:
          image_file_path = fetch_artifact.get(build_id, target, image_regex,
                                               image_directory)
          if not image_file_path:
            logs.log_error(
                'Failed to download image artifact %s for '
                'branch %s and target %s.' % (image_file_path, branch, target))
            return
          if image_file_path.endswith('.zip'):
            archive.unpack(image_file_path, image_directory)

      # We do one device flash at a time on one host, otherwise we run into
      # failures and device being stuck in a bad state.
      flash_lock_key_name = 'flash:%s' % socket.gethostname()
      if not locks.acquire_lock(flash_lock_key_name, by_zone=True):
        logs.log_error('Failed to acquire lock for reimaging, exiting.')
        return

      logs.log('Reimaging started.')
      logs.log('Rebooting into bootloader mode.')
      for _ in range(FLASH_RETRIES):
        adb.run_as_root()
        adb.run_command(['reboot-bootloader'])
        time.sleep(FLASH_REBOOT_BOOTLOADER_WAIT)
        adb.run_fastboot_command(['oem', 'off-mode-charge', '0'])
        adb.run_fastboot_command(['-w', 'reboot-bootloader'])

        for partition, partition_image_filename in FLASH_IMAGE_FILES:
          partition_image_file_path = os.path.join(image_directory,
                                                   partition_image_filename)
          adb.run_fastboot_command(
              ['flash', partition, partition_image_file_path])
          if partition in ['bootloader', 'radio']:
            adb.run_fastboot_command(['reboot-bootloader'])

        # Disable ramdump to avoid capturing ramdumps during kernel crashes.
        # This causes device lockup of several minutes during boot and we intend
        # to analyze them ourselves.
        adb.run_fastboot_command(['oem', 'ramdump', 'disable'])

        adb.run_fastboot_command('reboot')
        time.sleep(FLASH_REBOOT_WAIT)

        if adb.get_device_state() == 'device':
          break
        logs.log_error('Reimaging failed, retrying.')

      locks.release_lock(flash_lock_key_name, by_zone=True)

  if adb.get_device_state() != 'device':
    logs.log_error('Unable to find device. Reimaging failed.')
    adb.bad_state_reached()

  logs.log('Reimaging finished.')

  # Reset all of our persistent keys after wipe.
  persistent_cache.delete_value(constants.BUILD_PROP_MD5_KEY)
  persistent_cache.delete_value(constants.LAST_TEST_ACCOUNT_CHECK_KEY)
  persistent_cache.set_value(constants.LAST_FLASH_BUILD_KEY, build_info)
  persistent_cache.set_value(constants.LAST_FLASH_TIME_KEY, time.time())

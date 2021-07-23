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

from clusterfuzz._internal.base import dates
from clusterfuzz._internal.base import persistent_cache
from clusterfuzz._internal.datastore import locks
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

from . import adb
from . import constants
from . import fetch_artifact
from . import settings

FLASH_IMAGE_REGEXES = [
    r'.*[.]img',
    r'.*-img-.*[.]zip',
]
FLASH_CUTTLEFISH_REGEXES = [
    r'.*-img-.*[.]zip',
    r'cvd-host_package.tar.gz',
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


def download_latest_build(build_info, image_regexes, image_directory):
  """Download the latest build artifact for the given branch and target."""
  # Check if our local build matches the latest build. If not, we will
  # download it.
  build_id = build_info['bid']
  target = build_info['target']
  last_build_info = persistent_cache.get_value(constants.LAST_FLASH_BUILD_KEY)
  if last_build_info and last_build_info['bid'] == build_id:
    return

  # Clean up the images directory first.
  shell.remove_directory(image_directory, recreate=True)
  for image_regex in image_regexes:
    image_file_path = fetch_artifact.get(build_id, target, image_regex,
                                         image_directory)
    if not image_file_path:
      logs.log_error('Failed to download artifact %s for '
                     'branch %s and target %s.' %
                     (image_file_path, build_info['branch'], target))
      return
    if image_file_path.endswith('.zip') or image_file_path.endswith('.tar.gz'):
      archive.unpack(image_file_path, image_directory)


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

  is_google_device = settings.is_google_device()
  if is_google_device is None:
    logs.log_error('Unable to query device. Reimaging failed.')
    adb.bad_state_reached()

  elif not is_google_device:
    # We can't reimage these, skip.
    logs.log('Non-Google device found, skipping reimage.')
    return

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

  image_directory = environment.get_value('IMAGES_DIR')
  build_info = fetch_artifact.get_latest_artifact_info(branch, target)
  if not build_info:
    logs.log_error('Unable to fetch information on latest build artifact for '
                   'branch %s and target %s.' % (branch, target))
    return

  if environment.is_android_cuttlefish():
    download_latest_build(build_info, FLASH_CUTTLEFISH_REGEXES, image_directory)
    adb.recreate_cuttlefish_device()
    adb.connect_to_cuttlefish_device()
  else:
    download_latest_build(build_info, FLASH_IMAGE_REGEXES, image_directory)
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

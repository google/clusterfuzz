# Copyright 2026 Google LLC
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
"""Tests for Android fastboot flashing."""

import os
import tempfile
import unittest

from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.platforms.android import flash
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class FlashTest(unittest.TestCase):
  """Tests for flash_to_latest_build_if_needed and image wildcard resolution."""

  def setUp(self):
    super().setUp()
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.persistent_cache.delete_value',
        'clusterfuzz._internal.base.persistent_cache.get_value',
        'clusterfuzz._internal.base.persistent_cache.set_value',
        'clusterfuzz._internal.datastore.locks.acquire_lock',
        'clusterfuzz._internal.datastore.locks.release_lock',
        'clusterfuzz._internal.metrics.monitoring_metrics.CF_TIP_BOOT_FAILED_COUNT',
        'clusterfuzz._internal.platforms.android.adb.execute_command',
        'clusterfuzz._internal.platforms.android.adb.get_device_state',
        'clusterfuzz._internal.platforms.android.adb.run_as_root',
        'clusterfuzz._internal.platforms.android.adb.run_command',
        'clusterfuzz._internal.platforms.android.fetch_artifact.get_latest_artifact_info',
        'clusterfuzz._internal.platforms.android.flash.download_latest_build',
        'clusterfuzz._internal.platforms.android.settings.is_google_device',
        'time.sleep',
    ])

  def test_flash_expands_bootloader_and_radio_wildcards_without_shell(self):
    """Tests that bootloader*.img and radio*.img resolve before fastboot argv."""
    with tempfile.TemporaryDirectory() as image_dir:
      bootloader_img = os.path.join(image_dir,
                                    'bootloader-shiba-ripcurrent-15.0.img')
      radio_img = os.path.join(image_dir, 'radio-shiba-g5300q-2409.img')
      boot_img = os.path.join(image_dir, 'boot.img')
      for path in (bootloader_img, radio_img, boot_img):
        with open(path, 'wb') as handle:
          handle.write(b'img')

      os.environ['OS_OVERRIDE'] = 'ANDROID'
      os.environ['FASTBOOT'] = '/usr/bin/fastboot'
      os.environ['BUILD_BRANCH'] = 'git_main'
      os.environ['BUILD_TARGET'] = 'shiba-userdebug'
      os.environ['IMAGES_DIR'] = image_dir

      self.mock.get_value.return_value = None
      self.mock.is_google_device.return_value = True
      self.mock.get_latest_artifact_info.return_value = {
          'bid': '123456',
          'branch': 'git_main',
          'target': 'shiba-userdebug',
      }
      self.mock.acquire_lock.return_value = True
      self.mock.get_device_state.return_value = 'device'
      self.mock.execute_command.return_value = ''

      flash.flash_to_latest_build_if_needed()

      parsed_argvs = [
          adb._build_host_command_args(  # pylint: disable=protected-access
              call_args[0][0],
              on_cuttlefish_host=False)
          for call_args in self.mock.execute_command.call_args_list
      ]
      self.assertIn(
          ['/usr/bin/fastboot', 'flash', 'bootloader', bootloader_img],
          parsed_argvs)
      self.assertIn(['/usr/bin/fastboot', 'flash', 'radio', radio_img],
                    parsed_argvs)
      self.assertIn(['/usr/bin/fastboot', 'flash', 'boot', boot_img],
                    parsed_argvs)
      for argv in parsed_argvs:
        for token in argv:
          self.assertNotIn('*', token)

  def test_flash_skips_unmatched_wildcard_partition(self):
    """Tests that a missing radio*.img on Wi-Fi-only targets is skipped."""
    with tempfile.TemporaryDirectory() as image_dir:
      bootloader_img = os.path.join(image_dir, 'bootloader-tangorpro-15.0.img')
      with open(bootloader_img, 'wb') as handle:
        handle.write(b'img')

      self.assertEqual(
          bootloader_img,
          flash._resolve_partition_image_path(  # pylint: disable=protected-access
              image_dir, 'bootloader*.img'))
      self.assertIsNone(
          flash._resolve_partition_image_path(  # pylint: disable=protected-access
              image_dir, 'radio*.img'))
      self.assertEqual(
          os.path.join(image_dir, 'boot.img'),
          flash._resolve_partition_image_path(  # pylint: disable=protected-access
              image_dir, 'boot.img'))

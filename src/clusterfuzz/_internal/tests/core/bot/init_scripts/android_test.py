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
"""Tests for the Android platform initialization script."""

import os
import sys
import tempfile
import textwrap
import unittest

from clusterfuzz._internal.bot.init_scripts import android
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class AndroidInitTest(unittest.TestCase):
  """End-to-end tests for Android platform initialization."""

  def setUp(self):
    super().setUp()
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.init_scripts.init_runner.run',
    ])

  def test_emulator_init_succeeds_without_lsusb_on_path(self):
    """Tests that android.run completes on ANDROID_EMULATOR without lsusb."""
    with tempfile.TemporaryDirectory() as temp_dir:
      bin_dir = os.path.join(temp_dir, 'bin')
      cache_dir = os.path.join(temp_dir, 'cache')
      os.makedirs(bin_dir)
      os.makedirs(cache_dir)
      adb_path = _write_fake_adb_binary(bin_dir)
      os.environ.pop('BUILD_BRANCH', None)
      os.environ.pop('BUILD_TARGET', None)
      os.environ['OS_OVERRIDE'] = 'ANDROID_EMULATOR'
      os.environ['ANDROID_SERIAL'] = 'emulator-5554'
      os.environ['ADB'] = adb_path
      os.environ['CACHE_DIR'] = cache_dir
      os.environ['PATH'] = bin_dir

      android.run()

      self.mock.run.assert_called_once()
      self.assertIsNone(environment.get_value('DEVICE_PATH'))
      self.assertEqual('android:emu64xa:U',
                       environment.get_value('PLATFORM_ID'))
      self.assertEqual('google', environment.get_value('PRODUCT_BRAND'))


def _write_fake_adb_binary(bin_dir: str) -> str:
  """Creates an executable fake adb script handling emulator init commands."""
  adb_path = os.path.join(bin_dir, 'adb')
  script = textwrap.dedent(f"""\
      #!{sys.executable}
      import sys

      cmd = ' '.join(sys.argv[1:])
      if 'wait-for-device' in cmd:
        sys.exit(0)
      if 'devices -l' in cmd:
        print('List of devices attached')
        print('emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emu64xa transport_id:1')
        sys.exit(0)
      if '/proc/uptime' in cmd:
        print('120.50 240.00')
        sys.exit(0)
      if 'test -d "/"' in cmd:
        print('0')
        sys.exit(0)
      if 'pm path android' in cmd:
        print('package:/system/framework/framework-res.apk')
        sys.exit(0)
      if 'sys.boot_completed' in cmd:
        print('1')
        sys.exit(0)
      if 'ro.build.fingerprint' in cmd:
        print('google/sdk_gphone64_x86_64/emu64xa:14/UE1A.230829.036/11000000:userdebug/dev-keys')
        sys.exit(0)
      if 'ro.build.id' in cmd:
        print('UE1A.230829.036')
        sys.exit(0)
      if 'ro.build.flavor' in cmd:
        print('sdk_gphone64_x86_64-userdebug')
        sys.exit(0)
      if 'ro.product.brand' in cmd:
        print('google')
        sys.exit(0)
      if 'ro.build.version.security_patch' in cmd:
        print('2026-01-05')
        sys.exit(0)
      sys.exit(0)
      """)
  with open(adb_path, 'w') as script_file:
    script_file.write(script)
  os.chmod(adb_path, 0o755)
  return adb_path

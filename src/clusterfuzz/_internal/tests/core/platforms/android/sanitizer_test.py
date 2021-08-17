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
"""Tests for sanitizer functions."""

import os

from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.platforms.android import constants
from clusterfuzz._internal.platforms.android import sanitizer
from clusterfuzz._internal.platforms.android import settings
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import android_helpers
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

DATA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'sanitizer_data')


class GetOptionsFilePathTest(android_helpers.AndroidTest):
  """Tests get_options_file_path."""

  def test_regular_build(self):
    """Test that options file path is returned inside device temp dir when
    device has ASan setup with partial instrumentation using asan_device_setup
    script."""
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.settings.get_sanitizer_tool_name'
    ])
    self.mock.get_sanitizer_tool_name.return_value = None

    self.assertEqual('/data/local/tmp/asan.options',
                     sanitizer.get_options_file_path('asan'))

  def test_system_asan_build(self):
    """Test that options file path is returned inside /system when device is
    setup with a full-system ASan build."""
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.settings.get_sanitizer_tool_name'
    ])
    self.mock.get_sanitizer_tool_name.return_value = 'asan'

    self.assertEqual('/system/asan.options',
                     sanitizer.get_options_file_path('asan'))

  def test_invalid(self):
    """Test that no options file path is returned with an invalid sanitizer
    name."""
    self.assertEqual(None, sanitizer.get_options_file_path('invalid'))

  def test_unsupported(self):
    """Test that no options file path is returned with an unsupported sanitizer
    e.g. UBSan, MSan."""
    self.assertEqual(None, sanitizer.get_options_file_path('msan'))
    self.assertEqual(None, sanitizer.get_options_file_path('tsan'))
    self.assertEqual(None, sanitizer.get_options_file_path('ubsan'))


class SetOptionsTest(android_helpers.AndroidTest):
  """Tests set_options."""

  def setUp(self):
    """Setup for set options test."""
    super(SetOptionsTest, self).setUp()

    test_helpers.patch(self, ['clusterfuzz._internal.metrics.logs.log_error'])

    if settings.get_sanitizer_tool_name():
      self.skipTest('This test is not applicable on a system sanitizer build.')

    # Clear and create temporary directory on device.
    self.device_temp_dir = constants.DEVICE_TMP_DIR
    adb.remove_directory(self.device_temp_dir, recreate=True)

  def test(self):
    """Test that options are successfully set with ASan."""
    sanitizer.set_options('ASAN', 'a=b:c=d')
    self.assertEqual('a=b:c=d',
                     adb.read_data_from_file('/data/local/tmp/asan.options'))
    self.assertEqual(0, self.mock.log_error.call_count)

  def test_unsupported(self):
    """Test that options are not set with an unsupported sanitizer e.g.
    UBSan, MSan, etc."""
    sanitizer.set_options('UBSAN', 'a=b:c=d')
    self.assertFalse(adb.file_exists('/data/local/tmp/ubsan.options'))
    self.assertEqual(1, self.mock.log_error.call_count)

  def test_invalid(self):
    """Test that options are not set with an invalid sanitizer name."""
    sanitizer.set_options('invalid', 'a=b:c=d')
    self.assertEqual(1, self.mock.log_error.call_count)


class SetupASanIfNeededTest(android_helpers.AndroidTest):
  """Tests setup_asan_if_needed."""

  def setUp(self):
    """Setup for setup ASan if needed test."""
    super(SetupASanIfNeededTest, self).setUp()

    test_helpers.patch(self, ['clusterfuzz._internal.metrics.logs.log_error'])

    if settings.get_sanitizer_tool_name():
      self.skipTest('This test is not applicable on a system sanitizer build.')

    environment.set_value('ASAN_DEVICE_SETUP', True)
    environment.set_value('JOB_NAME', 'android_asan_chrome')
    environment.set_value('APP_DIR', DATA_PATH)

  def test(self):
    """Test that ASan instrumentation can be successfully set up on device."""
    adb.revert_asan_device_setup_if_needed()
    environment.reset_current_memory_tool_options()
    sanitizer.setup_asan_if_needed()
    self.assertEqual(0, self.mock.log_error.call_count)
    self.assertTrue(adb.file_exists('/system/bin/asanwrapper'))

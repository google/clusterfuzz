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
"""Tests for path overrides"""

import os
import unittest

from clusterfuzz._internal.build_management import overrides
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

DATA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'overrides_data')


def _read_data_file(filename):
  return open(os.path.join(DATA_PATH, filename)).read()


class UpdateCheckAndApplyOverridesTest(unittest.TestCase):
  """Tests for update_build_or_revision_path."""

  def setUp(self):
    test_helpers.patch(
        self, ['clusterfuzz._internal.system.environment.get_platform_id'])
    test_helpers.patch(
        self, ['clusterfuzz._internal.google_cloud_utils.storage.read_data'])
    output = _read_data_file('test_config.json')
    self.mock.read_data.return_value = output.encode()
    test_helpers.patch_environ(self)

  def test_url_branch_update(self):
    """Ensure that the path is updated correctly based on platform_id."""
    self.mock.get_platform_id.return_value = 'android:seahawk_hwasan:s'
    curr_path = 'gs://auto/config.json'
    self.assertEqual(
        overrides.check_and_apply_overrides(
            curr_path, overrides.PLATFORM_ID_TO_BUILD_PATH_KEY),
        'gs://auto/git_s/something/%something%/([something]+).zip')

  def test_empty_platform_id(self):
    """Ensure that a path is not updated if the platform_id is empty."""
    self.mock.get_platform_id.return_value = ''
    curr_path = 'gs://auto/config.json'
    self.assertRaises(overrides.BuildOverrideError,
                      overrides.check_and_apply_overrides, curr_path,
                      overrides.PLATFORM_ID_TO_BUILD_PATH_KEY)

  def test_invalid_config_url(self):
    """Ensure that a path which does not point to config.json is not updated."""
    self.mock.get_platform_id.return_value = 'android:seahawk_hwasan:r'
    curr_path = 'gs://auto/git_r/something/something/' \
                '%something%/([something]+).zip'
    self.assertEqual(
        overrides.check_and_apply_overrides(
            curr_path, overrides.PLATFORM_ID_TO_BUILD_PATH_KEY), curr_path)

  def test_unknown_platform_id(self):
    """Ensure that a path is not updated if the platform_id is unknown."""
    self.mock.get_platform_id.return_value = 'unknown'
    curr_path = 'gs://auto/config.json'
    self.assertRaises(overrides.BuildOverrideError,
                      overrides.check_and_apply_overrides, curr_path,
                      overrides.PLATFORM_ID_TO_BUILD_PATH_KEY)

  def test_empty_config(self):
    """Ensure that a path is not updated if the config is empty."""
    self.mock.get_platform_id.return_value = 'android:seahawk_hwasan:r'
    self.mock.read_data.return_value = None
    curr_path = 'gs://auto/config.json'
    self.assertRaises(overrides.BuildOverrideError,
                      overrides.check_and_apply_overrides, curr_path,
                      overrides.PLATFORM_ID_TO_BUILD_PATH_KEY)

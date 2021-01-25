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
"""Tests for build info utilities."""

import os
import unittest

from internal.chrome import build_info
from tests.test_libs import helpers as test_helpers

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'build_info_data')
ALL_CSV = os.path.join(DATA_DIRECTORY, 'all.csv')


class BuildInfoTest(unittest.TestCase):
  """Tests BuildInfo utilities."""

  def setUp(self):
    test_helpers.patch(self, [
        'internal.base.utils.fetch_url',
    ])

    def _fetch_url(url):
      if url == build_info.BUILD_INFO_URL:
        return open(ALL_CSV, 'r').read()
      return None

    self.mock.fetch_url.side_effect = _fetch_url

  def _validate_build_info_list(self, actual_list, expected_list):
    """Validates actual list of BuildInfos matches expected list of tuples."""
    if expected_list is None:
      self.assertIsNone(actual_list)
      return

    actual_list_converted = [(info.platform, info.build_type, info.version,
                              info.revision) for info in actual_list]
    self.assertEqual(actual_list_converted, expected_list)

  def test_get_valid_platform(self):
    """Tests if a valid platform (WIN) results in the correct metadata list from
       OmahaProxy."""
    self._validate_build_info_list(
        build_info.get_production_builds_info('WINDOWS'),
        [
            # Note that canary_asan and win64 are omitted.
            ('WINDOWS', 'canary', '62.0.3187.0',
             '632559c0c94194aa462299ff5c2ed121dd8ce833'),
            ('WINDOWS', 'dev', '62.0.3178.0',
             'd682ac8276223315dbc95a65c87b09dea12506e5'),
            ('WINDOWS', 'beta', '61.0.3163.39',
             '5b3b74da7199443677af72c0f38974c5336f0072'),
            ('WINDOWS', 'stable', '60.0.3112.101',
             'bfd423326e0eba3fbb293a0cf29ededfe22871a8'),
        ])

  def test_get_invalid_platform(self):
    """Tests if an invalid platform results in the correct (empty) list."""
    self._validate_build_info_list(
        build_info.get_production_builds_info('foo'), [])

  def test_get_milestone_for_release(self):
    """Tests get_milestone_for_release."""
    for platform in ['android', 'linux', 'mac', 'windows']:
      self.assertEqual(build_info.get_release_milestone('stable', platform), 60)
      self.assertEqual(build_info.get_release_milestone('beta', platform), 61)
      self.assertEqual(build_info.get_release_milestone('head', platform), 62)

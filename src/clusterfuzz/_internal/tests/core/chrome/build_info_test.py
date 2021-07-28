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

import json
import os
import re
import unittest

from clusterfuzz._internal.chrome import build_info
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'build_info_data')
ALL_CSV = os.path.join(DATA_DIRECTORY, 'all.csv')
CD_ALL = os.path.join(DATA_DIRECTORY, 'chromium_dash_res_all.json')


class BuildInfoTest(unittest.TestCase):
  """Tests BuildInfo utilities."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.fetch_url',
    ])

    def _fetch_url(url):
      if url == build_info.BUILD_INFO_URL:
        return open(ALL_CSV, 'r').read()

      match = re.match(
          r'https://chromiumdash\.appspot\.com/fetch_releases\?'
          r'num=1&platform=([a-zA-Z0-9]+)($|&channel=([a-zA-Z]+))', url)
      if not match:
        return None
      res = []
      with open(CD_ALL, 'r') as all_info:
        info_json = json.load(all_info)
        for info in info_json:
          if info['platform'] == match.group(1):
            if match.group(3) and info['channel'] != match.group(3):
              continue
            res.append(info)
      return json.dumps(res)

    self.mock.fetch_url.side_effect = _fetch_url

  def _validate_build_info_list(self, actual_list, expected_list):
    """Validates actual list of BuildInfos matches expected list of tuples."""
    if expected_list is None:
      self.assertIsNone(actual_list)
      return

    actual_list_converted = [(info.platform, info.build_type, info.version,
                              info.revision) for info in actual_list]
    self.assertEqual(actual_list_converted, expected_list)

  # TODO(yuanjunh): remove unit tests for omahaproxy.
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

  def test_get_valid_platform_cd(self):
    """Tests if a valid platform (WIN) results in the correct metadata list from
       ChromiumDash."""
    self._validate_build_info_list(
        build_info.get_production_builds_info_from_cd('WINDOWS'),
        [
            # Note that canary_asan and win64 are omitted.
            ('WINDOWS', 'canary', '93.0.4557.2',
             '2023bf9b459f1d7798ffcb93de0ff5bf9556a4a6'),
            ('WINDOWS', 'stable', '91.0.4472.124',
             '7a7e35991d61ce564ed3641222da2c4ed7a65535'),
            ('WINDOWS', 'beta', '92.0.4515.70',
             'f8707b75c2349225c3c846d9016daf10a75abefb'),
            ('WINDOWS', 'dev', '93.0.4549.3',
             'bf8816161669f47681d64fb77c5e2317d1873de1'),
            ('WINDOWS', 'extended_stable', '91.0.4472.114',
             'c1e1dff6f551c4aab8578ec695825cc9b27d51e6'),
        ])

  def test_get_valid_linux_builds_info(self):
    """Tests if a valid Linux builds info in the correct metadata list from
       ChromiumDash."""
    self._validate_build_info_list(
        build_info.get_production_builds_info_from_cd('LINUX'), [
            ('LINUX', 'beta', '92.0.4515.70',
             'f8707b75c2349225c3c846d9016daf10a75abefb'),
            ('LINUX', 'dev', '93.0.4549.3',
             'bf8816161669f47681d64fb77c5e2317d1873de1'),
            ('LINUX', 'stable', '91.0.4472.114',
             'c1e1dff6f551c4aab8578ec695825cc9b27d51e6'),
            ('LINUX', 'extended_stable', '91.0.4472.114',
             'c1e1dff6f551c4aab8578ec695825cc9b27d51e6'),
        ])

  def test_get_invalid_platform_cd(self):
    """Tests if an invalid platform results in the correct (empty) list."""
    self._validate_build_info_list(
        build_info.get_production_builds_info_from_cd('foo'), [])

  def test_get_milestone_for_release_cd(self):
    """Tests get_milestone_for_release."""
    for platform in ['android', 'linux', 'mac', 'windows']:
      self.assertEqual(build_info.get_release_milestone('stable', platform), 91)
      self.assertEqual(build_info.get_release_milestone('beta', platform), 92)
      self.assertEqual(build_info.get_release_milestone('head', platform), 93)
      if platform != 'android':
        self.assertEqual(
            build_info.get_release_milestone('extended_stable', platform), 91)

  def test_get_build_to_revision_mappings_with_valid_platform(self):
    """Tests if a valid platform (WIN) results in the correct metadata dict from
       ChromiumDash."""
    result = build_info.get_build_to_revision_mappings('WINDOWS')
    expected_result = {
        'beta': {
            'revision': '885287',
            'version': '92.0.4515.70'
        },
        'canary': {
            'revision': '896380',
            'version': '93.0.4557.2'
        },
        'dev': {
            'revision': '894125',
            'version': '93.0.4549.3'
        },
        'stable': {
            'revision': '870763',
            'version': '91.0.4472.124'
        },
        'extended_stable': {
            'revision': '870763',
            'version': '91.0.4472.114'
        }
    }
    self.assertDictEqual(result, expected_result)

  def test_get_build_to_revision_mappings_for_linux(self):
    """Tests if a valid platform (Linux) results in the correct metadata dict
       from ChromiumDash."""
    result = build_info.get_build_to_revision_mappings('LINUX')
    expected_result = {
        'beta': {
            'revision': '885287',
            'version': '92.0.4515.70'
        },
        'dev': {
            'revision': '894125',
            'version': '93.0.4549.3'
        },
        'stable': {
            'revision': '870763',
            'version': '91.0.4472.114'
        },
        'extended_stable': {
            'revision': '870763',
            'version': '91.0.4472.114'
        }
    }
    self.assertDictEqual(result, expected_result)

  def test_get_build_to_revision_mappings_with_invalid_platform(self):
    """Tests if an invalid platform results in the correct (empty) dict."""
    result = build_info.get_build_to_revision_mappings('foo')
    self.assertEqual(result, {})

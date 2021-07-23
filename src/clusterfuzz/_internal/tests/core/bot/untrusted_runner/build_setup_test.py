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
"""Tests for build_setup."""

import os
import unittest

from clusterfuzz._internal.bot.untrusted_runner import build_setup
from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


def _failed_setup(*_):
  return False


def _mock_regular_build_setup(*_):
  os.environ['APP_PATH'] = '/release/bin/app'
  os.environ['APP_PATH_DEBUG'] = ''
  os.environ['APP_DIR'] = '/release/bin'
  os.environ['BUILD_DIR'] = '/release'
  os.environ['BUILD_URL'] = 'https://build/url.zip'
  return True


class BuildSetupTest(unittest.TestCase):
  """Tests for build setup (untrusted side)."""

  def setUp(self):
    test_helpers.patch(self, [
        ('regular_build_setup',
         'clusterfuzz._internal.build_management.build_manager.RegularBuild.setup'
        ),
    ])

    test_helpers.patch_environ(self)

  def test_setup_regular_build(self):
    """Test setup_regular_build."""
    request = untrusted_runner_pb2.SetupRegularBuildRequest(
        base_build_dir='/base',
        revision=1337,
        build_url='https://build/url.zip',
        target_weights={
            'bad_target': 0.1,
            'normal_target': 1.0
        })

    self.mock.regular_build_setup.side_effect = _mock_regular_build_setup
    response = build_setup.setup_regular_build(request)
    self.assertTrue(response.result)
    self.assertEqual(response.app_path, '/release/bin/app')
    self.assertEqual(response.app_path_debug, '')
    self.assertEqual(response.app_dir, '/release/bin')
    self.assertEqual(response.build_dir, '/release')
    self.assertEqual(response.build_url, 'https://build/url.zip')

    self.mock.regular_build_setup.side_effect = _failed_setup
    response = build_setup.setup_regular_build(request)
    self.assertFalse(response.result)
    self.assertFalse(response.HasField('app_path'))
    self.assertFalse(response.HasField('app_path_debug'))
    self.assertFalse(response.HasField('app_dir'))
    self.assertFalse(response.HasField('build_dir'))
    self.assertFalse(response.HasField('build_url'))

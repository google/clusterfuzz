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

from bot.untrusted_runner import build_setup
from protos import untrusted_runner_pb2
from tests.test_libs import helpers as test_helpers


def _failed_setup(_):
  return False


def _mock_regular_build_setup(_):
  os.environ['APP_PATH'] = '/release/bin/app'
  os.environ['APP_PATH_DEBUG'] = ''
  os.environ['APP_DIR'] = '/release/bin'
  os.environ['BUILD_DIR'] = '/release'
  os.environ['BUILD_URL'] = 'https://build/url.zip'
  return True


def _mock_symbolized_build_setup(_):
  os.environ['APP_PATH'] = '/release/bin/app'
  os.environ['APP_PATH_DEBUG'] = '/debug/bin/app'
  os.environ['APP_DIR'] = '/debug/bin'
  os.environ['BUILD_DIR'] = '/debug'
  os.environ['BUILD_URL'] = 'https://build/url-release.zip'
  return True


def _mock_production_build_setup(_):
  os.environ['APP_PATH'] = '/stable/bin/app'
  os.environ['APP_PATH_DEBUG'] = ''
  os.environ['APP_DIR'] = '/stable/bin'
  os.environ['BUILD_DIR'] = '/stable'
  os.environ['BUILD_URL'] = 'https://build/url-stable.zip'
  return True


class BuildSetupTest(unittest.TestCase):
  """Tests for build setup (untrusted side)."""

  def setUp(self):
    test_helpers.patch(self, [
        ('regular_build_setup',
         'build_management.build_manager.RegularBuild.setup'),
        ('symbolized_build_setup',
         'build_management.build_manager.SymbolizedBuild.setup'),
        ('production_build_setup',
         'build_management.build_manager.ProductionBuild.setup'),
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

  def test_setup_symbolized_build(self):
    """Test setup_symbolized_build."""
    request = untrusted_runner_pb2.SetupSymbolizedBuildRequest(
        base_build_dir='/base',
        revision=1337,
        release_build_url='https://build/url-release.zip',
        debug_build_url='https://build/url-debug.zip')

    self.mock.symbolized_build_setup.side_effect = _mock_symbolized_build_setup
    response = build_setup.setup_symbolized_build(request)
    self.assertTrue(response.result)
    self.assertEqual(response.app_path, '/release/bin/app')
    self.assertEqual(response.app_path_debug, '/debug/bin/app')
    self.assertEqual(response.app_dir, '/debug/bin')
    self.assertEqual(response.build_dir, '/debug')
    self.assertEqual(response.build_url, 'https://build/url-release.zip')

    self.mock.symbolized_build_setup.side_effect = _failed_setup
    response = build_setup.setup_symbolized_build(request)
    self.assertFalse(response.result)
    self.assertFalse(response.HasField('app_path'))
    self.assertFalse(response.HasField('app_path_debug'))
    self.assertFalse(response.HasField('app_dir'))
    self.assertFalse(response.HasField('build_dir'))
    self.assertFalse(response.HasField('build_url'))

  def test_setup_production_build(self):
    """Test setup_production_build."""
    request = untrusted_runner_pb2.SetupProductionBuildRequest(
        base_build_dir='/base',
        version='43.0.0.1',
        build_url='https://build/url-stable.zip',
        build_type='stable')

    self.mock.production_build_setup.side_effect = _mock_production_build_setup
    response = build_setup.setup_production_build(request)
    self.assertTrue(response.result)
    self.assertEqual(response.app_path, '/stable/bin/app')
    self.assertEqual(response.app_path_debug, '')
    self.assertEqual(response.app_dir, '/stable/bin')
    self.assertEqual(response.build_dir, '/stable')
    self.assertEqual(response.build_url, 'https://build/url-stable.zip')

    self.mock.production_build_setup.side_effect = _failed_setup
    response = build_setup.setup_production_build(request)
    self.assertFalse(response.result)
    self.assertFalse(response.HasField('app_path'))
    self.assertFalse(response.HasField('app_path_debug'))
    self.assertFalse(response.HasField('app_dir'))
    self.assertFalse(response.HasField('build_dir'))
    self.assertFalse(response.HasField('build_url'))

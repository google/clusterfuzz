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
"""Tests for build_setup_host."""

import os
import unittest

from clusterfuzz._internal.bot.untrusted_runner import build_setup_host
from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


def _mock_set_environment_vars(_):
  """Mock build_manager.set_environment_vars."""
  os.environ['APP_PATH'] = ''
  os.environ['APP_DIR'] = ''


class BuildSetupHostTest(unittest.TestCase):
  """Tests for build setup host (trusted side)."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.set_environment_vars',
        'clusterfuzz._internal.bot.untrusted_runner.host.stub',
    ])

    test_helpers.patch_environ(self)

  def test_remote_regular_build(self):
    """Test RemoteRegularBuild."""
    self.mock.stub().SetupRegularBuild.return_value = (
        untrusted_runner_pb2.SetupBuildResponse(
            result=True,
            app_path='/release/bin/app',
            app_path_debug='',
            app_dir='/release/bin',
            build_dir='/release',
            build_url='https://build/url.zip'))

    build = build_setup_host.RemoteRegularBuild('/', 1337,
                                                'https://build/url.zip')
    self.assertTrue(build.setup())
    self.assertEqual(os.environ['APP_PATH'], '/release/bin/app')
    self.assertEqual(os.environ['APP_PATH_DEBUG'], '')
    self.assertEqual(os.environ['APP_DIR'], '/release/bin')
    self.assertEqual(os.environ['BUILD_DIR'], '/release')
    self.assertEqual(os.environ['BUILD_URL'], 'https://build/url.zip')
    self.assertEqual(os.environ['APP_REVISION'], '1337')

    self.mock.stub().SetupRegularBuild.return_value = (
        untrusted_runner_pb2.SetupBuildResponse(result=False))
    self.assertFalse(build.setup())
    self.assertFalse(os.getenv('APP_PATH'))
    self.assertFalse(os.getenv('APP_PATH_DEBUG'))
    self.assertFalse(os.getenv('APP_DIR'))
    self.assertFalse(os.getenv('BUILD_DIR'))
    self.assertFalse(os.getenv('BUILD_URL'))
    self.assertFalse(os.getenv('APP_REVISION'))

  def test_set_env_vars_from_fuzzer(self):
    """Test setting APP_PATH etc from FUZZER_DIR as a fallback."""
    os.environ['FUZZER_DIR'] = '/fuzzer_dir'

    self.mock.stub().SetupRegularBuild.return_value = (
        untrusted_runner_pb2.SetupBuildResponse(
            result=True,
            app_path='',
            app_path_debug='',
            app_dir='',
            build_dir='/release',
            build_url='https://build/url.zip'))
    self.mock.set_environment_vars.side_effect = _mock_set_environment_vars

    build = build_setup_host.RemoteRegularBuild('/', 1337,
                                                'https://build/url.zip')
    self.assertTrue(build.setup())
    self.assertEqual(os.getenv('APP_PATH'), '')
    self.assertEqual(os.getenv('APP_DIR'), '')
    self.assertEqual(os.getenv('BUILD_DIR'), '/release')
    self.assertEqual(os.getenv('BUILD_URL'), 'https://build/url.zip')
    self.assertEqual(os.getenv('APP_REVISION'), '1337')

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
"""modules tests."""
# pylint: disable=protected-access
import os
import sys
import unittest
from unittest import mock

from clusterfuzz._internal.base import modules


class ConfigModulesDirectoryTest(unittest.TestCase):
  """Test _config_modules_directory."""

  def test_default_config_dir(self):
    """Test default config directory when override is not set."""
    with mock.patch.dict(os.environ, {}, clear=True):
      res = modules._config_modules_directory('/root')
      self.assertEqual(
          res, os.path.join('/root', 'src', 'appengine', 'config', 'modules'))

  def test_override_config_dir(self):
    """Test config directory when CONFIG_DIR_OVERRIDE is set."""
    with mock.patch.dict(os.environ, {'CONFIG_DIR_OVERRIDE': '/custom_config'}):
      res = modules._config_modules_directory('/root')
      self.assertEqual(res, os.path.join('/custom_config', 'modules'))


class PatchAppEngineModulesForBotsTest(unittest.TestCase):
  """Test _patch_appengine_modules_for_bots."""

  def test_appengine_environment(self):
    """Test that it does nothing on App Engine (SERVER_SOFTWARE set)."""
    with mock.patch.dict(os.environ, {'SERVER_SOFTWARE': 'Development/2.0'}):
      mock_auth = mock.MagicMock()
      mock_auth.app_identity = mock.MagicMock()
      with mock.patch.dict(
          sys.modules, {
              'google': mock.MagicMock(),
              'google.auth': mock.MagicMock(app_engine=mock_auth),
              'google.auth.app_engine': mock_auth
          }):
        modules._patch_appengine_modules_for_bots()
        self.assertIsNotNone(mock_auth.app_identity)

  def test_bot_environment(self):
    """Test patching on bot environment."""
    with mock.patch.dict(os.environ, {}, clear=True):
      mock_auth = mock.MagicMock()
      mock_auth.app_identity = mock.MagicMock()
      with mock.patch.dict(
          sys.modules, {
              'google': mock.MagicMock(),
              'google.auth': mock.MagicMock(app_engine=mock_auth),
              'google.auth.app_engine': mock_auth
          }):
        modules._patch_appengine_modules_for_bots()
        self.assertIsNone(mock_auth.app_identity)


class FixModuleSearchPathsTest(unittest.TestCase):
  """Test fix_module_search_paths."""

  @mock.patch(
      'clusterfuzz._internal.base.modules._patch_appengine_modules_for_bots')
  @mock.patch('site.addsitedir')
  @mock.patch('os.path.exists')
  def test_fix_module_search_paths(self, mock_exists, mock_addsitedir,
                                   mock_patch):
    """Test fix_module_search_paths adds paths correctly."""
    mock_exists.return_value = True
    root = '/fake_root'
    with mock.patch.dict(
        os.environ, {
            'ROOT_DIR': root,
            'PYTHONPATH': ''
        }, clear=True):
      with mock.patch.object(sys, 'path', ['/existing_path']):
        modules.fix_module_search_paths()

        expected_config_modules = os.path.join(root, 'src', 'appengine',
                                               'config', 'modules')
        expected_third_party = os.path.join(root, 'src', 'third_party')
        expected_src = os.path.join(root, 'src')

        self.assertIn(expected_config_modules, sys.path)
        self.assertIn(expected_third_party, sys.path)
        self.assertIn(expected_src, sys.path)

        mock_addsitedir.assert_called_once_with(expected_third_party)
        mock_patch.assert_called_once()

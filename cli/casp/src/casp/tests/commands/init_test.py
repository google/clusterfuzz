# Copyright 2025 Google LLC
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
"""Tests for the init command.

   For running all the tests, use (from the root of the project):
   python -m unittest discover -s cli/casp/src/casp/tests -p init_test.py -v
"""

import os
import unittest
from unittest.mock import patch

from casp.commands import init
from click.testing import CliRunner


class InitCliTest(unittest.TestCase):
  """Tests for the init command."""

  def setUp(self):
    super().setUp()
    self.runner = CliRunner()

    # Patch dependencies
    self.mock_docker_utils = self.enterContext(
        patch.object(init, 'docker_utils', autospec=True))
    self.mock_gcloud = self.enterContext(
        patch.object(init, 'gcloud', autospec=True))
    self.mock_config = self.enterContext(
        patch.object(init, 'config', autospec=True))
    self.mock_os_path_exists = self.enterContext(
        patch.object(os.path, 'exists', autospec=True))

    # Default mock behaviors for success paths
    self.mock_docker_utils.check_docker_setup.return_value = True
    self.mock_docker_utils.pull_image.return_value = True
    credentials_path = '/fake/path/credentials.json'
    self.mock_gcloud.get_credentials_path.return_value = credentials_path
    self.mock_config.load_config.return_value = {}
    self.mock_config.CONFIG_FILE = '~/.casp/config.json'

  def test_init_success_all_steps(self):
    """Tests successful initialization through all steps, no custom config."""
    result = self.runner.invoke(
        init.cli, input='\n')  # Enter for optional prompt

    self.assertEqual(0, result.exit_code)
    self.assertIn('Docker setup is correct.', result.output)
    self.assertIn('gcloud authentication is configured correctly.',
                  result.output)
    self.assertIn('Initialization complete.', result.output)

    self.mock_docker_utils.check_docker_setup.assert_called_once()
    self.mock_gcloud.get_credentials_path.assert_called_once()
    expected_config = {'gcloud_credentials_path': '/fake/path/credentials.json'}
    self.mock_config.save_config.assert_called_once_with(expected_config)
    self.mock_docker_utils.pull_image.assert_called_once()

  def test_init_docker_setup_fails(self):
    """Tests when Docker setup check fails."""
    self.mock_docker_utils.check_docker_setup.return_value = False
    result = self.runner.invoke(init.cli)

    self.assertNotEqual(0, result.exit_code)  # Should indicate failure
    self.assertIn('Docker setup check failed.', result.output)
    self.assertNotIn('Initialization complete.', result.output)
    self.mock_gcloud.get_credentials_path.assert_not_called()

  def test_init_gcloud_auth_fails(self):
    """Tests when gcloud authentication fails."""
    self.mock_gcloud.get_credentials_path.return_value = None
    result = self.runner.invoke(init.cli)

    self.assertNotEqual(0, result.exit_code)
    self.assertIn('gcloud authentication check failed.', result.output)
    self.assertNotIn('Initialization complete.', result.output)
    self.mock_config.save_config.assert_not_called()
    self.mock_docker_utils.pull_image.assert_not_called()

  def test_init_docker_pull_fails(self):
    """Tests when Docker image pull fails."""
    self.mock_docker_utils.pull_image.return_value = False
    result = self.runner.invoke(init.cli, input='\n')

    self.assertNotEqual(0, result.exit_code)
    self.assertIn('Error: Failed to pull Docker image', result.output)
    self.assertIn('Initialization failed.', result.output)
    self.assertNotIn('Initialization complete.', result.output)

  def test_init_with_existing_config(self):
    """Tests that existing config is loaded and updated."""
    self.mock_config.load_config.return_value = {
        'existing_key': 'existing_value'
    }
    result = self.runner.invoke(init.cli, input='\n')

    self.assertEqual(0, result.exit_code)
    expected_config = {
        'existing_key': 'existing_value',
        'gcloud_credentials_path': '/fake/path/credentials.json'
    }
    self.mock_config.save_config.assert_called_once_with(expected_config)

  def test_init_custom_config_path_success(self):
    """Tests providing a valid custom config path."""
    custom_path = '/my/custom/config/dir'
    self.mock_os_path_exists.return_value = True  # Path exists
    self.mock_config.load_config.return_value = {}

    result = self.runner.invoke(init.cli, input=f'{custom_path}\n')

    self.assertEqual(0, result.exit_code)
    self.mock_os_path_exists.assert_any_call(custom_path)
    expected_config = {
        'gcloud_credentials_path': '/fake/path/credentials.json',
        'custom_config_path': custom_path
    }
    self.mock_config.save_config.assert_called_once_with(expected_config)
    self.assertIn(f'Custom config path set to: {custom_path}', result.output)
    self.assertIn('Initialization complete.', result.output)

  def test_init_custom_config_path_not_exists(self):
    """Tests providing a custom config path that does not exist."""
    custom_path = '/non/existent/dir'
    self.mock_os_path_exists.return_value = False  # Path does not exist
    self.mock_config.load_config.return_value = {}

    result = self.runner.invoke(init.cli, input=f'{custom_path}\n')

    self.assertEqual(0, result.exit_code)
    self.mock_os_path_exists.assert_any_call(custom_path)
    expected_config = {'gcloud_credentials_path': '/fake/path/credentials.json'}
    self.mock_config.save_config.assert_called_once_with(expected_config)
    self.assertIn(f'Custom config path "{custom_path}" does not exist.',
                  result.output)
    self.assertIn('Skipping.', result.output)
    self.assertNotIn('Custom config path set to', result.output)
    self.assertIn('Initialization complete.', result.output)

  def test_init_custom_config_path_empty(self):
    """Tests providing an empty custom config path (skipping)."""
    self.mock_config.load_config.return_value = {}
    result = self.runner.invoke(init.cli, input='\n')  # Just press Enter

    self.assertEqual(0, result.exit_code)
    expected_config = {'gcloud_credentials_path': '/fake/path/credentials.json'}
    self.mock_config.save_config.assert_called_once_with(expected_config)
    self.assertNotIn('Custom config path set to', result.output)
    self.assertNotIn('Cleared custom config path', result.output)
    self.assertIn('Initialization complete.', result.output)

  def test_init_custom_config_path_empty_clears_existing(self):
    """Tests that an empty input for custom 
    config path clears an existing one."""
    self.mock_config.load_config.return_value = {
        'custom_config_path': '/my/old/path'
    }
    result = self.runner.invoke(init.cli, input='\n')

    self.assertEqual(0, result.exit_code)
    expected_config = {'gcloud_credentials_path': '/fake/path/credentials.json'}
    self.mock_config.save_config.assert_called_once_with(expected_config)
    self.assertIn('Cleared custom config path.', result.output)


if __name__ == '__main__':
  unittest.main()

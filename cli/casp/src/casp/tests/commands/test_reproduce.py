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
"""Tests for the reproduce command.

  For running all the tests, use (from the root of the project):
  python -m unittest discover -s cli/casp/src/casp/tests -p test_reproduce.py -v
"""

import unittest
from unittest.mock import patch

from casp.commands import reproduce
from click.testing import CliRunner


class ReproduceCliTest(unittest.TestCase):
  """Tests for the reproduce command."""

  def setUp(self):
    self.runner = CliRunner()
    self.mock_config = self.enterContext(
        patch.object(reproduce, 'config', autospec=True))
    self.mock_docker_utils = self.enterContext(
        patch.object(reproduce, 'docker_utils', autospec=True))

  def test_reproduce_success(self):
    """Tests successful reproduction with default options."""
    self.mock_config.load_config.return_value = {
        'gcloud_credentials_path': '/fake/credentials/path'
    }
    self.mock_docker_utils.run_command.return_value = True

    result = self.runner.invoke(reproduce.cli, ['--testcase-id', '123'])

    self.assertEqual(0, result.exit_code)
    self.mock_docker_utils.run_command.assert_called_once()

  def test_reproduce_success_with_custom_config(self):
    """Tests successful reproduction with a custom config path."""
    self.mock_config.load_config.return_value = {
        'gcloud_credentials_path': '/fake/credentials/path',
        'custom_config_path': '/my/custom/config'
    }
    self.mock_docker_utils.run_command.return_value = True

    result = self.runner.invoke(reproduce.cli, ['--testcase-id', '123'])

    self.assertEqual(0, result.exit_code)
    self.assertIn('Using custom config directory: /my/custom/config',
                  result.output)
    self.mock_docker_utils.run_command.assert_called_once()
    args, _ = self.mock_docker_utils.run_command.call_args
    self.assertIn('config-dir=/data/clusterfuzz/src/appengine/custom_config',
                  args[0][2])
    self.assertIn('/my/custom/config', args[1])

  def test_reproduce_no_config(self):
    """Tests when no config is found."""
    self.mock_config.load_config.return_value = None
    result = self.runner.invoke(reproduce.cli, ['--testcase-id', '123'])

    self.assertNotEqual(0, result.exit_code)
    self.assertIn('Error: gcloud credentials not found.', result.output)
    self.mock_docker_utils.run_command.assert_not_called()

  def test_reproduce_no_gcloud_credentials(self):
    """Tests when gcloud credentials are not in the config."""
    self.mock_config.load_config.return_value = {}
    result = self.runner.invoke(reproduce.cli, ['--testcase-id', '123'])

    self.assertNotEqual(0, result.exit_code)
    self.assertIn('Error: gcloud credentials not found.', result.output)
    self.mock_docker_utils.run_command.assert_not_called()

  def test_reproduce_docker_command_fails(self):
    """Tests when the docker command fails."""
    self.mock_config.load_config.return_value = {
        'gcloud_credentials_path': '/fake/credentials/path'
    }
    self.mock_docker_utils.run_command.return_value = False

    result = self.runner.invoke(reproduce.cli, ['--testcase-id', '123'])

    self.assertNotEqual(0, result.exit_code)
    self.mock_docker_utils.run_command.assert_called_once()

  def test_reproduce_with_project_option(self):
    """Tests that the --project option is passed to docker_utils."""
    self.mock_config.load_config.return_value = {
        'gcloud_credentials_path': '/fake/credentials/path'
    }
    self.mock_docker_utils.run_command.return_value = True
    self.mock_docker_utils.PROJECT_TO_IMAGE = {'dev': 'dev-image'}

    result = self.runner.invoke(reproduce.cli,
                                ['--testcase-id', '123', '--project', 'dev'])

    self.assertEqual(0, result.exit_code)
    self.mock_docker_utils.run_command.assert_called_once()
    _, kwargs = self.mock_docker_utils.run_command.call_args
    self.assertEqual(self.mock_docker_utils.PROJECT_TO_IMAGE['dev'],
                     kwargs.get('image'))


if __name__ == '__main__':
  unittest.main()

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
  python -m unittest discover -s cli/casp/src/casp/tests -p reproduce_test.py -v
"""

from pathlib import Path
import unittest
from unittest.mock import patch

from casp.commands import reproduce
from click.testing import CliRunner


class ReproduceCliTest(unittest.TestCase):
  """Tests for the reproduce command."""

  def setUp(self):
    self.runner = CliRunner()
    self.mock_config = self.enterContext(
        patch('casp.commands.reproduce.config', autospec=True))
    self.mock_docker_utils = self.enterContext(
        patch('casp.commands.reproduce.docker_utils', autospec=True))
    self.mock_container = self.enterContext(
        patch('casp.commands.reproduce.container', autospec=True))

  def test_reproduce_success(self):
    """Tests successful reproduction with default options."""
    self.mock_config.load_and_validate_config.return_value = {
        'gcloud_credentials_path': '/fake/credentials/path'
    }
    self.mock_docker_utils.prepare_docker_volumes.return_value = ({
        '/fake/credentials': {
            'bind': '/root/.config/gcloud/',
            'mode': 'rw'
        }
    }, Path('/container/config/dir'))
    self.mock_container.build_butler_command.return_value = ['run']
    self.mock_docker_utils.run_command.return_value = True

    result = self.runner.invoke(
        reproduce.cli, ['--testcase-id', '123', '--project', 'internal'])

    self.assertEqual(0, result.exit_code, msg=result.output)
    self.mock_docker_utils.run_command.assert_called_once_with(
        ['run'],
        {'/fake/credentials': {
            'bind': '/root/.config/gcloud/',
            'mode': 'rw'
        }},
        privileged=True,
        image=self.mock_docker_utils.PROJECT_TO_IMAGE['internal'],
    )

  def test_reproduce_success_with_custom_config(self):
    """Tests successful reproduction with a custom config path."""
    self.mock_config.load_and_validate_config.return_value = {
        'gcloud_credentials_path': '/fake/credentials/path',
        'custom_config_path': '/my/custom/config'
    }
    self.mock_docker_utils.prepare_docker_volumes.return_value = ({
        '/fake/credentials': {
            'bind': '/root/.config/gcloud/',
            'mode': 'rw'
        },
        '/my/custom/config': {
            'bind': '/container/custom/config',
            'mode': 'rw'
        }
    }, Path('/container/custom/config'))
    self.mock_container.build_butler_command.return_value = ['run']
    self.mock_docker_utils.run_command.return_value = True

    result = self.runner.invoke(
        reproduce.cli, ['--testcase-id', '123', '--project', 'internal'])

    self.assertEqual(0, result.exit_code, msg=result.output)
    self.mock_docker_utils.run_command.assert_called_once()
    self.mock_container.build_butler_command.assert_called_once_with(
        'reproduce',
        config_dir='/container/custom/config',
        testcase_id='123',
    )

  def test_reproduce_no_config(self):
    """Tests when no config is found."""
    self.mock_config.load_and_validate_config.side_effect = SystemExit(1)
    result = self.runner.invoke(
        reproduce.cli, ['--testcase-id', '123', '--project', 'internal'])

    self.assertEqual(1, result.exit_code)
    self.mock_docker_utils.run_command.assert_not_called()

  def test_reproduce_no_gcloud_credentials(self):
    """Tests when gcloud credentials are not in the config."""
    self.mock_config.load_and_validate_config.side_effect = SystemExit(1)
    result = self.runner.invoke(
        reproduce.cli, ['--testcase-id', '123', '--project', 'internal'])

    self.assertEqual(1, result.exit_code)
    self.mock_docker_utils.run_command.assert_not_called()

  def test_reproduce_docker_command_fails(self):
    """Tests when the docker command fails."""
    self.mock_config.load_and_validate_config.return_value = {
        'gcloud_credentials_path': '/fake/credentials/path'
    }
    self.mock_docker_utils.run_command.return_value = False
    self.mock_docker_utils.prepare_docker_volumes.return_value = (
        {}, Path('/mock/path'))
    self.mock_container.build_butler_command.return_value = ['fail']

    result = self.runner.invoke(
        reproduce.cli, ['--testcase-id', '123', '--project', 'internal'])

    self.assertEqual(1, result.exit_code)
    self.mock_docker_utils.run_command.assert_called_once()

  def test_reproduce_with_project_option(self):
    """Tests that the --project option is passed to docker_utils."""
    self.mock_config.load_and_validate_config.return_value = {
        'gcloud_credentials_path': '/fake/credentials/path'
    }
    self.mock_docker_utils.prepare_docker_volumes.return_value = (
        {}, Path('/mock/path'))
    self.mock_container.build_butler_command.return_value = ['false']
    self.mock_docker_utils.run_command.return_value = True
    self.mock_docker_utils.PROJECT_TO_IMAGE = {'dev': 'dev-image'}

    result = self.runner.invoke(reproduce.cli,
                                ['--testcase-id', '123', '--project', 'dev'])

    self.assertEqual(0, result.exit_code, msg=result.output)
    self.mock_docker_utils.run_command.assert_called_once()
    _, kwargs = self.mock_docker_utils.run_command.call_args
    self.assertEqual(self.mock_docker_utils.PROJECT_TO_IMAGE['dev'],
                     kwargs.get('image'))


if __name__ == '__main__':
  unittest.main()

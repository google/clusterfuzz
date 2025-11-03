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
"""Tests for docker utility functions.

  For running, use (from the root of the project):
  python -m unittest discover -s cli/casp/src/casp/tests -p test_docker.py -v
"""

import os
import unittest
from unittest.mock import call
from unittest.mock import create_autospec
from unittest.mock import patch

from casp.utils import docker_utils

import docker


class CheckDockerSetupTest(unittest.TestCase):
  """Tests for check_docker_setup."""

  @patch('docker.from_env', autospec=True)
  @patch('click.secho', autospec=True)
  @patch('click.echo', autospec=True)
  def test_docker_setup_ok(self, mock_echo, mock_secho, mock_from_env):
    """Tests when Docker is setup correctly."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_from_env.return_value = mock_client
    mock_client.ping.return_value = True

    client = docker_utils.check_docker_setup()

    self.assertIsNotNone(client)
    self.assertEqual(client, mock_client)
    mock_from_env.assert_called_once()
    mock_client.ping.assert_called_once()
    mock_echo.assert_not_called()
    mock_secho.assert_not_called()

  @patch.dict(os.environ, {'USER': 'testuser'}, clear=True)
  @patch('docker.from_env', autospec=True)
  @patch('click.secho', autospec=True)
  @patch('click.echo', autospec=True)
  def test_docker_permission_denied(self, mock_echo, mock_secho, mock_from_env):
    """Tests when DockerException is raised due to permission issues."""
    mock_from_env.side_effect = docker.errors.DockerException(
        "Permission denied while connecting to the Docker daemon")

    client = docker_utils.check_docker_setup()

    self.assertIsNone(client)
    mock_from_env.assert_called_once()
    mock_secho.assert_has_calls([
        call(
            'Error: Permission denied while connecting to the Docker daemon.',
            fg='red'),
        call('  sudo usermod -aG docker $testuser', fg='yellow')
    ])
    mock_echo.assert_has_calls([
        call('Please add your user to the "docker" group by running:'),
        call('Then, log out and log back in for the change to take effect.')
    ])

  @patch('docker.from_env', autospec=True)
  @patch('click.secho', autospec=True)
  @patch('click.echo', autospec=True)
  def test_docker_not_running(self, mock_echo, mock_secho, mock_from_env):
    """Tests when DockerException is raised for other reasons."""
    mock_from_env.side_effect = docker.errors.DockerException("Generic Docker "
                                                              "error")

    client = docker_utils.check_docker_setup()

    self.assertIsNone(client)
    mock_from_env.assert_called_once()
    mock_secho.assert_called_once()
    args, _ = mock_secho.call_args
    self.assertIn('Docker is not running', args[0])
    mock_echo.assert_not_called()

  @patch('docker.from_env', autospec=True)
  @patch('click.secho', autospec=True)
  @patch('click.echo', autospec=True)
  def test_docker_ping_fails(self, mock_echo, mock_secho, mock_from_env):
    """Tests when client.ping() fails by raising an exception."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_from_env.return_value = mock_client
    mock_client.ping.side_effect = docker.errors.DockerException("Ping failed")

    client = docker_utils.check_docker_setup()

    self.assertIsNone(client)
    mock_from_env.assert_called_once()
    mock_client.ping.assert_called_once()
    mock_secho.assert_called_once()
    args, _ = mock_secho.call_args
    self.assertIn('Docker is not running', args[0])
    mock_echo.assert_not_called()


class PullImageTest(unittest.TestCase):
  """Tests for pull_image."""

  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  @patch('click.secho', autospec=True)
  @patch('click.echo', autospec=True)
  def test_pull_image_success(self, mock_echo, mock_secho,
                              mock_check_docker_setup):
    """Tests successful image pull."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client

    mock_images_collection = create_autospec(
        docker.models.images.ImageCollection, instance=True, spec_set=True)
    mock_client.images = mock_images_collection

    result = docker_utils.pull_image()

    self.assertTrue(result)
    mock_echo.assert_called_once()
    args, _ = mock_echo.call_args
    self.assertIn('Pulling Docker image:', args[0])
    mock_check_docker_setup.assert_called_once()
    mock_images_collection.pull.assert_called_once_with(
        docker_utils.DOCKER_IMAGE)
    mock_secho.assert_not_called()

  @patch(
      'casp.utils.docker_utils.check_docker_setup',
      return_value=None,
      autospec=True)
  @patch('click.secho', autospec=True)
  @patch('click.echo', autospec=True)
  def test_pull_image_docker_setup_fails(self, mock_echo, mock_secho,
                                         mock_check_docker_setup):
    """Tests when check_docker_setup returns None."""
    result = docker_utils.pull_image()

    self.assertFalse(result)
    mock_check_docker_setup.assert_called_once()
    mock_echo.assert_not_called()
    mock_secho.assert_not_called()

  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  @patch('click.secho', autospec=True)
  @patch('click.echo', autospec=True)
  def test_pull_image_not_found(self, mock_echo, mock_secho,
                                mock_check_docker_setup):
    """Tests when the image pull raises DockerException."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client

    mock_images_collection = create_autospec(
        docker.models.images.ImageCollection, instance=True, spec_set=True)
    mock_client.images = mock_images_collection
    mock_images_collection.pull.side_effect = docker.errors.DockerException(
        "Image not found")

    result = docker_utils.pull_image()

    self.assertFalse(result)
    mock_echo.assert_called_once_with(
        f'Pulling Docker image: {docker_utils.DOCKER_IMAGE}...')
    mock_check_docker_setup.assert_called_once()
    mock_images_collection.pull.assert_called_once_with(
        docker_utils.DOCKER_IMAGE)
    mock_secho.assert_called_once_with(
        f'Error: Docker image {docker_utils.DOCKER_IMAGE} not found.', fg='red')


if __name__ == '__main__':
  unittest.main()

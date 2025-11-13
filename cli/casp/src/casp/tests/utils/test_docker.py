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
        docker_utils.PROJECT_TO_IMAGE["internal"])
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
        f'Pulling Docker image: {docker_utils.PROJECT_TO_IMAGE["internal"]}...')
    mock_check_docker_setup.assert_called_once()
    mock_images_collection.pull.assert_called_once_with(
        docker_utils.PROJECT_TO_IMAGE["internal"])
    mock_secho.assert_called_once()
    args, _ = mock_secho.call_args
    self.assertIn('not found', args[0])


class RunCommandTest(unittest.TestCase):
  """Tests for run_command."""

  @patch('casp.utils.docker_utils.pull_image', return_value=True, autospec=True)
  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  @patch('click.secho', autospec=True)
  @patch('click.echo', autospec=True)
  def test_run_command_success(self, mock_echo, mock_secho,
                               mock_check_docker_setup, mock_pull_image):
    """Tests successful command execution."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client

    mock_container = create_autospec(
        docker.models.containers.Container, instance=True, spec_set=True)
    mock_client.containers.run.return_value = mock_container
    mock_container.logs.return_value = [b'line 1\n', b'line 2\n']
    mock_container.wait.return_value = {'StatusCode': 0}

    command = ['echo', 'hello']
    volumes = {'/tmp': {'bind': '/data', 'mode': 'rw'}}
    result = docker_utils.run_command(command, volumes)

    self.assertTrue(result)
    mock_check_docker_setup.assert_called_once()
    mock_pull_image.assert_called_once_with(
        docker_utils.PROJECT_TO_IMAGE['internal'])
    mock_client.containers.run.assert_called_once_with(
        docker_utils.PROJECT_TO_IMAGE['internal'],
        command,
        volumes=volumes,
        working_dir='/data/clusterfuzz',
        privileged=False,
        detach=True,
        remove=False)
    mock_container.logs.assert_called_once_with(stream=True, follow=True)
    mock_echo.assert_any_call('line 1')
    mock_echo.assert_any_call('line 2')
    mock_container.wait.assert_called_once()
    mock_container.remove.assert_called_once()
    mock_secho.assert_not_called()

  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  def test_run_command_privileged(self, mock_check_docker_setup):
    """Tests running a command with privileged=True."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client

    mock_container = create_autospec(
        docker.models.containers.Container, instance=True, spec_set=True)
    mock_client.containers.run.return_value = mock_container
    mock_container.logs.return_value = []
    mock_container.wait.return_value = {'StatusCode': 0}

    command = ['echo', 'hello']
    volumes = {}
    docker_utils.run_command(command, volumes, privileged=True)

    mock_client.containers.run.assert_called_once_with(
        docker_utils.PROJECT_TO_IMAGE['internal'],
        command,
        volumes=volumes,
        working_dir='/data/clusterfuzz',
        privileged=True,
        detach=True,
        remove=False)

  @patch('casp.utils.docker_utils.pull_image', autospec=True)
  @patch(
      'casp.utils.docker_utils.check_docker_setup',
      return_value=None,
      autospec=True)
  @patch('click.secho', autospec=True)
  @patch('click.echo', autospec=True)
  def test_run_command_docker_setup_fails(
      self, mock_echo, mock_secho, mock_check_docker_setup, mock_pull_image):
    """Tests when check_docker_setup fails."""
    command = ['echo', 'hello']
    volumes = {'/tmp': {'bind': '/data', 'mode': 'rw'}}
    result = docker_utils.run_command(command, volumes)

    self.assertFalse(result)
    mock_check_docker_setup.assert_called_once()
    mock_pull_image.assert_not_called()
    mock_echo.assert_not_called()
    mock_secho.assert_not_called()

  @patch(
      'casp.utils.docker_utils.pull_image', return_value=False, autospec=True)
  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  def test_run_command_pull_image_fails(self, mock_check_docker_setup,
                                        mock_pull_image):
    """Tests when pull_image fails."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client

    command = ['echo', 'hello']
    volumes = {'/tmp': {'bind': '/data', 'mode': 'rw'}}
    result = docker_utils.run_command(command, volumes)

    self.assertFalse(result)
    mock_check_docker_setup.assert_called_once()
    mock_pull_image.assert_called_once()
    mock_client.containers.run.assert_not_called()

  @patch('casp.utils.docker_utils.pull_image', return_value=True, autospec=True)
  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  @patch('click.secho', autospec=True)
  def test_run_command_container_error_status(
      self, mock_secho, mock_check_docker_setup, mock_pull_image):
    """Tests when command fails with a non-zero status code."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client

    mock_container = create_autospec(
        docker.models.containers.Container, instance=True, spec_set=True)
    mock_client.containers.run.return_value = mock_container
    mock_container.logs.side_effect = [
        [b'line 1\n'],  # For the streaming logs
        b'error log'  # For the final logs on error
    ]
    mock_container.wait.return_value = {'StatusCode': 1}

    command = ['false']
    volumes = {}
    result = docker_utils.run_command(command, volumes)

    self.assertFalse(result)
    mock_check_docker_setup.assert_called_once()
    mock_pull_image.assert_called_once()
    mock_client.containers.run.assert_called_once()
    self.assertEqual(mock_container.logs.call_count, 2)
    mock_container.wait.assert_called_once()
    mock_secho.assert_any_call(
        'Error: Command failed in Docker container with exit code 1.', fg='red')
    mock_secho.assert_any_call('error log', fg='red')
    mock_container.remove.assert_called_once()

  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  @patch('click.secho', autospec=True)
  def test_run_command_container_error_exception_with_stderr(
      self, mock_secho, mock_check_docker_setup):
    """Tests ContainerError with stderr."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client
    mock_exception = docker.errors.ContainerError(
        None, 1, 'cmd', 'img', stderr=b'error details')
    mock_client.containers.run.side_effect = mock_exception

    result = docker_utils.run_command(['fail'], {})

    self.assertFalse(result)
    mock_secho.assert_any_call(
        f'Error: Command failed in Docker container: {mock_exception}',
        fg='red')
    mock_secho.assert_any_call('error details', fg='red')

  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  @patch('click.secho', autospec=True)
  def test_run_command_container_error_exception_no_stderr(
      self, mock_secho, mock_check_docker_setup):
    """Tests ContainerError without stderr."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client
    mock_exception = docker.errors.ContainerError(
        None, 1, 'cmd', 'img', stderr=None)
    mock_client.containers.run.side_effect = mock_exception

    result = docker_utils.run_command(['fail'], {})

    self.assertFalse(result)
    mock_secho.assert_called_once_with(
        f'Error: Command failed in Docker container: {mock_exception}',
        fg='red')

  @patch('casp.utils.docker_utils.pull_image', return_value=True, autospec=True)
  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  @patch('click.secho', autospec=True)
  def test_run_command_image_not_found(
      self, mock_secho, mock_check_docker_setup, mock_pull_image):
    """Tests when client.containers.run raises ImageNotFound."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client
    mock_client.containers.run.side_effect = docker.errors.ImageNotFound(
        'not found')

    command = ['run']
    volumes = {}
    result = docker_utils.run_command(command, volumes)

    self.assertFalse(result)
    mock_check_docker_setup.assert_called_once()
    mock_pull_image.assert_called_once()
    mock_client.containers.run.assert_called_once()
    mock_secho.assert_called_once()
    args, _ = mock_secho.call_args
    self.assertIn('Error: Docker image', args[0])
    self.assertIn('not found', args[0])

  @patch('casp.utils.docker_utils.pull_image', return_value=True, autospec=True)
  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  @patch('click.secho', autospec=True)
  def test_run_command_api_error(self, mock_secho, mock_check_docker_setup,
                                 mock_pull_image):
    """Tests when client.containers.run raises APIError."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client
    mock_client.containers.run.side_effect = docker.errors.APIError('api error')

    command = ['run']
    volumes = {}
    result = docker_utils.run_command(command, volumes)

    self.assertFalse(result)
    mock_check_docker_setup.assert_called_once()
    mock_pull_image.assert_called_once()
    mock_client.containers.run.assert_called_once()
    mock_secho.assert_called_once()
    args, _ = mock_secho.call_args
    self.assertIn('Error: Docker API error', args[0])

  @patch('casp.utils.docker_utils.check_docker_setup', autospec=True)
  @patch('click.secho', autospec=True)
  def test_run_command_remove_container_fails(
      self,
      mock_secho,
      mock_check_docker_setup,
  ):
    """Tests when removing the container fails."""
    mock_client = create_autospec(
        docker.DockerClient, instance=True, spec_set=True)
    mock_check_docker_setup.return_value = mock_client

    mock_container = create_autospec(
        docker.models.containers.Container, instance=True, spec_set=True)
    mock_client.containers.run.return_value = mock_container
    mock_container.logs.return_value = []
    mock_container.wait.return_value = {'StatusCode': 0}
    mock_container.remove.side_effect = docker.errors.APIError('remove error')

    command = ['echo', 'hello']
    volumes = {}
    result = docker_utils.run_command(command, volumes)

    self.assertTrue(result)
    mock_container.remove.assert_called_once()
    mock_secho.assert_called_once()
    args, kwargs = mock_secho.call_args
    self.assertIn('Error removing container', args[0])
    self.assertEqual(kwargs['fg'], 'yellow')


if __name__ == '__main__':
  unittest.main()

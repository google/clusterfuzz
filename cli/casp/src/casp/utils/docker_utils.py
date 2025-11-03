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
"""Docker utility functions."""

import logging
import os

import click

import docker

# TODO: Make this configurable.
DOCKER_IMAGE = ("gcr.io/clusterfuzz-images/chromium/base/immutable/dev:"
                "20251008165901-utc-893e97e-640142509185-compute-d609115-prod")


def check_docker_setup() -> docker.client.DockerClient | None:
  """Checks if Docker is installed, running, and has correct permissions.

  Returns:
    A docker.client object if setup is correct, None otherwise.
  """
  try:
    client = docker.from_env()
    client.ping()
    return client
  except docker.errors.DockerException as e:
    if 'Permission denied' in str(e):
      click.secho(
          'Error: Permission denied while connecting to the Docker daemon.',
          fg='red')
      click.echo('Please add your user to the "docker" group by running:')
      click.secho(
          f'  sudo usermod -aG docker ${os.environ.get("USER")}', fg='yellow')
      click.echo('Then, log out and log back in for the change to take effect.')
    else:
      logging.error(e)
      click.secho(
          'Error: Docker is not running or is not installed. Please start '
          'Docker and try again.',
          fg='red')
    return None


def pull_image() -> bool:
  """Pulls the docker image."""
  client = check_docker_setup()
  if not client:
    return False

  try:
    click.echo(f'Pulling Docker image: {DOCKER_IMAGE}...')
    client.images.pull(DOCKER_IMAGE)
    return True
  except docker.errors.DockerException:
    click.secho(f'Error: Docker image {DOCKER_IMAGE} not found.', fg='red')
    return False

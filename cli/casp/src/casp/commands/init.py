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
"""Init command."""

import click

from ..utils import docker
from ..utils import gcloud


@click.command(name='init', help='Initializes the CLI.')
def cli():
  """Initializes the CLI by checking the Docker setup and pulling the
  required image."""
  click.echo('Checking Docker setup...')
  if not docker.check_docker_setup():
    click.secho(
        'Docker setup check failed. Please resolve the issues above.', fg='red')
    return

  click.secho('Docker setup is correct.', fg='green')

  click.echo('Checking gcloud authentication...')
  if gcloud.save_credentials_path():
    click.secho('gcloud authentication is configured correctly.', fg='green')
  else:
    click.secho('gcloud authentication check failed.', fg='red')
    return

  click.echo(f'Pulling Docker image: {docker.DOCKER_IMAGE}...')
  if docker.pull_image():
    click.secho(f'\nSuccessfully pulled {docker.DOCKER_IMAGE}.', fg='green')
    click.secho('Initialization complete.', fg='green')
  else:
    click.secho(
        f'\nError: Failed to pull Docker image {docker.DOCKER_IMAGE}.',
        fg='red')
    click.secho('Initialization failed.', fg='red')

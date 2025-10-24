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

import os

import click

from ..utils import config
from ..utils import docker_utils
from ..utils import gcloud


@click.command(name='init', help='Initializes the CLI.')
def cli():
  """Initializes the CLI by checking the Docker setup and pulling the
  required image."""
  click.echo('Checking Docker setup...')
  if not docker_utils.check_docker_setup():
    click.secho(
        'Docker setup check failed. Please resolve the issues above.', fg='red')
    return
  click.secho('Docker setup is correct.', fg='green')

  click.echo('Checking gcloud authentication...')
  credentials_path = gcloud.get_credentials_path()

  if not credentials_path:
    click.secho('gcloud authentication check failed.', fg='red')
    return

  click.echo(
      f'Saving credentials found in {credentials_path} file path to ~/.casp/config.json'
  )
  cfg = config.load_config()
  if not cfg:
    click.echo('Config file not found, creating it...')
  cfg['gcloud_credentials_path'] = credentials_path
  config.save_config(cfg)

  click.secho('gcloud authentication is configured correctly.', fg='green')

  custom_config_path = click.prompt(
      'Enter path to custom config directory (optional)',
      default='',
      show_default=False,
      type=click.Path())

  if custom_config_path and os.path.exists(custom_config_path):
    cfg = config.load_config()
    cfg['custom_config_path'] = custom_config_path
    config.save_config(cfg)
    click.secho(
        f'Custom config path saved to {config.CONFIG_FILE}.', fg='green')

  click.echo(f'Pulling Docker image: {docker_utils.DOCKER_IMAGE}...')
  if not docker_utils.pull_image():
    click.secho(
        f'\nError: Failed to pull Docker image {docker_utils.DOCKER_IMAGE}.',
        fg='red')
    click.secho('Initialization failed.', fg='red')

  click.secho('Initialization complete.', fg='green')

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
import sys
from typing import Any
from typing import Dict
from typing import Tuple

from casp.utils import config
from casp.utils import docker_utils
from casp.utils import gcloud
import click


def _setup_docker():
  """Sets up Docker."""
  click.echo('Checking Docker setup...')
  if not docker_utils.check_docker_setup():
    click.secho(
        'Docker setup check failed. Please resolve the issues above.', fg='red')
    sys.exit(1)
  click.secho('Docker setup is correct.', fg='green')


def _setup_gcloud_credentials(cfg: Dict[str, Any]):
  """"Setup gcloud credentials. Prompts the user if not found.

  Args:
    cfg: The configuration dictionary to update.
  """
  click.echo('Checking gcloud authentication...')
  credentials_path = gcloud.get_credentials_path()

  if not credentials_path:
    click.secho('gcloud authentication check failed.', fg='red')
    sys.exit(1)

  click.echo(f'Using credentials found in {credentials_path}')
  cfg['gcloud_credentials_path'] = credentials_path
  click.secho('gcloud authentication is configured correctly.', fg='green')


def _setup_custom_config(cfg: Dict[str, Any]):
  """Sets up optional custom configuration directory path.

  Args:
    cfg: The configuration dictionary to update.
  """
  custom_config_path = click.prompt(
      'Enter path to custom config directory (optional)',
      default='',
      show_default=False,
      type=click.Path())

  if not custom_config_path:
    # Handle case where user wants to clear the path
    if 'custom_config_path' in cfg:
      del cfg['custom_config_path']
      click.echo('Cleared custom config path.')
    return

  if not os.path.exists(custom_config_path):
    click.secho(
        f'Custom config path "{custom_config_path}" does not exist. '
        'Skipping.',
        fg='yellow')
    return

  cfg['custom_config_path'] = custom_config_path
  click.secho(f'Custom config path set to: {custom_config_path}', fg='green')


def _pull_image_for_project(project: str = 'internal'):
  """Pulls the docker image for the given project."""
  if not docker_utils.pull_image(docker_utils.PROJECT_TO_IMAGE[project]):
    click.secho(
        (f'\nError: Failed to pull Docker image: '
         f'{docker_utils.PROJECT_TO_IMAGE[project]}.'),
        fg='red')
    click.secho('Initialization failed.', fg='red')
    sys.exit(1)


@click.command(name='init', help='Initializes the CLI')
@click.option(
    '--projects',
    '--project',
    '-p',
    help=('The ClusterFuzz project to use. You can specify multiple projects.'
          'Ex.: -p dev -p internal'),
    required=False,
    default=('internal',),
    type=click.Choice(
        docker_utils.PROJECT_TO_IMAGE.keys(), case_sensitive=False),
    multiple=True)
def cli(projects: Tuple[str, ...]):
  """Initializes the CASP CLI.

  This is done by:
    1. Checking the Docker setup
    2. Setting up the gcloud credentials for later use
    3. Optionally setting up a custom configuration directory path
    4. Saving the configuration to the config file
    5. Pulling the Docker image
  """
  _setup_docker()

  cfg = config.load_config()
  if not cfg:
    click.echo('Config file not found, creating a new one...')
    cfg = {}

  _setup_gcloud_credentials(cfg)
  _setup_custom_config(cfg)

  config.save_config(cfg)
  click.secho(f'Configuration saved to {config.CONFIG_FILE}.', fg='green')

  for project in projects:
    _pull_image_for_project(project)

  click.secho('Initialization complete.', fg='green')

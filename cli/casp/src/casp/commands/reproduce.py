# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is is "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Reproduces a testcase locally using Docker."""

import os
from pathlib import Path
import sys
from typing import Any
from typing import Dict

from casp.utils import config
from casp.utils import docker_utils
import click

_CONTAINER_CONFIG_PATH = Path('/data/clusterfuzz/src/appengine')
_CONTAINER_CREDENTIALS_PATH = Path('/root/.config/gcloud/')


def _load_and_validate_config() -> Dict[str, Any]:
  """Loads and validates the configuration."""
  cfg = config.load_config()
  if not cfg or 'gcloud_credentials_path' not in cfg:
    click.secho(
        'Error: gcloud credentials not found. Please run "casp init".',
        fg='red')
    sys.exit(1)
  return cfg


def _prepare_docker_volumes(cfg: Dict[str, Any],
                            default_config_dir: str) -> tuple[dict, Path]:
  """Prepares the Docker volume bindings."""
  credentials_path = os.path.dirname(cfg['gcloud_credentials_path'])
  container_config_dir = Path(default_config_dir)

  volumes = {
      credentials_path: {
          'bind': str(_CONTAINER_CREDENTIALS_PATH),
          'mode': 'rw',
      },
  }

  if 'custom_config_path' in cfg:
    container_config_dir = _CONTAINER_CONFIG_PATH / 'custom_config'
    custom_config_path = cfg['custom_config_path']
    volumes[custom_config_path] = {
        'bind': str(container_config_dir),
        'mode': 'rw',
    }
    click.echo(f'Using custom config directory: {custom_config_path}')

  return volumes, container_config_dir


def _build_reproduce_command(container_config_dir: Path,
                             testcase_id: str) -> list[str]:
  """Builds the Docker command to reproduce the testcase."""
  command_script = (
      'pipenv run python butler.py --local-logging reproduce '
      f'--config-dir={container_config_dir} --testcase-id={testcase_id}')
  return ['bash', '-c', command_script]


@click.command(name='reproduce', help='Reproduces a testcase locally.')
@click.option(
    '--project',
    '-p',
    help='The ClusterFuzz project to use.',
    required=True,
    type=click.Choice(
        docker_utils.PROJECT_TO_IMAGE.keys(), case_sensitive=False),
)
@click.option(
    '--config-dir',
    '-c',
    required=False,
    default=str(_CONTAINER_CONFIG_PATH / 'config'),
    help=('Path to the config directory. If you set a custom '
          'config directory, this argument is not used.'),
)
@click.option(
    '--testcase-id', required=True, help='The ID of the testcase to reproduce.')
def cli(project: str, config_dir: str, testcase_id: str) -> None:
  """Reproduces a testcase locally by running a Docker container.

  Args:
    project: The ClusterFuzz project name.
    config_dir: The default configuration directory path within the container.
    testcase_id: The ID of the testcase to be reproduced.
  """
  cfg = _load_and_validate_config()

  volumes, container_config_dir = _prepare_docker_volumes(cfg, config_dir)

  command = _build_reproduce_command(container_config_dir, testcase_id)

  if not docker_utils.run_command(
      command,
      volumes,
      privileged=True,
      image=docker_utils.PROJECT_TO_IMAGE[project],
  ):
    sys.exit(1)

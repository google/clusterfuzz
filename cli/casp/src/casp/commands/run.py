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
"""Run command."""

import subprocess
import sys
from pathlib import Path

from casp.utils import config
from casp.utils import container
from casp.utils import docker_utils
from casp.utils import local_butler
import click


def common_options(func):
  """
    Decorator to add common options to both 
    local and container modes
  """
  func = click.option(
      '--local',
      is_flag=True,
      default=False,
      help='Run against local server instance.')(
          func)
  func = click.option(
      '--non-dry-run',
      is_flag=True,
      default=False,
      help='Run with actual datastore writes. Default to dry-run.')(
          func)
  func = click.option(
      '--script_args', multiple=True, help='Script specific arguments')(
          func)
  func = click.argument('script_name')(func)
  return func


def _prepare_butler_run_args(non_dry_run: bool,
                             local: bool,
                             config_dir: str | None = None):
  """Prepares common butler run arguments."""
  butler_args = {}
  if non_dry_run:
    butler_args['non_dry_run'] = None
  if local:
    butler_args['local'] = None
  if config_dir:
    butler_args['config_dir'] = config_dir

  return butler_args


def _get_script_args_list(script_args: list[str]) -> list[str]:
  script_args_list = []
  for arg in script_args:
    script_args_list.append(f'--script_args={arg}')
  return script_args_list


@click.group(
    name='run',
    help='Run a one-off script against a datastore (e.g. migration).')
def cli():
  """Run a one-off script against a datastore (e.g. migration)."""


@cli.command(name='local', help='Run the script locally (on the host machine).')
@common_options
@click.option(
    '--config-dir',
    '-c',
    required=True,
    type=click.Path(exists=True),
    help='Path to application config.')
def local_cmd(script_name: str, script_args: list[str] | None,
              non_dry_run: bool, local: bool, config_dir: str):
  """Run a one-off script locally."""
  try:
    butler_args = _prepare_butler_run_args(non_dry_run, local, config_dir)

    command = local_butler.build_command('run', **butler_args)

    command.append(script_name)
    if script_args is not None:
      script_args_list = _get_script_args_list(script_args)
      command.extend(script_args_list)
  except FileNotFoundError:
    click.echo('butler.py not found in this directory.', err=True)
    sys.exit(1)

  try:
    subprocess.run(command, check=True)
  except FileNotFoundError:
    click.echo('python not found in PATH.', err=True)
    sys.exit(1)
  except subprocess.CalledProcessError as e:
    click.echo(f'Error running butler.py run: {e}', err=True)
    sys.exit(1)


@cli.command(name='container', help='Run the script inside a Docker container.')
@common_options
@click.option(
    '--project',
    '-p',
    help='The ClusterFuzz project to use.',
    required=True,
    type=click.Choice(
        docker_utils.PROJECT_TO_IMAGE.keys(), case_sensitive=False),
)
@click.option(
    '--script-path',
    type=click.Path(exists=True),
    help='Path to the script in the host machine.')
def container_cmd(script_name, script_args, non_dry_run, local, project,
                  script_path):
  """Run a one-off script inside a container."""
  cfg = config.load_and_validate_config()

  volumes, container_config_dir = docker_utils.prepare_docker_volumes(
      cfg, str(container.CONTAINER_CONFIG_PATH / 'config'))

  if script_path:
    script_path = Path(script_path).resolve()
    container_script_path = container.CONTAINER_SCRIPTS_DIR / script_path.name
    volumes[str(script_path)] = {
        'bind': str(container_script_path),
        'mode': 'rw',
    }

  butler_args = _prepare_butler_run_args(
      non_dry_run, local, config_dir=str(container_config_dir))

  subcommand = f'run {script_name}'
  if script_args:
    for arg in script_args:
      subcommand += f' --script_args={arg}'

  command = container.build_butler_command(subcommand, **butler_args)

  if not docker_utils.run_command(
      command,
      volumes,
      privileged=True,
      image=docker_utils.PROJECT_TO_IMAGE[project],
  ):
    sys.exit(1)

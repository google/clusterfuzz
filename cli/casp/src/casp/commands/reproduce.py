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
"""Reproduce command."""

import sys

import click

from ..utils import config
from ..utils import docker_utils


@click.command(name='reproduce', help='Reproduces a testcase locally.')
@click.option(
    '--config-dir', required=True, help='Path to the config directory.')
@click.option(
    '--testcase-id', required=True, help='The ID of the testcase to reproduce.')
def cli(config_dir: str, testcase_id: str) -> None:
  """Reproduces a testcase locally."""
  cfg = config.load_config()
  if not cfg or 'gcloud_credentials_path' not in cfg:
    click.secho(
        'Error: gcloud credentials not found. Please run "casp init".',
        fg='red')
    sys.exit(1)

  credentials_path = cfg['gcloud_credentials_path']
  volumes = {credentials_path: {'bind': '/root/.config/gcloud/application_default_credentials.json', 'mode': 'rw'}}

  # Note: The working directory is set to /data/clusterfuzz in the Dockerfile.
  # See docker/base/Dockerfile
  command = [
      'bash', '-c',
      'pipenv run python butler.py reproduce '
      f'--config-dir={config_dir} --testcase-id={testcase_id}'
  ]

  if not docker_utils.run_command(command, volumes):
    sys.exit(1)

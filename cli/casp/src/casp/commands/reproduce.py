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

import sys

from casp.utils import config
from casp.utils import container
from casp.utils import docker_utils
import click


@click.command(
    name='reproduce',
    help=('Reproduces a testcase locally. '
          ' WARN: This essentially runs untrusted code '
          'in your local environment. '
          'Please acknowledge the testcase (mainly input and build) '
          'before running this command.'))
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
    default=str(container.CONTAINER_CONFIG_PATH / 'config'),
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
  cfg = config.load_and_validate_config()

  volumes, container_config_dir = docker_utils.prepare_docker_volumes(
      cfg, config_dir)

  command = container.build_command(
      'reproduce',
      config_dir=str(container_config_dir),
      testcase_id=testcase_id,
  )

  if not docker_utils.run_command(
      command,
      volumes,
      privileged=True,
      image=docker_utils.PROJECT_TO_IMAGE[project],
  ):
    sys.exit(1)

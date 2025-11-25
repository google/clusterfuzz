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
"""Container-specific utilities."""

from pathlib import Path

# The root directory for the ClusterFuzz source code inside the container.
SRC_ROOT = Path('/data/clusterfuzz/src')

# The path to the ClusterFuzz appengine directory inside the container.
# This directory is the default location for ClusterFuzz configurations.
CONTAINER_CONFIG_PATH = SRC_ROOT / 'appengine'

# The path where gcloud credentials will be mounted inside the container.
# This allows the container to authenticate with Google Cloud services.
CONTAINER_CREDENTIALS_PATH = Path('/root/.config/gcloud/')

# The path to the directory containing butler scripts inside the container.
CONTAINER_SCRIPTS_DIR = SRC_ROOT / 'local' / 'butler' / 'scripts'

# The base command prefix for executing ClusterFuzz butler commands.
# This ensures that commands are run with the correct Python environment
# and logging settings within the container.
_COMMAND_PREFIX = 'pipenv run python butler.py --local-logging'


def build_butler_command(subcommand: str, **kwargs: str) -> list[str]:
  """Builds a butler command to be executed inside the container.

  Args:
    subcommand: The butler subcommand to execute (e.g., 'reproduce').
    **kwargs: A dictionary of command-line arguments to pass to the subcommand.
              For example, `testcase_id='123'` becomes
              '--testcase-id=123'.

  Returns:
    A list of strings representing the command to be executed.
  """
  command = f'{_COMMAND_PREFIX} {subcommand}'
  for key, value in kwargs.items():
    key = key.replace('_', '-')
    if value is not None:
      command += f' --{key}={value}'
    else:
      command += f' --{key}'

  return ['bash', '-c', command]

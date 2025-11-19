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
"""Local butler command utilities."""

from pathlib import Path
from typing import Optional

from casp.utils import path_utils


def build_command(subcommand: str,
                  butler_path: Optional[Path] = None,
                  **kwargs: str) -> list[str]:
  """Builds a butler command for local execution.

  Args:
    subcommand: The butler subcommand to execute (e.g., 'format').
    butler_path: The path to the butler.py file. If not provided, it will be
      searched in the current directory.
    **kwargs: A dictionary of command-line arguments to pass to the subcommand.
              For example, `testcase_id='123'` becomes
              '--testcase-id=123'.

  Returns:
    A list of strings representing the command to be executed.

  Raises:
    FileNotFoundError: If butler.py is not found.
  """
  if butler_path is None:
    butler_path = path_utils.get_butler_in_dir(Path.cwd())

  if not butler_path:
    raise FileNotFoundError('butler.py not found.')

  command = ['python', str(butler_path), subcommand]
  for key, value in kwargs.items():
    key = key.replace('_', '-')
    command.append(f'--{key}={value}')

  return command

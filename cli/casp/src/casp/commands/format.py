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
"""Run format command."""

import os
from pathlib import Path
import subprocess
import sys

import click


def _find_butler(start_path: Path) -> Path | None:
  """Find the butler.py script in the directory tree."""
  current_path = os.path.abspath(start_path)
  butler_path = os.path.join(current_path, 'butler.py')
  if os.path.exists(butler_path):
    return Path(butler_path)
  return None


@click.command(name='format', help='Run format command')
@click.argument(
    'path',
    required=False,
    type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option(
    '--dir',
    '--directory',
    '-d',
    'directory',
    help='The directory to run the format command in.',
    default=None,
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    show_default=True)
def cli(path, directory):
  """Run format command"""
  butler_py_path = _find_butler(Path.cwd())
  if not butler_py_path:
    click.echo('butler.py not found in this directory.', err=True)
    sys.exit(1)

  target_dir = directory or path

  command = ['python', str(butler_py_path), 'format']
  if target_dir:
    command.extend(['--dir', str(target_dir)])

  try:
    subprocess.run(command, check=True)
  except FileNotFoundError:
    click.echo('python not found in PATH.', err=True)
    sys.exit(1)
  except subprocess.CalledProcessError as e:
    click.echo(f'Error running butler.py format: {e}', err=True)
    sys.exit(1)

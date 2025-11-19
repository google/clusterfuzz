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
"""Run format command."""

import subprocess
import sys

from casp.utils import local_butler
import click


@click.command(name='format', help='Run format command')
@click.argument('path', required=False, type=click.Path(exists=True))
@click.option(
    '--path',
    '-p',
    'path_option',
    help='The file or directory to run the format command in.',
    default=None,
    type=click.Path(exists=True),
    show_default=True)
def cli(path: str, path_option: str) -> None:
  """Run format command"""
  target_dir = path_option or path

  try:
    if target_dir:
      command = local_butler.build_command('format', path=target_dir)
    else:
      command = local_butler.build_command('format')
  except FileNotFoundError:
    click.echo('butler.py not found in this directory.', err=True)
    sys.exit(1)

  try:
    subprocess.run(command, check=True)
  except FileNotFoundError:
    click.echo('python not found in PATH.', err=True)
    sys.exit(1)
  except subprocess.CalledProcessError as e:
    click.echo(f'Error running butler.py format: {e}', err=True)
    sys.exit(1)
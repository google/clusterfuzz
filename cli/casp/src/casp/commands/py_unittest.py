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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.S
# See the License for the specific language governing permissions and
# limitations under the License.
"""Run Python unit tests command."""

import subprocess
import sys

from casp.utils import local_butler
import click


@click.command(
    name='py_unittest',
    help=('Runs Python unit tests. '
          'You can specify a pattern for test files, '
          'run tests in parallel, unsuppress output, '
          'or print verbose logs.'))
@click.option(
    '--pattern', '-p', help='Pattern for test files. Default is *_test.py.')
@click.option(
    '--unsuppress-output',
    '-u',
    is_flag=True,
    default=False,
    help='Unsuppress output from `print`. Good for debugging.')
@click.option(
    '--parallel',
    '-m',
    is_flag=True,
    default=False,
    help='Run tests in parallel.')
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    default=False,
    help='Print logs from tests.')
@click.option(
    '--target',
    '-t',
    required=True,
    type=click.Choice(['appengine', 'core', 'modules', 'cli']),
    help='The target for the unit tests.')
@click.option(
    '--config-dir', '-c', help='Config directory to use for module tests.')
def cli(pattern: str, unsuppress_output: bool, parallel: bool, verbose: bool,
        target: str, config_dir: str) -> None:
  """Runs Python unit tests."""
  try:
    arguments = {}
    arguments['target'] = target
    if pattern:
      arguments['pattern'] = pattern
    if unsuppress_output:
      arguments['unsuppress_output'] = None
    if parallel:
      arguments['parallel'] = None
    if verbose:
      arguments['verbose'] = None
    if config_dir:
      arguments['config_dir'] = config_dir

    command = local_butler.build_command('py_unittest', **arguments)
  except FileNotFoundError:
    click.echo('butler.py not found in this directory.', err=True)
    sys.exit(1)

  try:
    subprocess.run(command, check=True)
  except FileNotFoundError:
    click.echo('python not found in PATH.', err=True)
    sys.exit(1)
  except subprocess.CalledProcessError as e:
    click.echo(f'Error running butler.py py_unittest: {e}', err=True)
    sys.exit(1)

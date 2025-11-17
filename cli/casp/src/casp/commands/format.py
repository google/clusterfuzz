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

from pathlib import Path

import os
import subprocess
import sys

import click


def _find_butler_py(start_path: Path) -> Path | None:
  """Find the butler.py script in the directory tree."""
  current_path = os.path.abspath(start_path)
  butler_py_path = os.path.join(current_path, 'butler.py')
  if os.path.exists(butler_py_path):
    return Path(butler_py_path)
  return None


@click.command(name='format', help='Run format command')
def cli():
  """Run format command"""
  butler_py_path = _find_butler_py(Path.cwd())
  if not butler_py_path:
    click.echo('butler.py not found in this directory.', err=True)
    sys.exit(1)

  try:
    subprocess.run(['python', butler_py_path, 'format'], check=True)
  except FileNotFoundError:
    click.echo('python not found in PATH.', err=True)
    sys.exit(1)
  except subprocess.CalledProcessError as e:
    click.echo(f'Error running butler.py format: {e}', err=True)
    sys.exit(1)
  

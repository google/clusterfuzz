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
"""Casp CLI."""

from casp.commands import hi
from casp.commands import init
from casp.commands import reproduce
from casp.commands import run_task
from casp.commands import version
import click


@click.group()
def cli():
  """A new, modern Command-Line Interface (CLI) for ClusterFuzz."""


cli.add_command(version.cli)
cli.add_command(hi.cli)
cli.add_command(init.cli)
cli.add_command(run_task.cli)
cli.add_command(reproduce.cli)

if __name__ == '__main__':
  cli()

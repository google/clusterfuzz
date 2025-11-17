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

import click

from .commands import format as format_command
from .commands import hi
from .commands import init
from .commands import reproduce
from .commands import run_task
from .commands import version


@click.group()
def cli():
  """A new, modern Command-Line Interface (CLI) for ClusterFuzz."""


cli.add_command(version.cli)
cli.add_command(hi.cli)
cli.add_command(init.cli)
cli.add_command(run_task.cli)
cli.add_command(reproduce.cli)
cli.add_command(format_command.cli)

if __name__ == '__main__':
  cli()

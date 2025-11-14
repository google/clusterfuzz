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

from .commands import bootstrap
from .commands import clean_indexes
from .commands import create_config
from .commands import deploy
from .commands import format as format_command
from .commands import hi
from .commands import init
from .commands import integration_tests
from .commands import js_unittest
from .commands import lint
from .commands import package
from .commands import py_unittest
from .commands import remote
from .commands import reproduce
from .commands import run
from .commands import run_bot
from .commands import run_server
from .commands import run_task
from .commands import version
from .commands import weights


@click.group()
def cli():
  """A new, modern Command-Line Interface (CLI) for ClusterFuzz."""


cli.add_command(version.cli)
cli.add_command(hi.cli)
cli.add_command(init.cli)
cli.add_command(run_task.cli)
cli.add_command(reproduce.cli)
cli.add_command(bootstrap.cli)
cli.add_command(py_unittest.cli)
cli.add_command(js_unittest.cli)
cli.add_command(format_command.cli)
cli.add_command(lint.cli)
cli.add_command(package.cli)
cli.add_command(deploy.cli)
cli.add_command(run_server.cli)
cli.add_command(run.cli)
cli.add_command(run_bot.cli)
cli.add_command(remote.cli)
cli.add_command(clean_indexes.cli)
cli.add_command(create_config.cli)
cli.add_command(integration_tests.cli)
cli.add_command(weights.cli)

if __name__ == '__main__':
  cli()

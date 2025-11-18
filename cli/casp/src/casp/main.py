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

from casp.commands import bootstrap
from casp.commands import clean_indexes
from casp.commands import create_config
from casp.commands import deploy
from casp.commands import format as format_command
from casp.commands import hi
from casp.commands import init
from casp.commands import integration_tests
from casp.commands import js_unittest
from casp.commands import lint
from casp.commands import package
from casp.commands import py_unittest
from casp.commands import remote
from casp.commands import reproduce
from casp.commands import run
from casp.commands import run_bot
from casp.commands import run_server
from casp.commands import run_task
from casp.commands import version
from casp.commands import weights
import click


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

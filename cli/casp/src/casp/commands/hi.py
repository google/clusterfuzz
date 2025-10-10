# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may not use a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Hi command."""

import click


@click.command(name='hi', help='Greets the user.')
@click.option(
    '--repeat',
    '-r',
    default=1,
    type=int,
    help='The number of times to repeat the greeting.')
def cli(repeat):
  """Greets the user."""
  for _ in range(repeat):
    click.echo("Hi, I'm casp, your friendly CLI!")

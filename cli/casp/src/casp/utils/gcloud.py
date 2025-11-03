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
"""gcloud utility functions."""

import os
import subprocess

import click
from google.oauth2 import credentials

DEFAULT_GCLOUD_CREDENTIALS_PATH = os.path.expanduser(
    '~/.config/gcloud/application_default_credentials.json')


def _is_valid_credentials(path: str) -> bool:
  """Returns True if the path points to a valid credentials file."""
  if not path or not os.path.exists(path):
    click.secho('Error: No valid credentials file found.', fg='red')
    return False
  try:
    credentials.Credentials.from_authorized_user_file(path)
    return True
  except ValueError as e:
    click.secho(f'Error when checking for valid credentials: {e}', fg='red')
    return False


def _run_gcloud_login() -> bool:
  """
  Runs the gcloud login command and returns True on success.
  """
  try:
    subprocess.run(
        ['gcloud', 'auth', 'application-default', 'login'], check=True)
    # After login, re-validate the default file.
    return _is_valid_credentials(DEFAULT_GCLOUD_CREDENTIALS_PATH)
  except FileNotFoundError:
    click.secho(
        'Error: gcloud command not found. Please ensure it is installed and '
        'in your PATH. '
        'Or you can mannually run '
        '`gcloud auth application-default login`',
        fg='red')
    return False
  except subprocess.CalledProcessError:
    click.secho(
        'Error: gcloud login failed. '
        'You can mannually run '
        '`gcloud auth application-default login`',
        fg='red')
    return False


def _prompt_for_custom_path() -> str | None:
  """
  Prompts the user for a custom credentials path and returns it if valid.
  """
  path = click.prompt(
      'Enter path to your credentials file (or press Ctrl+C to cancel)',
      default='',
      show_default=False,
      type=click.Path(exists=True, dir_okay=False, resolve_path=True))

  if not path:
    return None

  if _is_valid_credentials(path):
    return path

  click.secho('Error: The provided credentials file is not valid.', fg='red')
  return None


def get_credentials_path() -> str | None:
  """
  Finds a valid gcloud credentials path, prompting the user if needed.

  Returns:
      The path to a valid credentials file, or None if one cannot be found.
  """
  if _is_valid_credentials(DEFAULT_GCLOUD_CREDENTIALS_PATH):
    return DEFAULT_GCLOUD_CREDENTIALS_PATH

  click.secho(
      'Default gcloud credentials not found or are invalid.', fg='yellow')

  if click.confirm('Do you want to log in with gcloud now?'):
    if _run_gcloud_login():
      return DEFAULT_GCLOUD_CREDENTIALS_PATH

  click.secho(
      '\nLogin was skipped or failed. You can provide a direct path instead.',
      fg='yellow')
  return _prompt_for_custom_path()

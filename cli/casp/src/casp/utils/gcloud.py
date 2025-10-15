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
from google.oauth2.credentials import Credentials

from . import config

GCLOUD_CREDENTIALS_PATH = os.path.expanduser(
    '~/.config/gcloud/application_default_credentials.json')


def _get_credentials():
  """Returns the gcloud application-default credentials."""
  if not os.path.exists(GCLOUD_CREDENTIALS_PATH):
    click.secho(
        'gcloud application-default credentials not found.', fg='yellow')
    if click.confirm('Do you want to log in now?'):
      try:
        subprocess.run(['gcloud', 'auth', 'application-default', 'login'],
                       check=True)
      except FileNotFoundError:
        click.secho(
            'Error: gcloud command not found. Please make sure it is '
            'installed and in your PATH.',
            fg='red')
        return None
      except subprocess.CalledProcessError:
        click.secho('Error: gcloud login failed.', fg='red')
        return None

  if not os.path.exists(GCLOUD_CREDENTIALS_PATH):
    click.secho(
        'Login failed. Could not find application default credentials.',
        fg='red')
    return None

  try:
    # We can't use google.auth.default() because it might pick up GCE
    # credentials. We want to specifically use the application-default
    # credentials file.
    return Credentials.from_authorized_user_file(GCLOUD_CREDENTIALS_PATH)
  except Exception as e:
    click.secho(f'Error loading credentials: {e}', fg='red')
    return None

def save_credentials_path():
  """Saves the gcloud credentials path to the config file."""
  if not _get_credentials():
    return False

  if os.path.exists(GCLOUD_CREDENTIALS_PATH):
    cfg = config.load_config()
    cfg['gcloud_credentials_path'] = GCLOUD_CREDENTIALS_PATH
    config.save_config(cfg)
    return True

  return False
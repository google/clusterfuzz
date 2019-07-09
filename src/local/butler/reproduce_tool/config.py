# Copyright 2019 Google LLC
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
"""Configuration helpers for the reproduce tool."""

import os

from base import json_utils
from base import memoize
from base import utils
from local.butler.reproduce_tool import errors
from local.butler.reproduce_tool import http_utils
from system import shell

CONFIG_DIRECTORY = os.path.join(
    os.path.expanduser('~'), '.config', 'clusterfuzz')
AUTHORIZATION_CACHE_FILE = os.path.join(CONFIG_DIRECTORY, 'authorization-cache')
CONFIG_URL_FILE = os.path.join(CONFIG_DIRECTORY, 'config-url')


def set_configuration_url(config_url):
  """Configure the tool to connect to the specified domain."""
  response, content = http_utils.request(
      config_url, body={}, authenticate=False)
  if response.status != 200 or not json_utils.loads(content):
    return False

  shell.create_directory(CONFIG_DIRECTORY, create_intermediates=True)
  utils.write_data_to_file(config_url, CONFIG_URL_FILE)
  return True


@memoize.wrap(memoize.FifoInMemory(1))
def _get_config():
  """Get the current configuration from the server.

  This is not stored to a file to avoid issues with server-side changes."""
  config_url = utils.read_data_from_file(CONFIG_URL_FILE, eval_data=False)
  if not config_url:
    raise errors.ReproduceToolUnrecoverableError(
        'The reproduce tool has not been configured.\n\n'
        'Please run "butler.py configure_reproduce <url>".')

  response, content = http_utils.request(
      config_url, body={}, authenticate=False)
  if response.status != 200:
    raise errors.ReproduceToolUnrecoverableError('Unable to access the server.')

  return json_utils.loads(content)


def get(key):
  """Get a config entry."""
  return _get_config()[key]

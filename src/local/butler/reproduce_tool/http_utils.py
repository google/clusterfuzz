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
"""HTTP utility functions for the reproduce tool."""

import os
import webbrowser

import httplib2

from clusterfuzz._internal.base import json_utils
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.system import shell
from local.butler.reproduce_tool import prompts

GET_METHOD = 'GET'
POST_METHOD = 'POST'

CONFIG_DIRECTORY = os.path.join(
    os.path.expanduser('~'), '.config', 'clusterfuzz')

AUTHORIZATION_CACHE_FILE = os.path.join(CONFIG_DIRECTORY, 'authorization-cache')
AUTHORIZATION_HEADER = 'x-clusterfuzz-authorization'


class SuppressOutput(object):
  """Suppress stdout and stderr.

  We need this to suppress webbrowser's stdout and stderr."""

  def __enter__(self):
    self.stdout = os.dup(1)
    self.stderr = os.dup(2)
    os.close(1)
    os.close(2)
    os.open(os.devnull, os.O_RDWR)

  def __exit__(self, *_):
    os.dup2(self.stdout, 1)
    os.dup2(self.stderr, 2)
    return True


def _get_authorization(force_reauthorization, configuration):
  """Get the value for an oauth authorization header."""
  # Try to read from cache unless we need to reauthorize.
  if not force_reauthorization:
    cached_authorization = utils.read_data_from_file(
        AUTHORIZATION_CACHE_FILE, eval_data=False)
    if cached_authorization:
      return cached_authorization

  # Prompt the user for a code if we don't have one or need a new one.
  oauth_url = configuration.get('oauth_url')
  print('Please login at the following URL to authenticate: {oauth_url}'.format(
      oauth_url=oauth_url))

  with SuppressOutput():
    webbrowser.open(oauth_url, new=1, autoraise=True)

  verification_code = prompts.get_string('Enter verification code')
  return 'VerificationCode {code}'.format(code=verification_code)


def request(url,
            body=None,
            method=POST_METHOD,
            force_reauthorization=False,
            configuration=None):
  """Make an HTTP request to the specified URL."""
  if configuration:
    authorization = _get_authorization(force_reauthorization, configuration)
    headers = {
        'User-Agent': 'clusterfuzz-reproduce',
        'Authorization': authorization
    }
  else:
    headers = {}

  http = httplib2.Http()
  request_body = json_utils.dumps(body) if body is not None else ''
  response, content = http.request(
      url, method=method, headers=headers, body=request_body)

  # If the server returns 401 we may need to reauthenticate. Try the request
  # a second time if this happens.
  if response.status == 401 and not force_reauthorization:
    return request(
        url,
        body,
        method=method,
        force_reauthorization=True,
        configuration=configuration)

  if AUTHORIZATION_HEADER in response:
    shell.create_directory(
        os.path.dirname(AUTHORIZATION_CACHE_FILE), create_intermediates=True)
    utils.write_data_to_file(response[AUTHORIZATION_HEADER],
                             AUTHORIZATION_CACHE_FILE)

  return response, content

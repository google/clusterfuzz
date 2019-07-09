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
"""configure_reproduce.py configures the reproduce tool."""

from __future__ import print_function

import os

from local.butler.reproduce_tool import config

REPRODUCE_TOOL_CONFIG_HANDLER = '/reproduce-tool/configure'


def execute(args):
  """Configure the reproduce tool."""
  # Environment variables for file utility functions.
  os.environ['FAIL_RETRIES'] = '1'
  os.environ['FAIL_WAIT'] = '1'

  # Format the url.
  url = args.url.rstrip('/')
  if '://' not in url:
    url = 'https://{}'.format(url)

  # Add the handler.
  url += REPRODUCE_TOOL_CONFIG_HANDLER

  result = config.set_configuration_url(url)
  if result:
    print('Reproduce tool configured successfully.')
  else:
    print('Failed to configure the reproduce tool. Please check the URL.')

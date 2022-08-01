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

from urllib import parse

from clusterfuzz._internal.base import json_utils
from local.butler.reproduce_tool import errors
from local.butler.reproduce_tool import http_utils

REPRODUCE_TOOL_CONFIG_HANDLER = '/reproduce-tool/get-config'


class ReproduceToolConfiguration(object):
  """Dynamically loaded configuration for the reproduce tool."""

  def __init__(self, testcase_url):
    testcase_url_parts = parse.urlparse(testcase_url)
    config_url = testcase_url_parts._replace(
        path=REPRODUCE_TOOL_CONFIG_HANDLER).geturl()
    response, content = http_utils.request(config_url, body={})
    if response.status != 200:
      raise errors.ReproduceToolUnrecoverableError('Failed to access server.')

    self._config = json_utils.loads(content)

  def get(self, key):
    """Get a config entry."""
    return self._config[key]

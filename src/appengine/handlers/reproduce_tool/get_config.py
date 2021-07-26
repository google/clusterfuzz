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
"""Allow users to configure the reproduce tool to point to this site."""

import urllib.parse

from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.datastore import data_handler
from handlers import base_handler
from libs import handler


class Handler(base_handler.Handler):
  """Handler to configure the reproduce tool."""

  # Note: This handler is intentionally unauthenticated.
  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    """Download the reproduce tool configuration json."""
    client_id = db_config.get_value('reproduce_tool_client_id')
    if not client_id:
      return self.render_json({
          'error': 'Reproduce tool is not configured.'
      }, 500)

    domain = data_handler.get_domain()
    link_format = 'https://{domain}/{handler}'
    configuration = {
        'testcase_info_url':
            link_format.format(
                domain=domain, handler='reproduce-tool/testcase-info'),
        'testcase_download_url':
            link_format.format(
                domain=domain, handler='testcase-detail/download-testcase'),
        'oauth_url':
            'https://accounts.google.com/o/oauth2/v2/auth?{}'.format(
                urllib.parse.urlencode({
                    'client_id': client_id,
                    'scope': 'email profile',
                    'response_type': 'code',
                    'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob'
                })),
    }

    return self.render_json(configuration)

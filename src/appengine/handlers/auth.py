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
"""Auth page."""

import gzip
import logging

from flask import request
from flask import Response
import requests

from handlers import base_handler
from libs import auth
from libs import handler


class Handler(base_handler.Handler):
  """Auth page."""

  @handler.get(handler.HTML)
  def get(self, extra=None):
    """Handle a get request."""
    # We iuse `request.url` which is already the full URL.
    del extra
    target_url = request.url.replace(auth.auth_domain(),
                                     auth.real_auth_domain(), 1)
    logging.info('Forwarding auth request to: %s', target_url)
    response = requests.get(target_url)
    gzip_response = gzip.compress(response.text.encode('utf-8'))
    flask_response = Response(
        gzip_response,
        status=response.status_code,
        headers=dict(response.headers))

    return flask_response

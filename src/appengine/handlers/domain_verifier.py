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
"""Domain verifier."""

from clusterfuzz._internal.config import local_config
from handlers import base_handler
from libs import helpers


class Handler(base_handler.Handler):
  """Serve google.*.html domain verification file."""

  def get(self, tag=None):
    """Handle a get request."""
    tag = 'google' + tag + '.html'
    verification_tag = local_config.GAEConfig().get('domain_verification_tag')
    if verification_tag != tag:
      raise helpers.EarlyExitException('Not found.', 404)

    return 'google-site-verification: ' + verification_tag

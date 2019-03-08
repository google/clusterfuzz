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
"""Log incoming reports of CSP violations.."""

from handlers import base_handler
from libs import handler
from metrics import logs


class CspReportHandler(base_handler.Handler):
  """Redirect to documentation."""

  def log_csp_violation(self):
    """Create an error log for a CSP violation."""
    logs.log_error('CSP violation: {}'.format(self.request.get('csp-report')))

  @handler.get(handler.JSON)
  def get(self):
    """Handle a GET request."""
    self.log_csp_violation()

  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    """Handle a POST request."""
    self.log_csp_violation()

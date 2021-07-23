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
"""Log incoming reports of CSP violations."""

from flask import request

from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler
from libs import helpers


class ReportCspFailureHandler(base_handler.Handler):
  """Log failures on HTML pages caused by CSP."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_user_access(need_privileged_access=False)
  def post(self):
    """Handle a POST request."""
    report = request.get('csp-report')
    if not report:
      raise helpers.EarlyExitException('No CSP report.', 400)

    logs.log_error('CSP violation: {}'.format(report))
    return 'OK'

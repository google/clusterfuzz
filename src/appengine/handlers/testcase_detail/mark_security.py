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
"""Handler for marking a testcase as security-related."""

from flask import request

from clusterfuzz._internal.base import bisection
from clusterfuzz._internal.crash_analysis import severity_analyzer
from handlers import base_handler
from handlers.testcase_detail import show
from libs import access
from libs import handler
from libs import helpers


def mark(testcase, security, severity):
  """Mark the testcase as security-related."""
  testcase.security_flag = security
  if security:
    if not severity:
      severity = severity_analyzer.get_security_severity(
          testcase.crash_type, testcase.crash_stacktrace, testcase.job_type,
          bool(testcase.gestures))

    testcase.security_severity = severity
    bisection.request_bisection(testcase)
  else:
    # The bisection infrastructure only cares about security bugs. If this was
    # marked as non-security, mark it as invalid.
    bisection.notify_bisection_invalid(testcase)

  testcase.put()
  helpers.log(
      f'Set security flags on testcase {testcase.key.id()} to {security}.',
      helpers.MODIFY_OPERATION)


class Handler(base_handler.Handler):
  """Handler that removes an issue from a testcase."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.require_csrf_token
  def post(self):
    """Mark the testcase as security-related."""
    testcase_id = request.get('testcaseId')
    security = request.get('security')
    severity = request.get('severity')
    testcase = helpers.get_testcase(testcase_id)

    if not access.has_access(
        fuzzer_name=testcase.actual_fuzzer_name(),
        job_type=testcase.job_type,
        need_privileged_access=True):
      raise helpers.AccessDeniedException()

    mark(testcase, security, severity)
    return self.render_json(show.get_testcase_detail(testcase))

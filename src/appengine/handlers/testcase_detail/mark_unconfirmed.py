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
"""Handler for marking a testcase as unconfirmed."""

from flask import request

from handlers import base_handler
from handlers.testcase_detail import show
from libs import handler
from libs import helpers


def mark(testcase):
  """Mark the testcase as unconfirmed."""
  testcase.one_time_crasher_flag = True
  if not testcase.fixed:
    testcase.fixed = 'NA'
  if not testcase.regression:
    testcase.regression = 'NA'
  if not testcase.minimized_keys:
    testcase.minimized_keys = 'NA'
  testcase.put()

  helpers.log('Marked testcase %s as unconfirmed' % testcase.key.id(),
              helpers.MODIFY_OPERATION)


class Handler(base_handler.Handler):
  """Handler that marks a testcase as unconfirmed."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.require_csrf_token
  @handler.check_admin_access
  def post(self):
    """Mark the testcase as unconfirmed."""
    testcase_id = request.get('testcaseId')
    testcase = helpers.get_testcase(testcase_id)
    mark(testcase)
    return self.render_json(show.get_testcase_detail(testcase))

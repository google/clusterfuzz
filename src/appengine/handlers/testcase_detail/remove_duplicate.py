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
"""Handler for removing duplicate_of of a testcase."""

from flask import request

from handlers import base_handler
from handlers.testcase_detail import show
from libs import handler
from libs import helpers


def remove(testcase):
  """Remove duplicate status from a test case."""
  testcase.status = 'Processed'
  testcase.duplicate_of = None
  testcase.put()

  helpers.log('Removed duplicate status for testcase %s' % testcase.key.id(),
              helpers.MODIFY_OPERATION)


class Handler(base_handler.Handler):
  """Handler that removes duplicate_of of a testcase."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.require_csrf_token
  @handler.check_admin_access
  def post(self):
    """Remove duplicate status from a test case."""
    testcase_id = request.get('testcaseId')
    testcase = helpers.get_testcase(testcase_id)
    remove(testcase)
    return self.render_json(show.get_testcase_detail(testcase))

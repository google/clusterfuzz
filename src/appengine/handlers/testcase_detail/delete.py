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
"""Handler for creating issue."""

from flask import request

from handlers import base_handler
from libs import handler
from libs import helpers


class Handler(base_handler.Handler):
  """Handler that creates an issue."""

  @staticmethod
  def delete_testcase(testcase_id):
    """Delete a testcase."""
    testcase = helpers.get_testcase(testcase_id)

    # Don't delete testcases that have an associated issue.
    if testcase.bug_information:
      raise helpers.EarlyExitException(
          'The testcase (id=%d) with an assigned issue cannot be deleted.' %
          testcase_id, 400)

    testcase.key.delete()
    helpers.log('Deleted testcase %s' % testcase_id, helpers.MODIFY_OPERATION)

  @handler.post(handler.JSON, handler.JSON)
  @handler.require_csrf_token
  @handler.check_admin_access
  def post(self):
    """Delete a testcase."""
    testcase_id = request.get('testcaseId')
    return self.render_json({'testcaseId': self.delete_testcase(testcase_id)})

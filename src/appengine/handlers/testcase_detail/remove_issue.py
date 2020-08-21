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
"""Handler for removing issue from a testcase."""

from flask import request

from handlers import base_handler
from handlers.testcase_detail import show
from libs import handler
from libs import helpers


class Handler(base_handler.Handler):
  """Handler that removes an issue from a testcase."""

  @staticmethod
  def remove_issue(testcase_id):
    """Remove the issue from the testcase."""
    testcase = helpers.get_testcase(testcase_id)
    issue_id = testcase.bug_information

    testcase.bug_information = ''
    testcase.put()

    helpers.log(
        'Removed the issue %s from the testcase %s' % (issue_id,
                                                       testcase.key.id()),
        helpers.MODIFY_OPERATION)

    return testcase

  @handler.post(handler.JSON, handler.JSON)
  @handler.require_csrf_token
  @handler.check_admin_access
  def post(self):
    """Remove the issue from the testcase."""
    testcase_id = request.get('testcaseId')

    updated_testcase = self.remove_issue(testcase_id)
    return self.render_json(show.get_testcase_detail(updated_testcase))

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
"""Handler for removing a testcase from a group."""

from flask import request

from clusterfuzz._internal.datastore import data_handler
from handlers import base_handler
from handlers.testcase_detail import show
from libs import handler
from libs import helpers


def remove_group(testcase_id):
  """Remove the testcase from a group."""
  testcase = helpers.get_testcase(testcase_id)
  group_id = testcase.group_id

  data_handler.remove_testcase_from_group(testcase)

  helpers.log(
      'Removed the testcase %s from the group %s' %
      (testcase.key.id(), group_id), helpers.MODIFY_OPERATION)

  return testcase


class Handler(base_handler.Handler):
  """Handler that removes a testcase from a group."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.require_csrf_token
  @handler.check_admin_access
  def post(self):
    """Remove the issue from the testcase."""
    testcase_id = request.get('testcaseId')

    updated_testcase = remove_group(testcase_id)
    return self.render_json(show.get_testcase_detail(updated_testcase))

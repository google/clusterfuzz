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
"""Handler for redoing."""

from flask import request

from clusterfuzz._internal.base import tasks
from handlers import base_handler
from handlers.testcase_detail import show
from libs import handler
from libs import helpers


class Handler(base_handler.Handler):
  """Handler that redo tasks."""

  @staticmethod
  def redo(testcase, testcase_tasks, user_email):
    """Redo tasks."""
    try:
      tasks.redo_testcase(testcase, testcase_tasks, user_email)
    except tasks.InvalidRedoTask as error:
      raise helpers.EarlyExitException(str(error), 400)

    helpers.log('Redo testcase %d: %s' % (testcase.key.id(), testcase_tasks),
                helpers.MODIFY_OPERATION)

  @handler.post(handler.JSON, handler.JSON)
  @handler.require_csrf_token
  @handler.check_testcase_access
  def post(self, testcase):
    """Queue redo tasks."""
    testcase_tasks = request.get('tasks')
    user_email = helpers.get_user_email()

    self.redo(testcase, testcase_tasks, user_email)
    return self.render_json(show.get_testcase_detail(testcase))

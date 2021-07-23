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
"""Handler for updating from trunk. In other words, updating the stacktrace."""
from clusterfuzz._internal.base import tasks
from handlers import base_handler
from handlers.testcase_detail import show
from libs import handler
from libs import helpers


def update(testcase):
  """Update from trunk."""
  testcase.last_tested_crash_stacktrace = 'Pending'
  testcase.put()

  tasks.add_task(
      'variant',
      testcase.key.id(),
      testcase.job_type,
      queue=tasks.queue_for_testcase(testcase))

  helpers.log(
      'Marked testcase %s for last tested stacktrace update' %
      testcase.key.id(), helpers.MODIFY_OPERATION)


class Handler(base_handler.Handler):
  """Handler that updates from trunk."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.require_csrf_token
  @handler.check_testcase_access
  def post(self, testcase):
    """Update from trunk."""
    update(testcase)
    return self.render_json(show.get_testcase_detail(testcase))

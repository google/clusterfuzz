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
"""Handler for updating issue."""

from datastore import data_handler
from handlers import base_handler
from handlers.testcase_detail import show
from issue_management import issue_filer
from libs import handler
from libs import helpers


class Handler(base_handler.Handler):
  """Handler that updates an issue."""

  @staticmethod
  def update_issue(testcase, issue_id, needs_summary_update):
    """Associate (or update) an existing issue with the testcase."""
    issue_id = helpers.cast(issue_id, int,
                            'Issue ID (%s) is not a number!' % issue_id)
    itm = helpers.get_issue_tracker_manager(testcase)

    issue = helpers.get_or_exit(lambda: itm.get_issue(issue_id),
                                'Issue (id=%d) is not found!' % issue_id,
                                'Failed to get the issue (id=%s).' % issue_id,
                                Exception)

    if not issue.open:
      raise helpers.EarlyExitException(
          ('The issue (%d) is already closed and further updates are not'
           ' allowed. Please file a new issue instead!') % issue_id, 400)

    # Create issue parameters.
    issue.comment = data_handler.get_issue_description(testcase,
                                                       helpers.get_user_email())
    issue_summary = data_handler.get_issue_summary(testcase)

    # NULL states leads to unhelpful summaries, so do not update in that case.
    if needs_summary_update and testcase.crash_state != 'NULL':
      issue.summary = issue_summary

    # Add label on memory tool used.
    issue_filer.add_memory_tool_label_if_needed(issue, testcase)

    # Add view restrictions for internal job types.
    issue_filer.add_view_restrictions_if_needed(issue, testcase)

    # Don't enforce security severity label on an existing issue.

    itm.save(issue)

    testcase.bug_information = str(issue_id)
    testcase.put()

    data_handler.update_group_bug(testcase.group_id)

    helpers.log('Updated issue %sd' % issue_id, helpers.MODIFY_OPERATION)

  @handler.post(handler.JSON, handler.JSON)
  @handler.require_csrf_token
  @handler.check_admin_access_if_oss_fuzz
  @handler.check_testcase_access
  def post(self, testcase):
    """Update an issue."""
    issue_id = self.request.get('issueId')
    needs_summary_update = self.request.get('needsSummaryUpdate')

    self.update_issue(testcase, issue_id, needs_summary_update)
    self.render_json(show.get_testcase_detail(testcase))

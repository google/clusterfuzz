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

from flask import request

from clusterfuzz._internal.datastore import data_handler
from handlers import base_handler
from handlers.testcase_detail import show
from libs import handler
from libs import helpers
from libs.issue_management import issue_filer
from libs.issue_management import issue_tracker_policy


class Handler(base_handler.Handler):
  """Handler that updates an issue."""

  @staticmethod
  def update_issue(testcase, issue_id, needs_summary_update):
    """Associate (or update) an existing issue with the testcase."""
    issue_id = helpers.cast(issue_id, int,
                            'Issue ID (%s) is not a number!' % issue_id)
    issue_tracker = helpers.get_issue_tracker_for_testcase(testcase)

    issue = helpers.get_or_exit(lambda: issue_tracker.get_issue(issue_id),
                                'Issue (id=%d) is not found!' % issue_id,
                                'Failed to get the issue (id=%s).' % issue_id,
                                Exception)

    if not issue.is_open:
      raise helpers.EarlyExitException(
          ('The issue (%d) is already closed and further updates are not'
           ' allowed. Please file a new issue instead!') % issue_id, 400)

    if not testcase.is_crash():
      raise helpers.EarlyExitException(
          'This is not a crash testcase, so issue update is not applicable.',
          400)

    issue_comment = data_handler.get_issue_description(testcase,
                                                       helpers.get_user_email())
    if needs_summary_update:
      issue.title = data_handler.get_issue_summary(testcase)

    policy = issue_tracker_policy.get(issue_tracker.project)
    properties = policy.get_existing_issue_properties()
    for label in properties.labels:
      for result in issue_filer.apply_substitutions(policy, label, testcase):
        issue.labels.add(result)

    issue.save(new_comment=issue_comment)

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
    issue_id = request.get('issueId')
    needs_summary_update = request.get('needsSummaryUpdate')

    self.update_issue(testcase, issue_id, needs_summary_update)
    return self.render_json(show.get_testcase_detail(testcase))

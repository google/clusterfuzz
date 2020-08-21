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
"""Handler for finding similar issues."""

from flask import request

from handlers import base_handler
from libs import handler
from libs import helpers
from libs.issue_management import issue_tracker_utils


class Handler(base_handler.Handler):
  """Handler that finds similar issues."""

  @staticmethod
  def get_issues(issue_tracker, testcase, only_open):
    """Get similar issues. It is used by self.process() and
    handler.testcase_detail.FindSimilarIssuesHandler.get()"""
    issues = issue_tracker_utils.get_similar_issues(
        issue_tracker, testcase, only_open=only_open)

    items = []
    for entry in issues:
      items.append({
          'owner': entry.assignee,
          'reporter': entry.reporter,
          'status': entry.status,
          'title': entry.title,
          'id': entry.id
      })

    items = sorted(items, key=lambda k: k['id'])
    return [{
        'issue': item,
        'url': issue_tracker.issue_url(item['id']),
    } for item in items]

  @handler.get(handler.JSON)
  @handler.check_admin_access_if_oss_fuzz
  @handler.check_testcase_access
  def get(self, testcase):
    """Find similar issues."""
    filter_type = request.get('filterType')
    only_open = filter_type == 'open'

    issue_tracker = helpers.get_issue_tracker_for_testcase(testcase)
    items = self.get_issues(issue_tracker, testcase, only_open)

    response = {
        'queryString':
            ' '.join(issue_tracker_utils.get_search_keywords(testcase)),
        'queryUrl':
            issue_tracker_utils.get_similar_issues_url(issue_tracker, testcase,
                                                       only_open),
        'items':
            items,
    }
    return self.render_json(response)

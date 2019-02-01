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
from base import utils
from handlers import base_handler
from issue_management import issue_tracker_utils
from libs import handler
from libs import helpers


class Handler(base_handler.Handler):
  """Handler that finds similar issues."""

  @staticmethod
  def get_issues(testcase, filter_type):
    """Get similar issues. It is used by self.process() and
    handler.testcase_detail.FindSimilarIssuesHandler.get()"""
    itm = helpers.get_issue_tracker_manager(testcase)

    issues = issue_tracker_utils.get_similar_issues(
        testcase, can=filter_type, issue_tracker_manager=itm)

    items = []
    for entry in issues:
      items.append({
          'owner': entry.owner,
          'reporter': entry.reporter,
          'security': entry.has_label_containing('security'),
          'status': entry.status,
          'summary': entry.summary,
          'updated': utils.time_difference_string(entry.updated),
          'id': entry.id
      })

    items = sorted(items, key=lambda k: k['id'])
    issue_url = issue_tracker_utils.get_issue_url(testcase)
    return items, issue_url

  @handler.get(handler.JSON)
  @handler.check_admin_access_if_oss_fuzz
  @handler.check_testcase_access
  def get(self, testcase):
    """Find similar issues."""
    filter_type = self.request.get('filterType')

    items, issue_url = self.get_issues(testcase, filter_type)

    response = {
        'queryString':
            issue_tracker_utils.get_similar_issues_query(testcase),
        'queryUrl':
            issue_tracker_utils.get_similar_issues_url(testcase, filter_type),
        'items':
            items,
        'issueUrlPrefix':
            issue_url
    }
    self.render_json(response)

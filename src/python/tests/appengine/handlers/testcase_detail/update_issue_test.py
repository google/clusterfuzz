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
"""update_issue tests."""
import mock
import unittest
import webapp2
import webtest

from datastore import data_types
from handlers.testcase_detail import update_issue
from issue_management import issue
from issue_management import issue_tracker_manager
from libs import access
from libs import form
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'issue_management.label_utils.get_memory_tool_labels',
        'issue_management.issue_filer.add_view_restrictions_if_needed',
        'datastore.data_handler.get_issue_description',
        'datastore.data_handler.get_issue_summary',
        'datastore.data_handler.get_stacktrace',
        'datastore.data_handler.update_group_bug',
        'issue_management.issue_tracker_utils.get_issue_tracker_manager',
        'google.appengine.api.users.get_current_user',
        'handlers.testcase_detail.show.get_testcase_detail',
        'libs.access.get_access',
    ])
    self.mock.get_access.return_value = access.UserAccess.Allowed
    self.mock.get_testcase_detail.return_value = {'testcase': 'yes'}
    self.mock.get_current_user().email.return_value = 'test@test.com'

    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', update_issue.Handler)]))

    self.testcase = data_types.Testcase()
    self.testcase.bug_information = 'unset'
    self.testcase.put()

  def test_issue_id_not_a_number(self):
    """issue_id is not a number."""
    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'issueId': 'aaa',
            'needsSummaryUpdate': '',
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)

    self.assertEqual(400, resp.status_int)
    self.assertEqual('Issue ID (aaa) is not a number!', resp.json['message'])
    self.assertEqual('test@test.com', resp.json['email'])

  def test_issue_not_found(self):
    """Issue is not found."""
    itm = mock.Mock(spec_set=issue_tracker_manager.IssueTrackerManager)

    self.mock.get_issue_tracker_manager.return_value = itm
    itm.get_issue.return_value = None

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'issueId': '2',
            'needsSummaryUpdate': '',
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)

    self.assertEqual(404, resp.status_int)
    self.assertEqual('Issue (id=2) is not found!', resp.json['message'])
    self.assertEqual('test@test.com', resp.json['email'])

  def test_issue_not_open(self):
    """Issue is not open."""
    itm = mock.Mock(spec_set=issue_tracker_manager.IssueTrackerManager)
    bug = issue.Issue()
    bug.open = False

    self.mock.get_issue_tracker_manager.return_value = itm
    itm.get_issue.return_value = bug

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'issueId': '2',
            'needsSummaryUpdate': '',
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)

    self.assertEqual(400, resp.status_int)
    self.assertIn('file a new issue', resp.json['message'])
    self.assertEqual('test@test.com', resp.json['email'])

  def test_succeed(self):
    """Update an issue."""
    bug = issue.Issue()
    bug.open = True
    itm = mock.Mock(project_name='chromium')
    itm.get_issue.return_value = bug

    self.mock.get_issue_tracker_manager.return_value = itm
    self.mock.get_issue_description.return_value = 'description'
    self.mock.get_issue_summary.return_value = 'summary'
    self.mock.get_stacktrace.return_value = 'stacktrace'
    self.mock.get_memory_tool_labels.return_value = ['label']

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'issueId': '2',
            'needsSummaryUpdate': 'true',
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)

    self.assertEqual(200, resp.status_int)
    self.assertEqual('yes', resp.json['testcase'])

    self.assertEqual('description', bug.comment)
    self.assertEqual('summary', bug.summary)
    self.assertListEqual(['label'], bug.labels)
    self.assertEqual('2', self.testcase.key.get().bug_information)

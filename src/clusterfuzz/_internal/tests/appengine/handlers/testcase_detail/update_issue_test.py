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
import unittest

import flask
import mock
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.testcase_detail import update_issue
from libs import access
from libs import form
from libs.issue_management import issue_tracker_policy
from libs.issue_management import monorail
from libs.issue_management.monorail import issue
from libs.issue_management.monorail import issue_tracker_manager

CHROMIUM_POLICY = issue_tracker_policy.IssueTrackerPolicy({
    'status': {
        'assigned': 'Assigned',
        'duplicate': 'Duplicate',
        'fixed': 'Fixed',
        'new': 'Untriaged',
        'verified': 'Verified',
        'wontfix': 'WontFix'
    },
    'labels': {},
    'existing': {
        'labels': ['Stability-%SANITIZER%']
    },
})


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.datastore.data_handler.get_issue_description',
        'clusterfuzz._internal.datastore.data_handler.get_issue_summary',
        'clusterfuzz._internal.datastore.data_handler.get_stacktrace',
        'clusterfuzz._internal.datastore.data_handler.update_group_bug',
        'libs.helpers.get_issue_tracker_for_testcase',
        'libs.auth.get_current_user',
        'handlers.testcase_detail.show.get_testcase_detail',
        'libs.access.get_access',
        'libs.issue_management.issue_tracker_policy.get',
        'libs.issue_management.issue_filer.get_memory_tool_labels',
    ])
    self.mock.get_access.return_value = access.UserAccess.Allowed
    self.mock.get_testcase_detail.return_value = {'testcase': 'yes'}
    self.mock.get_current_user().email = 'test@test.com'
    self.mock.get.return_value = CHROMIUM_POLICY

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=update_issue.Handler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    self.testcase = data_types.Testcase()
    self.testcase.bug_information = ''
    self.testcase.crash_state = 'fake_crash_state'
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

    self.mock.get_issue_tracker_for_testcase.return_value = (
        monorail.IssueTracker(itm))
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

    self.mock.get_issue_tracker_for_testcase.return_value = (
        monorail.IssueTracker(itm))
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

    self.mock.get_issue_tracker_for_testcase.return_value = (
        monorail.IssueTracker(itm))
    self.mock.get_issue_description.return_value = 'description'
    self.mock.get_issue_summary.return_value = 'summary'
    self.mock.get_stacktrace.return_value = 'stacktrace'
    self.mock.get_memory_tool_labels.return_value = ['tool']

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
    self.assertListEqual(['Stability-tool'], bug.labels)
    self.assertEqual('2', self.testcase.key.get().bug_information)

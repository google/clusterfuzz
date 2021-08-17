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
"""find_similar_issues tests."""
import unittest

import flask
import mock
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.testcase_detail import find_similar_issues
from libs.issue_management import monorail
from libs.issue_management.monorail import issue


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test FindSimilarIssuesHandler."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.check_access_and_get_testcase',
        'libs.issue_management.issue_tracker_utils.'
        'get_issue_tracker_for_testcase',
        'libs.issue_management.issue_tracker_utils.get_issue_url',
        'libs.issue_management.issue_tracker_utils.get_search_keywords',
        'libs.issue_management.issue_tracker_utils.get_similar_issues',
        'libs.issue_management.issue_tracker_utils.get_similar_issues_url',
    ])
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=find_similar_issues.Handler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    self.testcase = data_types.Testcase()
    self.testcase.put()
    self.mock.check_access_and_get_testcase.return_value = self.testcase

    self.invalid_testcase_id = self.testcase.key.id() + 1

  def test_itm_not_found(self):
    """Ensure it errors when issue_tracker_manager doesn't exist."""
    self.mock.get_issue_tracker_for_testcase.return_value = None

    response = self.app.get(
        '/?testcaseId=%d&filterType=open' % self.testcase.key.id(),
        expect_errors=True)
    self.assertEqual(response.status_int, 404)
    self.mock.get_issue_tracker_for_testcase.assert_has_calls(
        [mock.call(mock.ANY)])
    self.assertEqual(
        self.testcase.key.id(),
        self.mock.get_issue_tracker_for_testcase.call_args[0][0].key.id())

  def test_find(self):
    """Ensure it returns correct JSON when everything is ok."""
    issue_tracker = mock.Mock()
    monorail_issue = issue.Issue()
    monorail_issue.id = 100
    issue_item = monorail.Issue(monorail_issue)
    self.mock.get_issue_tracker_for_testcase.return_value = issue_tracker
    self.mock.get_search_keywords.return_value = ['query']
    self.mock.get_similar_issues_url.return_value = 'similarurl'
    self.mock.get_similar_issues.return_value = [issue_item]
    issue_tracker.issue_url.return_value = 'issueurl'

    response = self.app.get(
        '/?testcaseId=%d&filterType=open' % self.testcase.key.id())
    self.assertEqual(response.status_int, 200)
    self.assertEqual(response.json['queryString'], 'query')
    self.assertEqual(response.json['queryUrl'], 'similarurl')
    self.assertEqual(len(response.json['items']), 1)

    self.assertEqual(response.json['items'][0]['issue']['id'], issue_item.id)
    issue_tracker.issue_url.assert_called_with(issue_item.id)

    self.mock.get_issue_tracker_for_testcase.assert_has_calls(
        [mock.call(mock.ANY)])
    self.assertEqual(
        self.testcase.key.id(),
        self.mock.get_issue_tracker_for_testcase.call_args[0][0].key.id())
    self.mock.get_similar_issues.assert_has_calls(
        [mock.call(issue_tracker, mock.ANY, only_open=True)])
    self.assertEqual(self.testcase.key.id(),
                     self.mock.get_similar_issues.call_args[0][1].key.id())

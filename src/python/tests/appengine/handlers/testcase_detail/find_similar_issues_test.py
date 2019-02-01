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
import mock
import unittest
import webapp2
import webtest

from datastore import data_types
from handlers.testcase_detail import find_similar_issues
from issue_management import issue
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test FindSimilarIssuesHandler."""

  def setUp(self):
    test_helpers.patch(self, [
        'issue_management.issue_tracker_utils.get_issue_tracker_manager',
        'issue_management.issue_tracker_utils.get_similar_issues',
        'issue_management.issue_tracker_utils.get_similar_issues_query',
        'issue_management.issue_tracker_utils.get_similar_issues_url',
        'issue_management.issue_tracker_utils.get_issue_url',
        'libs.access.check_access_and_get_testcase',
    ])
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', find_similar_issues.Handler)]))

    self.testcase = data_types.Testcase()
    self.testcase.put()
    self.mock.check_access_and_get_testcase.return_value = self.testcase

    self.invalid_testcase_id = self.testcase.key.id() + 1

  def test_itm_not_found(self):
    """Ensure it errors when issue_tracker_manager doesn't exist."""
    self.mock.get_issue_tracker_manager.return_value = None

    response = self.app.get(
        '/?testcaseId=%d&filterType=open' % self.testcase.key.id(),
        expect_errors=True)
    self.assertEqual(response.status_int, 404)
    self.mock.get_issue_tracker_manager.assert_has_calls([mock.call(mock.ANY)])
    self.assertEqual(
        self.testcase.key.id(),
        self.mock.get_issue_tracker_manager.call_args[0][0].key.id())

  def test_find(self):
    """Ensure it returns correct JSON when everything is ok."""
    itm = mock.Mock()
    issue_item = issue.Issue()
    issue_item.id = 100
    self.mock.get_issue_tracker_manager.return_value = itm
    self.mock.get_similar_issues_url.return_value = 'similarurl'
    self.mock.get_similar_issues_query.return_value = 'query'
    self.mock.get_similar_issues.return_value = [issue_item]
    self.mock.get_issue_url.return_value = 'issueurl'

    response = self.app.get(
        '/?testcaseId=%d&filterType=open' % self.testcase.key.id())
    self.assertEqual(response.status_int, 200)
    self.assertEqual(response.json['queryString'], 'query')
    self.assertEqual(response.json['queryUrl'], 'similarurl')
    self.assertEqual(response.json['issueUrlPrefix'], 'issueurl')
    self.assertEqual(len(response.json['items']), 1)

    self.assertEqual(response.json['items'][0]['id'], issue_item.id)

    self.mock.get_issue_tracker_manager.assert_has_calls([mock.call(mock.ANY)])
    self.assertEqual(
        self.testcase.key.id(),
        self.mock.get_issue_tracker_manager.call_args[0][0].key.id())
    self.mock.get_similar_issues.assert_has_calls(
        [mock.call(mock.ANY, 'open', itm)])
    self.assertEqual(self.testcase.key.id(),
                     self.mock.get_similar_issues.call_args[0][0].key.id())

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
"""Create issue tests."""
import mock
import unittest
import webapp2
import webtest

from datastore import data_types
from handlers.testcase_detail import create_issue
from libs import form
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test HandlerTest."""

  def setUp(self):
    test_helpers.patch(self, [
        'issue_management.issue_filer.file_issue',
        'issue_management.issue_tracker_utils.get_issue_tracker_manager',
        'google.appengine.api.users.get_current_user',
        'handlers.testcase_detail.show.get_testcase_detail',
        'libs.access.has_access',
    ])
    self.mock.has_access.return_value = True
    self.mock.get_testcase_detail.return_value = {'testcase': 'yes'}
    self.mock.get_current_user().email.return_value = 'test@user.com'

    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', create_issue.Handler)]))

    self.testcase = data_types.Testcase()
    self.testcase.put()

  def test_create_successfully(self):
    """Create issue successfully."""
    itm = mock.Mock()
    self.mock.get_issue_tracker_manager.return_value = itm
    self.mock.file_issue.return_value = 100

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'severity': 3,
            'ccMe': 'true',
            'csrf_token': form.generate_csrf_token(),
        })

    self.assertEqual('yes', resp.json['testcase'])
    self.mock.get_issue_tracker_manager.assert_has_calls([mock.call(mock.ANY)])
    self.assertEqual(
        self.testcase.key.id(),
        self.mock.get_issue_tracker_manager.call_args[0][0].key.id())
    self.mock.file_issue.assert_has_calls([
        mock.call(
            mock.ANY,
            itm,
            security_severity=3,
            user_email='test@user.com',
            additional_ccs=['test@user.com'])
    ])
    self.assertEqual(self.testcase.key.id(),
                     self.mock.file_issue.call_args[0][0].key.id())

  def test_no_itm(self):
    """No IssueTrackerManager."""
    self.mock.get_issue_tracker_manager.return_value = None

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'severity': 3,
            'ccMe': 'true',
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)
    self.assertEqual(resp.status_int, 404)

  def test_invalid_testcase(self):
    """Invalid testcase."""
    itm = mock.Mock()
    self.mock.get_issue_tracker_manager.return_value = itm

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id() + 1,
            'severity': 3,
            'ccMe': 'true',
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)
    self.assertEqual(resp.status_int, 404)

  def test_invalid_severity(self):
    """Invalid severity."""
    itm = mock.Mock()
    self.mock.get_issue_tracker_manager.return_value = itm
    self.mock.file_issue.return_value = 100

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'severity': 'a',
            'ccMe': 'true',
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)
    self.assertEqual(resp.status_int, 400)

  def test_creating_fails(self):
    """Fail to create issue."""
    itm = mock.Mock()
    self.mock.get_issue_tracker_manager.return_value = itm
    self.mock.file_issue.return_value = None

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'severity': 3,
            'ccMe': 'true',
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)

    self.assertEqual(resp.status_int, 500)
    self.mock.get_issue_tracker_manager.assert_has_calls([mock.call(mock.ANY)])
    self.assertEqual(
        self.testcase.key.id(),
        self.mock.get_issue_tracker_manager.call_args[0][0].key.id())
    self.mock.file_issue.assert_has_calls([
        mock.call(
            mock.ANY,
            itm,
            security_severity=3,
            user_email='test@user.com',
            additional_ccs=['test@user.com'])
    ])
    self.assertEqual(self.testcase.key.id(),
                     self.mock.file_issue.call_args[0][0].key.id())

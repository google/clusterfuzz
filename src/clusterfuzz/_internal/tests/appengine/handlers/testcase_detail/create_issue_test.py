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
import unittest

import flask
import mock
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.testcase_detail import create_issue
from libs import form


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test HandlerTest."""

  def setUp(self):
    test_helpers.patch(self, [
        'handlers.testcase_detail.show.get_testcase_detail',
        'libs.access.has_access',
        'libs.auth.get_current_user',
        'libs.issue_management.issue_filer.file_issue',
        'libs.issue_management.issue_tracker_utils.'
        'get_issue_tracker_for_testcase',
    ])
    self.mock.has_access.return_value = True
    self.mock.get_testcase_detail.return_value = {'testcase': 'yes'}
    self.mock.get_current_user().email = 'test@user.com'

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=create_issue.Handler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    self.testcase = data_types.Testcase()
    self.testcase.put()

  def test_create_successfully(self):
    """Create issue successfully."""
    issue_tracker = mock.Mock()
    self.mock.get_issue_tracker_for_testcase.return_value = issue_tracker
    self.mock.file_issue.return_value = 100

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'severity': 3,
            'ccMe': True,
            'csrf_token': form.generate_csrf_token(),
        })

    self.assertEqual('yes', resp.json['testcase'])
    self.mock.get_issue_tracker_for_testcase.assert_has_calls(
        [mock.call(mock.ANY)])
    self.assertEqual(
        self.testcase.key.id(),
        self.mock.get_issue_tracker_for_testcase.call_args[0][0].key.id())
    self.mock.file_issue.assert_has_calls([
        mock.call(
            mock.ANY,
            issue_tracker,
            security_severity=3,
            user_email='test@user.com',
            additional_ccs=['test@user.com'])
    ])
    self.assertEqual(self.testcase.key.id(),
                     self.mock.file_issue.call_args[0][0].key.id())

  def test_no_issue_tracker(self):
    """No IssueTracker."""
    self.mock.get_issue_tracker_for_testcase.return_value = None

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'severity': 3,
            'ccMe': True,
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)
    self.assertEqual(resp.status_int, 404)

  def test_invalid_testcase(self):
    """Invalid testcase."""
    issue_tracker = mock.Mock()
    self.mock.get_issue_tracker_for_testcase.return_value = issue_tracker

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id() + 1,
            'severity': 3,
            'ccMe': True,
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)
    self.assertEqual(resp.status_int, 404)

  def test_invalid_severity(self):
    """Invalid severity."""
    issue_tracker = mock.Mock()
    self.mock.get_issue_tracker_for_testcase.return_value = issue_tracker
    self.mock.file_issue.return_value = 100

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'severity': 'a',
            'ccMe': True,
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)
    self.assertEqual(resp.status_int, 400)

  def test_creating_fails(self):
    """Fail to create issue."""
    issue_tracker = mock.Mock()
    self.mock.get_issue_tracker_for_testcase.return_value = issue_tracker
    self.mock.file_issue.return_value = None

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'severity': 3,
            'ccMe': True,
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)

    self.assertEqual(resp.status_int, 500)
    self.mock.get_issue_tracker_for_testcase.assert_has_calls(
        [mock.call(mock.ANY)])
    self.assertEqual(
        self.testcase.key.id(),
        self.mock.get_issue_tracker_for_testcase.call_args[0][0].key.id())
    self.mock.file_issue.assert_has_calls([
        mock.call(
            mock.ANY,
            issue_tracker,
            security_severity=3,
            user_email='test@user.com',
            additional_ccs=['test@user.com'])
    ])
    self.assertEqual(self.testcase.key.id(),
                     self.mock.file_issue.call_args[0][0].key.id())

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
"""Tests for the issue redirector handler."""

import unittest
from unittest import mock

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from handlers import issue_redirector


class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.issue_management.issue_tracker_utils.get_issue_url',
        'libs.access.check_access_and_get_testcase',
    ])

    self.flaskapp = flask.Flask('testflask')
    self.flaskapp.add_url_rule(
        '/issue/<testcase_id>',
        view_func=issue_redirector.Handler.as_view('/issue/'))
    self.app = webtest.TestApp(self.flaskapp)

  def test_succeed(self):
    """Test redirection succeeds."""
    testcase = data_types.Testcase()
    testcase.bug_information = '456789'
    self.mock.check_access_and_get_testcase.return_value = testcase
    self.mock.get_issue_url.return_value = 'http://google.com/456789'

    response = self.app.get('/issue/12345')

    self.assertEqual(302, response.status_int)
    self.assertEqual('http://google.com/456789', response.headers['Location'])

    self.mock.check_access_and_get_testcase.assert_has_calls(
        [mock.call('12345')])
    self.mock.get_issue_url.assert_has_calls([mock.call(testcase)])

  def test_no_issue_url(self):
    """Test no issue url."""
    self.mock.check_access_and_get_testcase.return_value = data_types.Testcase()
    self.mock.get_issue_url.return_value = ''

    response = self.app.get(
        '/issue/12345',
        headers={'Accept': 'application/json'},
        expect_errors=True)
    self.assertEqual(404, response.status_int)

  def test_access_denied(self):
    """Access denied returns 403 instead of leaking the issue URL."""
    from libs import helpers as libs_helpers
    self.mock.check_access_and_get_testcase.side_effect = (
        libs_helpers.AccessDeniedError('Access denied'))

    response = self.app.get(
        '/issue/12345',
        headers={'Accept': 'application/json'},
        expect_errors=True)
    self.assertEqual(403, response.status_int)
    self.mock.get_issue_url.assert_not_called()

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

import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.issue_management import issue_tracker_utils
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from libs import access
from libs import helpers


class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.issue_management.issue_tracker_utils.get_issue_url',
        'libs.access.check_access_and_get_testcase',
        'clusterfuzz._internal.system.environment.is_running_on_app_engine',
        'libs.helpers.get_user_email',
        'clusterfuzz._internal.config.db_config.get_value',
        'logging.exception',
        'libs.form.generate_csrf_token',
    ])
    self.mock.is_running_on_app_engine.return_value = True
    self.mock.get_user_email.return_value = ''
    self.mock.get_value.return_value = 'contact@example.com'
    self.mock.generate_csrf_token.return_value = 'dummy_csrf_token'

    self.ndb_context = ndb_init.context()
    self.ndb_context.__enter__()

    import server
    self.app = webtest.TestApp(server.app)

  def tearDown(self):
    self.ndb_context.__exit__(None, None, None)

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

    response = self.app.get('/issue/12345', expect_errors=True)
    self.assertEqual(404, response.status_int)

  def test_access_denied(self):
    """Test access denied error."""
    self.mock.get_user_email.return_value = 'test@user.com'
    self.mock.check_access_and_get_testcase.side_effect = (
        helpers.AccessDeniedError())

    response = self.app.get('/issue/12345', expect_errors=True)
    self.assertEqual(403, response.status_int)

  def test_unauthorized(self):
    """Test unauthorized error."""
    self.mock.get_user_email.return_value = ''
    self.mock.check_access_and_get_testcase.side_effect = (
        helpers.UnauthorizedError())

    response = self.app.get('/issue/12345', expect_errors=True)
    self.assertEqual(302, response.status_int)
    self.assertIn('/login', response.headers['Location'])

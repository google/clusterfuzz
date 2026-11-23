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
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.issue_management.issue_tracker_utils.get_issue_url',
        'libs.access.can_user_access_testcase',
        'libs.helpers.get_testcase',
        'clusterfuzz._internal.system.environment.is_running_on_app_engine',
    ])
    self.mock.is_running_on_app_engine.return_value = True
    self.mock.can_user_access_testcase.return_value = False

    import server
    self.app = webtest.TestApp(server.app)

  def test_succeed(self):
    """Test redirection succeeds."""
    testcase = data_types.Testcase()
    testcase.bug_information = '456789'
    self.mock.get_testcase.return_value = testcase
    self.mock.get_issue_url.return_value = 'http://google.com/456789'

    response = self.app.get('/issue/12345')

    self.assertEqual(302, response.status_int)
    self.assertEqual('http://google.com/456789', response.headers['Location'])

    self.mock.get_testcase.assert_has_calls([mock.call('12345')])
    self.mock.get_issue_url.assert_has_calls([mock.call(testcase)])

  def test_no_issue_url(self):
    """Test no issue url."""
    self.mock.get_testcase.return_value = data_types.Testcase()
    self.mock.get_issue_url.return_value = ''

    response = self.app.get('/issue/12345', expect_errors=True)
    self.assertEqual(404, response.status_int)

  def test_security_testcase_without_access(self):
    """Test that a security testcase's issue is not disclosed."""
    testcase = data_types.Testcase()
    testcase.bug_information = '456789'
    testcase.security_flag = True
    self.mock.get_testcase.return_value = testcase
    self.mock.get_issue_url.return_value = 'http://google.com/456789'
    self.mock.can_user_access_testcase.return_value = False

    response = self.app.get('/issue/12345', expect_errors=True)

    # Access is refused, so the caller is never sent to the issue and the
    # issue id appears nowhere in the response. An unauthenticated caller is
    # redirected to sign in rather than served the issue URL.
    self.assertNotEqual('http://google.com/456789',
                        response.headers.get('Location'))
    self.assertNotIn('456789', response.headers.get('Location', ''))
    self.assertNotIn('456789', response.body.decode('utf-8'))

  def test_security_testcase_with_access(self):
    """Test that an authorized user still gets the redirect."""
    testcase = data_types.Testcase()
    testcase.bug_information = '456789'
    testcase.security_flag = True
    self.mock.get_testcase.return_value = testcase
    self.mock.get_issue_url.return_value = 'http://google.com/456789'
    self.mock.can_user_access_testcase.return_value = True

    response = self.app.get('/issue/12345')

    self.assertEqual(302, response.status_int)
    self.assertEqual('http://google.com/456789', response.headers['Location'])

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

import mock
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.issue_management.issue_tracker_utils.get_issue_url',
        'libs.helpers.get_testcase',
        'clusterfuzz._internal.metrics.logs._is_running_on_app_engine',
    ])
    self.mock._is_running_on_app_engine.return_value = True  # pylint: disable=protected-access

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

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
"""Delete tests."""
import unittest

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.testcase_detail import delete
from libs import form


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test HandlerTest."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.auth.get_current_user',
        'libs.auth.is_current_user_admin',
    ])
    self.mock.is_current_user_admin.return_value = True
    self.mock.get_current_user().email = 'test@user.com'
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=delete.Handler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

  def test_assigned_issue(self):
    """The testcase is assigned an issue."""
    testcase = data_types.Testcase()
    testcase.bug_information = '1234'
    testcase.put()

    resp = self.app.post_json(
        '/', {
            'testcaseId': testcase.key.id(),
            'csrf_token': form.generate_csrf_token()
        },
        expect_errors=True)
    self.assertEqual(400, resp.status_int)
    self.assertIsNotNone(testcase.key.get())

  def test_succeed(self):
    """Delete."""
    testcase = data_types.Testcase()
    testcase.bug_information = None
    testcase.put()

    resp = self.app.post_json('/', {
        'testcaseId': testcase.key.id(),
        'csrf_token': form.generate_csrf_token()
    })
    self.assertEqual(200, resp.status_int)
    self.assertIsNone(testcase.key.get())

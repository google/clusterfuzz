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
"""redo tests."""
import unittest

import flask
import webtest

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.testcase_detail import redo
from libs import form


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test Handler."""

  ALL_TASKS = ['minimize', 'regression', 'impact', 'blame', 'progression']
  USER_EMAIL = 'test@user.com'

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.redo_testcase',
        'libs.auth.get_current_user',
        'handlers.testcase_detail.show.get_testcase_detail',
        'libs.access.check_access_and_get_testcase'
    ])
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=redo.Handler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    self.mock.get_testcase_detail.return_value = {'testcase': 'yes'}
    self.testcase = data_types.Testcase()
    self.testcase.put()
    self.mock.check_access_and_get_testcase.return_value = self.testcase
    self.mock.get_current_user().email = self.USER_EMAIL

  def test_redo(self):
    """Redo all tasks."""
    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'tasks': self.ALL_TASKS,
            'csrf_token': form.generate_csrf_token(),
        })

    self.assertEqual(200, resp.status_int)
    self.assertEqual('yes', resp.json['testcase'])

    called_testcase = self.mock.redo_testcase.call_args_list[0][0][0]
    self.assertEqual(self.testcase.key.id(), called_testcase.key.id())
    self.mock.redo_testcase.assert_called_once_with(
        called_testcase, self.ALL_TASKS, self.USER_EMAIL)

  def test_invalid_task(self):
    """Invalid testcase."""
    self.mock.redo_testcase.side_effect = tasks.InvalidRedoTask('rand')

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'tasks': ['rand'],
            'csrf_token': form.generate_csrf_token(),
        },
        expect_errors=True)
    self.assertEqual(400, resp.status_int)

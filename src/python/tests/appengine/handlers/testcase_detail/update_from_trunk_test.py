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
"""update_from_trunk tests."""
import unittest
import webapp2
import webtest

from datastore import data_types
from handlers.testcase_detail import update_from_trunk
from libs import form
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'base.tasks.add_task',
        'base.tasks.queue_for_job',
        'libs.auth.get_current_user',
        'handlers.testcase_detail.show.get_testcase_detail',
        'libs.access.check_access_and_get_testcase',
    ])
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', update_from_trunk.Handler)]))

    self.testcase = data_types.Testcase(queue='old-queue')
    self.testcase.put()
    self.mock.check_access_and_get_testcase.return_value = self.testcase
    self.mock.get_testcase_detail.return_value = {'testcase': 'yes'}
    self.mock.get_current_user().email = 'test@user.com'

  def test_succeed(self):
    """Update from trunk"""
    self.mock.queue_for_job.return_value = 'jobs-suffix'

    self.testcase.crash_stacktrace = 'Random'
    self.testcase.job_type = 'job'
    self.testcase.put()

    resp = self.app.post_json(
        '/', {
            'testcaseId': self.testcase.key.id(),
            'csrf_token': form.generate_csrf_token(),
        })

    self.assertEqual(200, resp.status_int)
    self.assertEqual('yes', resp.json['testcase'])
    self.mock.add_task.assert_called_once_with(
        'variant', self.testcase.key.id(), 'job', queue='jobs-suffix')

    testcase = self.testcase.key.get()
    self.assertEqual('Pending', testcase.last_tested_crash_stacktrace)

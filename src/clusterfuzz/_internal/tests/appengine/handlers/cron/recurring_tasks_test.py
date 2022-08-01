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
"""Tests for recurring_tasks."""

import unittest

import flask
import mock
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import recurring_tasks


@test_utils.with_cloud_emulators('datastore')
class OpenReproducibleTestcaseTasksSchedulerTest(unittest.TestCase):
  """Tests OpenReproducibleTestcaseTasksScheduler."""

  def setUp(self):
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/schedule-open-reproducible-testcase-tasks',
        view_func=recurring_tasks.OpenReproducibleTestcaseTasksScheduler.
        as_view('/schedule-open-reproducible-testcase-tasks'))
    self.app = webtest.TestApp(flaskapp)

    self.testcase_0 = data_types.Testcase(
        open=True,
        one_time_crasher_flag=False,
        status='Processed',
        job_type='job',
        queue='jobs-linux')
    self.testcase_0.put()

    self.testcase_1 = data_types.Testcase(
        open=False,
        one_time_crasher_flag=False,
        status='Processed',
        job_type='job',
        queue='jobs-linux')
    self.testcase_1.put()

    self.testcase_2 = data_types.Testcase(
        open=True,
        one_time_crasher_flag=True,
        status='Processed',
        job_type='job',
        queue='jobs-linux')
    self.testcase_2.put()

    self.testcase_3 = data_types.Testcase(
        open=True,
        one_time_crasher_flag=False,
        status='NA',
        job_type='job',
        queue='jobs-linux')
    self.testcase_3.put()

    self.testcase_4 = data_types.Testcase(
        open=True,
        one_time_crasher_flag=False,
        status='Processed',
        job_type='job_windows',
        queue='jobs-windows')
    self.testcase_4.put()

    data_types.Job(name='job', environment_string='', platform='LINUX').put()
    data_types.Job(
        name='job_windows', environment_string='', platform='WINDOWS').put()

    helpers.patch(self, [
        'handlers.base_handler.Handler.is_cron',
    ])

  def test_execute(self):
    """Tests that we don't directly use this scheduler."""
    with self.assertRaises(webtest.AppError):
      self.app.get('/schedule-open-reproducible-testcase-tasks')


class ProgressionTasksSchedulerTest(OpenReproducibleTestcaseTasksSchedulerTest):
  """Tests ProgressionTasksScheduler."""

  def setUp(self):
    super(ProgressionTasksSchedulerTest, self).setUp()
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/schedule-progression-tasks',
        view_func=recurring_tasks.ProgressionTasksScheduler.as_view(
            '/schedule-progression-tasks'))
    self.app = webtest.TestApp(flaskapp)

    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
    ])

  def test_execute(self):
    """Tests scheduling of progression tasks."""
    self.app.get('/schedule-progression-tasks')
    self.mock.add_task.assert_has_calls([
        mock.call('progression', 1, 'job', queue='jobs-linux'),
        mock.call('progression', 5, 'job_windows', queue='jobs-windows')
    ])


class ImpactTasksSchedulerTest(OpenReproducibleTestcaseTasksSchedulerTest):
  """Tests ProgressionTasksScheduler."""

  def setUp(self):
    super(ImpactTasksSchedulerTest, self).setUp()
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/schedule-impact-tasks',
        view_func=recurring_tasks.ImpactTasksScheduler.as_view(
            '/schedule-impact-tasks'))
    self.app = webtest.TestApp(flaskapp)
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
    ])

  def test_execute(self):
    """Tests scheduling of progression tasks."""
    self.app.get('/schedule-impact-tasks')
    self.mock.add_task.assert_has_calls([
        mock.call('impact', 1, 'job', queue='jobs-linux'),
        mock.call('impact', 5, 'job_windows', queue='jobs-windows'),
    ])

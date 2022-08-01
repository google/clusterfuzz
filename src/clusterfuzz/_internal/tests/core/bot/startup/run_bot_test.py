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
"""run_bot tests."""
# pylint: disable=protected-access
import os
import unittest

import mock

from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.tests.test_libs import helpers
from python.bot.startup import run_bot


class MonitorTest(unittest.TestCase):
  """Test _Monitor."""

  def setUp(self):
    self.time = helpers.MockTime()
    monitor.metrics_store().reset_for_testing()

  def test_succeed(self):
    """Test succeed."""
    task = mock.Mock()
    task.command = 'task'
    task.job = 'job'

    with run_bot._Monitor(task, time_module=self.time):
      self.time.advance(5)

    self.assertEqual(
        1, monitoring_metrics.TASK_COUNT.get({
            'task': 'task',
            'job': 'job'
        }))

  def test_empty(self):
    """Test empty."""
    task = mock.Mock()
    task.command = None
    task.job = None

    with run_bot._Monitor(task, time_module=self.time):
      self.time.advance(5)

    self.assertEqual(1,
                     monitoring_metrics.TASK_COUNT.get({
                         'task': '',
                         'job': ''
                     }))

  def test_exception(self):
    """Test raising exception."""
    task = mock.Mock()
    task.command = 'task'
    task.job = 'job'

    with self.assertRaises(Exception):
      with run_bot._Monitor(task, time_module=self.time):
        self.time.advance(5)
        raise Exception('test')

    self.assertEqual(
        1, monitoring_metrics.TASK_COUNT.get({
            'task': 'task',
            'job': 'job'
        }))


class TaskLoopTest(unittest.TestCase):
  """Test task_loop."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.get_task',
        'clusterfuzz._internal.bot.tasks.commands.process_command',
        'clusterfuzz._internal.bot.tasks.update_task.run',
        'clusterfuzz._internal.bot.tasks.update_task.track_revision',
    ])

    self.task = mock.MagicMock()
    self.task.payload.return_value = 'payload'
    self.mock.get_task.return_value = self.task
    self.task.lease.__enter__ = mock.Mock(return_value=None)
    self.task.lease.__exit = mock.Mock(return_value=False)

    os.environ['FAIL_WAIT'] = '1'

  def test_exception(self):
    """Test that exceptions are properly reported."""
    self.mock.process_command.side_effect = Exception('text')
    exception, clean_exit, payload = run_bot.task_loop()
    self.assertIn('Exception: text', exception)
    self.assertFalse(clean_exit)
    self.assertEqual('payload', payload)

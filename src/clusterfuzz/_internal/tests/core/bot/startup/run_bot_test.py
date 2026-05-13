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
from unittest import mock

from clusterfuzz._internal.base import tasks as taskslib
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
        raise RuntimeError('test')

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
        'python.bot.startup.run_bot.update_task_enabled',
    ])
    self.mock.update_task_enabled.return_value = True

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

  def test_max_executions(self):
    """Test that the loop breaks after MAX_EXECUTIONS iterations."""
    from clusterfuzz._internal.system import environment
    environment._initial_environment = None
    os.environ['MAX_EXECUTIONS'] = '3'
    # Use side_effect to avoid raising an exception so it loops cleanly.
    self.mock.process_command.side_effect = None
    
    exception, clean_exit, payload = run_bot.task_loop()
    
    self.assertEqual(3, self.mock.process_command.call_count)
    self.assertTrue(clean_exit)
    self.assertEqual('payload', payload)

  @mock.patch('clusterfuzz._internal.metrics.logs.error')
  def test_max_executions_invalid(self, mock_error):
    """Test that an invalid MAX_EXECUTIONS logs an error and is removed."""
    from clusterfuzz._internal.system import environment
    environment._initial_environment = None
    os.environ['MAX_EXECUTIONS'] = 'invalid'
    
    # We need the loop to exit otherwise it will run indefinitely because we removed the limit.
    # We can make process_command succeed once, then raise an exception so it exits.
    self.mock.process_command.side_effect = [None, Exception('exit')]
    
    exception, clean_exit, payload = run_bot.task_loop()
    
    mock_error.assert_any_call('Invalid value for MAX_EXECUTIONS: invalid')
    self.assertEqual(2, self.mock.process_command.call_count)


class LeaseAllTasksTest(unittest.TestCase):
  """Tests for lease_all_tasks."""

  def test_lease_all_tasks_on_pubsubtasks(self):
    """Tests that lease_all_tasks works with PubSubTasks."""
    message = mock.Mock(
        attributes={
            'command': 'fuzz',
            'argument': 'libFuzzer',
            'job': 'libfuzzer_chrome_asan',
            'eta': 1
        })
    with mock.patch(
        'clusterfuzz._internal.base.tasks.PubSubTask.lease') as lease:
      tasks = [taskslib.PubSubTask(message)]
      with run_bot.lease_all_tasks(tasks):
        pass
    lease.assert_called_with()


class ScheduleUtaskMainsTest(unittest.TestCase):
  """Tests for schedule_utask_mains."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.get_utask_mains',
        'clusterfuzz._internal.remote_task.remote_task_gate.RemoteTaskGate',
    ])

  def test_schedule_tasks_requeue_uncreated(self):
    """Test that uncreated tasks are not acked."""
    mock_task = mock.MagicMock()
    mock_task.command = 'command'
    mock_task.job = 'job'
    mock_task.argument = 'argument'
    mock_task.lease.return_value.__enter__.return_value = None
    mock_task.lease.return_value.__exit__.return_value = None

    self.mock.get_utask_mains.return_value = [mock_task]

    # Simulate that the tasks were not created and returned back.
    self.mock.RemoteTaskGate.return_value.create_utask_main_jobs.side_effect = lambda tasks: tasks

    run_bot.schedule_utask_mains()

    self.mock.RemoteTaskGate.return_value.create_utask_main_jobs.assert_called_once(
    )

    # Verify that cancel_lease_ack was called on the pubsub task.
    mock_task.cancel_lease_ack.assert_called_once()

  def test_schedule_tasks_success(self):
    """Test scheduling tasks successfully."""
    mock_task = mock.MagicMock()
    mock_task.command = 'command'
    mock_task.job = 'job'
    mock_task.argument = 'argument'
    mock_task.lease.return_value.__enter__.return_value = None
    mock_task.lease.return_value.__exit__.return_value = None

    self.mock.get_utask_mains.return_value = [mock_task]
    self.mock.RemoteTaskGate.return_value.create_utask_main_jobs.return_value = []

    run_bot.schedule_utask_mains()

    self.mock.RemoteTaskGate.return_value.create_utask_main_jobs.assert_called_once(
    )

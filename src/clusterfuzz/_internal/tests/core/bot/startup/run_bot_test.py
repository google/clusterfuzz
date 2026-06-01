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
from clusterfuzz._internal.tests.test_libs import test_utils
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
    """Test that the loop breaks after MAX_TASK_EXECUTIONS iterations."""
    from clusterfuzz._internal.system import environment
    environment._initial_environment = None
    os.environ['MAX_TASK_EXECUTIONS'] = '3'

    _, clean_exit, payload = run_bot.task_loop()

    self.assertEqual(3, self.mock.process_command.call_count)
    self.assertTrue(clean_exit)
    self.assertEqual('payload', payload)

  @mock.patch('clusterfuzz._internal.metrics.logs.log_fatal_and_exit')
  def test_max_executions_invalid(self, mock_log_fatal_and_exit):
    """Test that an invalid MAX_TASK_EXECUTIONS logs a fatal error and exits."""
    from clusterfuzz._internal.system import environment
    environment._initial_environment = None
    os.environ['MAX_TASK_EXECUTIONS'] = 'invalid'
    mock_log_fatal_and_exit.side_effect = SystemExit

    with self.assertRaises(SystemExit):
      run_bot.task_loop()

    mock_log_fatal_and_exit.assert_any_call(
        'Invalid value for MAX_TASK_EXECUTIONS: invalid')
    self.assertEqual(0, self.mock.process_command.call_count)


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


@test_utils.with_cloud_emulators('datastore')
class ScheduleUtaskMainsTest(unittest.TestCase):
  """Tests for schedule_utask_mains."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.get_utask_mains',
        'clusterfuzz._internal.remote_task.remote_task_gate.RemoteTaskGate',
    ])
    patcher = mock.patch(
        'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
        new_callable=mock.PropertyMock)
    self.mock_swarming_enabled = patcher.start()
    self.mock_swarming_enabled.return_value = False
    self.addCleanup(patcher.stop)

  def test_schedule_tasks_requeue_uncreated(self):
    """Test that uncreated tasks are not acked."""
    mock_task = mock.MagicMock()
    mock_task.command = 'command'
    mock_task.job = 'job'
    mock_task.argument = 'argument'
    mock_task.lease.return_value.__enter__.return_value = None
    mock_task.lease.return_value.__exit__.return_value = None

    self.mock.get_utask_mains.side_effect = [[mock_task], []]

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

    self.mock.get_utask_mains.side_effect = [[mock_task], []]
    self.mock.RemoteTaskGate.return_value.create_utask_main_jobs.return_value = []

    run_bot.schedule_utask_mains()

    self.mock.RemoteTaskGate.return_value.create_utask_main_jobs.assert_called_once(
    )

  def test_schedule_tasks_both_queues(self):
    """Test that schedule_utask_mains picks up tasks from both queues."""
    regular_task = mock.MagicMock(
        command='command1', job='job1', argument='argument1')
    swarming_task = mock.MagicMock(
        command='command2', job='job2', argument='argument2')

    self.mock.get_utask_mains.side_effect = [[regular_task], [swarming_task]]
    self.mock.RemoteTaskGate.return_value.create_utask_main_jobs.return_value = []
    self.mock_swarming_enabled.return_value = True

    run_bot.schedule_utask_mains()

    self.mock.RemoteTaskGate.return_value.create_utask_main_jobs.assert_called_once(
    )
    args, _ = self.mock.RemoteTaskGate.return_value.create_utask_main_jobs.call_args
    called_batch_tasks = args[0]

    self.assertEqual(len(called_batch_tasks), 2)
    self.assertEqual(called_batch_tasks[0].pubsub_task, regular_task)
    self.assertEqual(called_batch_tasks[1].pubsub_task, swarming_task)


class TworkerGetTaskTest(unittest.TestCase):
  """Tests for tworker_get_task."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.get_value',
        'clusterfuzz._internal.system.environment.is_tworker',
        'clusterfuzz._internal.base.tasks.get_regular_task',
        'clusterfuzz._internal.base.tasks.get_postprocess_task',
        'clusterfuzz._internal.base.tasks.get_preprocess_task',
        'clusterfuzz._internal.base.tasks.random.random',
        'clusterfuzz._internal.google_cloud_utils.compute_metadata.is_gce',
        'clusterfuzz._internal.google_cloud_utils.compute_metadata.get',
    ])
    self.mock.is_tworker.return_value = True
    self.mock.is_gce.return_value = False

  def test_override_queue_set(self):
    """Test that tworker_get_task returns a task from the override queue."""
    self.mock.get_value.return_value = 'override_queue'
    override = run_bot._get_tworker_queue_override(__memoize_force__=True)  # pylint: disable=protected-access
    mock_task = mock.Mock()
    self.mock.get_regular_task.return_value = mock_task

    result = taskslib.tworker_get_task(override_queue=override)

    self.assertEqual(result, mock_task)
    self.mock.get_regular_task.assert_called_once_with(queue='override_queue')

  def test_override_queue_not_set(self):
    """Test that tworker_get_task falls back to random choice when override queue is not set."""
    self.mock.get_value.return_value = None
    override = run_bot._get_tworker_queue_override(__memoize_force__=True)  # pylint: disable=protected-access
    self.mock.random.return_value = 0.4
    mock_task = mock.Mock()
    self.mock.get_postprocess_task.return_value = mock_task

    result = taskslib.tworker_get_task(override_queue=override)

    self.assertEqual(result, mock_task)
    self.mock.get_postprocess_task.assert_called_once()

  def test_override_queue_empty(self):
    """Test that tworker_get_task falls back to random choice when override queue is empty."""
    self.mock.get_value.return_value = ''
    override = run_bot._get_tworker_queue_override(__memoize_force__=True)  # pylint: disable=protected-access
    self.mock.random.return_value = 0.6
    mock_task = mock.Mock()
    self.mock.get_preprocess_task.return_value = mock_task

    result = taskslib.tworker_get_task(override_queue=override)

    self.assertEqual(result, mock_task)
    self.mock.get_preprocess_task.assert_called_once()

  def test_override_queue_from_metadata_success(self):
    """Test that tworker_get_task returns a task from the override queue in metadata."""
    self.mock.get_value.return_value = None
    self.mock.is_gce.return_value = True
    self.mock.get.return_value = ' metadata_override '
    override = run_bot._get_tworker_queue_override(__memoize_force__=True)  # pylint: disable=protected-access
    mock_task = mock.Mock()
    self.mock.get_regular_task.return_value = mock_task

    result = taskslib.tworker_get_task(override_queue=override)

    self.assertEqual(result, mock_task)
    self.mock.get_regular_task.assert_called_once_with(
        queue='metadata_override')

  def test_override_queue_from_metadata_exception(self):
    """Test that tworker_get_task falls back to original behavior when metadata fetch fails."""
    from requests import exceptions
    self.mock.get_value.return_value = None
    self.mock.is_gce.return_value = True
    self.mock.get.side_effect = exceptions.RequestException("Failed")
    override = run_bot._get_tworker_queue_override(__memoize_force__=True)  # pylint: disable=protected-access
    self.mock.random.return_value = 0.4
    mock_task = mock.Mock()
    self.mock.get_postprocess_task.return_value = mock_task

    result = taskslib.tworker_get_task(override_queue=override)

    self.assertEqual(result, mock_task)
    self.mock.get_postprocess_task.assert_called_once()

# Copyright 2023 Google LLC
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
"""Tests for task_types."""

import datetime
import inspect
import os
import unittest
from unittest import mock

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base.tasks import pub_sub_task_queue
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.bot.tasks import task_types
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class IsRemoteUtaskTest(unittest.TestCase):
  """Tests for is_remote_utask."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_mac(self):
    job_name = 'libfuzzer_mac_asan'

    with mock.patch(
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        return_value=True):
      data_types.Job(name=job_name, platform='MAC').put()
      self.assertFalse(task_types.is_remote_utask('variant', job_name))

  @unittest.skip('No remote utasks')
  def test_linux(self):
    job_name = 'libfuzzer_linux_asan'

    with mock.patch(
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        return_value=True):
      data_types.Job(name=job_name, platform='LINUX').put()
      self.assertTrue(task_types.is_remote_utask('progression', job_name))

  def test_trusted(self):
    job_name = 'libfuzzer_linux_asan'

    with mock.patch(
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        return_value=True):
      data_types.Job(name=job_name, platform='LINUX').put()
      self.assertFalse(task_types.is_remote_utask('impact', job_name))


@test_utils.with_cloud_emulators('datastore')
class TrustedTaskEventTest(unittest.TestCase):
  # pylint: disable=protected-access
  """Tests for emitting task execution events in trusted tasks."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.events.emit',
        'clusterfuzz._internal.metrics.events._get_datetime_now',
    ])
    self.mock._get_datetime_now.return_value = datetime.datetime(2025, 1, 1)
    os.environ['CF_TASK_ID'] = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    os.environ['CF_TASK_NAME'] = 'mock_task'

  def tearDown(self):
    task_utils._TESTCASE_BASED_TASKS.discard('mock')

  def test_task_event_emit(self):
    """Tests that task events are emitted during a successfull execution."""
    module = mock.MagicMock(__name__='mock_task')
    task_utils._TESTCASE_BASED_TASKS.add('mock')

    task = task_types.TrustedTask(module)
    task.execute(task_argument='1', job_type='job1', uworker_env={})
    module.execute_task.assert_called_once_with('1', 'job1')

    # Asserts for task execution events emitted.
    event_data = {
        'task_job': 'job1',
        'testcase_id': 1,
        'task_stage': events.TaskStage.NA
    }
    event_started = events.TaskExecutionEvent(
        **event_data, task_status=events.TaskStatus.STARTED)
    event_finished = events.TaskExecutionEvent(
        **event_data, task_status=events.TaskStatus.FINISHED)

    self.assertTrue(self.mock.emit.call_count, 2)
    self.mock.emit.assert_any_call(event_started)
    self.mock.emit.assert_any_call(event_finished)

  def test_event_emit_during_exception(self):
    """Tests that task events are emitted during a unhandled exception."""
    module = mock.MagicMock(__name__='mock_task')
    task_utils._TESTCASE_BASED_TASKS.add('mock')

    module.execute_task.side_effect = ValueError
    task = task_types.TrustedTask(module)
    try:
      task.execute(task_argument='1', job_type='job1', uworker_env={})
    except:
      pass

    module.execute_task.assert_called_once_with('1', 'job1')

    # Asserts for task execution events emitted.
    event_data = {
        'task_job': 'job1',
        'testcase_id': 1,
        'task_stage': events.TaskStage.NA
    }
    event_started = events.TaskExecutionEvent(
        **event_data, task_status=events.TaskStatus.STARTED)
    event_finished = events.TaskExecutionEvent(
        **event_data,
        task_status=events.TaskStatus.EXCEPTION,
        task_outcome=events.TaskOutcome.UNHANDLED_EXCEPTION)

    self.assertTrue(self.mock.emit.call_count, 2)
    self.mock.emit.assert_any_call(event_started)
    self.mock.emit.assert_any_call(event_finished)


@test_utils.with_cloud_emulators('datastore')
class UTaskExecuteTest(unittest.TestCase):
  """Tests for UTask execution."""

  def setUp(self):
    self.mock_module = mock.Mock()
    self.mock_module.__name__ = 'module'
    self.utask = task_types.UTask(self.mock_module)

    patchers = [
        mock.patch(
            'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module',
            return_value='command'),
        mock.patch(
            'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
            return_value=True),
        mock.patch('clusterfuzz._internal.metrics.logs.info'),
    ]
    for patcher in patchers:
      patcher.start()
      self.addCleanup(patcher.stop)

  def test_execute_raises_queue_limit_reached(self):
    """Tests that QueueLimitReachedError is raised when limit is exceeded."""
    with mock.patch(
        'clusterfuzz._internal.bot.tasks.task_types.tasks.get_utask_main_queue_size'
    ) as mock_size:
      mock_size.return_value = 10001

      with mock.patch(
          'clusterfuzz._internal.bot.tasks.task_types.is_remote_utask',
          return_value=True):
        with mock.patch(
            'clusterfuzz._internal.bot.tasks.task_types.environment.is_tworker',
            return_value=False):
          with self.assertRaises(errors.QueueLimitReachedError):
            self.utask.execute('arg', 'job', {})

  def test_execute_proceeds_below_limit(self):
    """Tests that execution proceeds when queue size is within limit."""
    self.utask.preprocess = mock.Mock(return_value=None)  # Stop execution flow

    with mock.patch(
        'clusterfuzz._internal.bot.tasks.task_types.tasks.get_utask_main_queue_size'
    ) as mock_size:
      mock_size.return_value = 9999

      with mock.patch(
          'clusterfuzz._internal.bot.tasks.task_types.is_remote_utask',
          return_value=True):
        with mock.patch(
            'clusterfuzz._internal.bot.tasks.task_types.environment.is_tworker',
            return_value=False):
          self.utask.execute('arg', 'job', {})
          self.utask.preprocess.assert_called()


class TaskExecuteLocalOrRemoteTest(unittest.TestCase):
  """Tests that executing a task either runs it locally or queues it for remote
  execution, for every kind of task module in COMMAND_TYPES."""

  # Tasks that run untrusted code, and thus can have their uworker_main shipped
  # off to batch or swarming.
  UTASK_COMMANDS = sorted(
      command for command, task_type in task_types.COMMAND_TYPES.items()
      if issubclass(task_type, task_types.BaseUTask))

  # Utasks that are only remotely executed when a tworker forces it, see
  # commands.get_command_object().
  TWORKER_ONLY_REMOTE_COMMANDS = sorted(
      command for command, task_type in task_types.COMMAND_TYPES.items()
      if task_type is task_types.UTaskLocalExecutor)

  # Tasks that always run in this process, they are never remotely executed.
  TRUSTED_COMMANDS = sorted(
      command for command, task_type in task_types.COMMAND_TYPES.items()
      if task_type is task_types.TrustedTask)

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_utask_main',
        'clusterfuzz._internal.base.tasks.get_utask_main_queue_size',
        'clusterfuzz._internal.base.tasks.pub_sub_task_queue.PubSubTaskQueue.get_max_target_size',
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        'clusterfuzz._internal.batch.service.is_remote_task',
        'clusterfuzz._internal.bot.tasks.task_types.BaseUTask.execute_locally',
        'clusterfuzz._internal.bot.tasks.task_types.UTask.preprocess',
        'clusterfuzz._internal.swarming.is_swarming_task',
    ])

    # Defaults: nothing is remote and the utask_main queue is empty.
    self.mock.is_remotely_executing_utasks.return_value = False
    self.mock.is_remote_task.return_value = False
    self.mock.is_swarming_task.return_value = False
    self.mock.get_utask_main_queue_size.return_value = 0
    self.mock.get_max_target_size.return_value = 1000
    self.mock.preprocess.return_value = 'https://download-url'

  def _execute(self, command):
    """Executes `command` through the real command dispatch, which is what
    decides the task class to use (e.g. tworkers force utasks into UTask)."""
    self.mock.execute_locally.reset_mock()
    self.mock.add_utask_main.reset_mock()
    commands.get_command_object(command).execute('1', 'job', {})

  def _assert_executed_locally(self):
    """Asserts the utask was executed locally, and not queued for remote
    execution."""
    self.mock.execute_locally.assert_called_once()
    self.mock.add_utask_main.assert_not_called()

  def _assert_queued_on(self, queue_name):
    """Asserts the utask was queued on `queue_name`, and not executed
    locally."""
    self.mock.execute_locally.assert_not_called()
    self.mock.add_utask_main.assert_called_once()
    # Bind the recorded call to add_utask_main()'s signature, so that the queue
    # is looked up by name instead of by position.
    call = self.mock.add_utask_main.call_args
    arguments = inspect.signature(self.mock.add_utask_main).bind(
        *call.args, **call.kwargs).arguments
    self.assertEqual(queue_name, arguments['queue_name'])

  def test_executes_locally_when_remote_execution_is_disabled(self):
    """Tests that utasks run locally when remote execution is disabled."""
    self.mock.is_remotely_executing_utasks.return_value = False

    for command in self.UTASK_COMMANDS:
      with self.subTest(command=command):
        self._execute(command)
        self._assert_executed_locally()

  def test_executes_locally_when_job_is_not_remote(self):
    """Tests that utasks run locally when the job is neither a batch nor a
    swarming job."""
    self.mock.is_remotely_executing_utasks.return_value = True
    self.mock.is_remote_task.return_value = False
    self.mock.is_swarming_task.return_value = False

    for command in self.UTASK_COMMANDS:
      with self.subTest(command=command):
        self._execute(command)
        self._assert_executed_locally()

  def test_routes_batch_jobs_to_the_utask_main_queue(self):
    """Tests that a utask on a batch job is queued on the utask_main queue."""
    self.mock.is_remotely_executing_utasks.return_value = True
    self.mock.is_remote_task.return_value = True
    self.mock.is_swarming_task.return_value = False

    for command in self.UTASK_COMMANDS:
      with self.subTest(command=command):
        self._execute(command)
        if command in self.TWORKER_ONLY_REMOTE_COMMANDS:
          self._assert_executed_locally()
        else:
          self._assert_queued_on(pub_sub_task_queue.UTASK_MAIN_QUEUE.name)

  def test_routes_swarming_jobs_to_the_swarming_queue(self):
    """Tests that a utask on a swarming job is queued on the swarming
    utask_main queue, even though it is not a batch remote task."""
    self.mock.is_remotely_executing_utasks.return_value = True
    self.mock.is_remote_task.return_value = False
    self.mock.is_swarming_task.return_value = True

    for command in self.UTASK_COMMANDS:
      with self.subTest(command=command):
        self._execute(command)
        if command in self.TWORKER_ONLY_REMOTE_COMMANDS:
          self._assert_executed_locally()
        else:
          self._assert_queued_on(
              pub_sub_task_queue.SWARMING_UTASK_MAIN_QUEUE.name)

  def test_tworker_routes_batch_jobs_to_the_utask_main_queue(self):
    """Tests that on a tworker every utask on a batch job is queued on the
    utask_main queue, including the ones that run locally elsewhere."""
    os.environ['TWORKER'] = 'True'
    self.mock.is_remote_task.return_value = True
    self.mock.is_swarming_task.return_value = False

    for command in self.UTASK_COMMANDS:
      with self.subTest(command=command):
        self._execute(command)
        self._assert_queued_on(pub_sub_task_queue.UTASK_MAIN_QUEUE.name)

  def test_tworker_routes_swarming_jobs_to_the_swarming_queue(self):
    """Tests that on a tworker every utask on a swarming job is queued on the
    swarming utask_main queue, including the ones that run locally
    elsewhere."""
    os.environ['TWORKER'] = 'True'
    self.mock.is_remote_task.return_value = False
    self.mock.is_swarming_task.return_value = True

    for command in self.UTASK_COMMANDS:
      with self.subTest(command=command):
        self._execute(command)
        self._assert_queued_on(
            pub_sub_task_queue.SWARMING_UTASK_MAIN_QUEUE.name)

  def test_trusted_tasks_always_execute_locally(self):
    """Tests that trusted tasks run in this process and are never queued, even
    on a job that is remote for utasks."""
    self.mock.is_remotely_executing_utasks.return_value = True
    self.mock.is_remote_task.return_value = True
    self.mock.is_swarming_task.return_value = True

    for command in self.TRUSTED_COMMANDS:
      with self.subTest(command=command):
        with mock.patch(f'clusterfuzz._internal.bot.tasks.{command}_task'
                        '.execute_task') as execute_task:
          self._execute(command)
          execute_task.assert_called_once_with('1', 'job')
        self.mock.execute_locally.assert_not_called()
        self.mock.add_utask_main.assert_not_called()

  def test_neither_when_preprocess_fails(self):
    """Tests that nothing is queued when preprocess returns no download url."""
    os.environ['TWORKER'] = 'True'
    self.mock.is_remote_task.return_value = True
    self.mock.preprocess.return_value = None

    for command in self.UTASK_COMMANDS:
      with self.subTest(command=command):
        self._execute(command)
        self.mock.execute_locally.assert_not_called()
        self.mock.add_utask_main.assert_not_called()

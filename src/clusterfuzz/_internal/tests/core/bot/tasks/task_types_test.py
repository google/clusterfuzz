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
import os
import unittest
from unittest import mock

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.bot.tasks import task_types
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.system import environment
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

  def test_uworker(self):
    """Tests that is_remote_utask returns True when running on a uworker."""
    environment.set_value('UWORKER', True)

    result = task_types.is_remote_utask('fuzz', 'any_job')

    self.assertTrue(result)

  def test_linux_fuzz_tworker(self):
    """Tests that on an orchestration tworker, is_remote_utask evaluates 'fuzz'
    as remote when configured for batch, ensuring signed URLs are generated
    during preprocess."""
    mock_remotely_executing = mock.patch(
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        return_value=True)
    mock_is_remote_task = mock.patch(
        'clusterfuzz._internal.batch.service.is_remote_task', return_value=True)
    environment.set_value('TWORKER', True)

    with mock_remotely_executing, mock_is_remote_task:
      result = task_types.is_remote_utask('fuzz', 'linux_asan_chrome')

    self.assertTrue(result)

  def test_linux_fuzz_tworker_swarming(self):
    """Tests that on an orchestration tworker, is_remote_utask returns False for
    fuzz if the task is not targeting remote batch or swarming."""
    mock_remotely_executing = mock.patch(
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        return_value=True)
    mock_is_remote_task = mock.patch(
        'clusterfuzz._internal.batch.service.is_remote_task',
        return_value=False)
    mock_is_swarming = mock.patch(
        'clusterfuzz._internal.swarming.is_swarming_task', return_value=False)
    environment.set_value('TWORKER', True)

    with mock_remotely_executing, mock_is_remote_task, mock_is_swarming:
      result = task_types.is_remote_utask('fuzz', 'linux_asan_chrome')

    self.assertFalse(result)

  def test_linux_fuzz_trusted_pooled_bot(self):
    """Tests that trusted pooled bots (e.g. Windows, Mac, or legacy Linux bots
    which run fuzz tasks end-to-end locally) evaluate is_remote_utask as False.
    """
    mock_remotely_executing = mock.patch(
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        return_value=True)
    mock_is_remote_task = mock.patch(
        'clusterfuzz._internal.batch.service.is_remote_task', return_value=True)
    environment.set_value('TWORKER', False)
    environment.set_value('UWORKER', False)

    with mock_remotely_executing, mock_is_remote_task:
      result = task_types.is_remote_utask('fuzz', 'linux_asan_chrome')

    self.assertFalse(result)

  def test_trusted_tworker(self):
    """Tests that on an orchestration tworker, is_remote_utask returns False non
    fuzz tasks on batch."""
    mock_remotely_executing = mock.patch(
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        return_value=True)
    mock_is_remote_task = mock.patch(
        'clusterfuzz._internal.batch.service.is_remote_task', return_value=True)
    environment.set_value('TWORKER', True)

    with mock_remotely_executing, mock_is_remote_task:
      result = task_types.is_remote_utask('impact', 'linux_asan_chrome')

    self.assertFalse(result)


@test_utils.with_cloud_emulators('datastore')
class TaskMainRunsOnUworkerTest(unittest.TestCase):
  """Tests for task_main_runs_on_uworker."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        'clusterfuzz._internal.batch.service.is_remote_task',
    ])
    self.mock.is_remotely_executing_utasks.return_value = True
    self.mock.is_remote_task.return_value = True

  def test_fuzz_tworker(self):
    """Tests that task_main_runs_on_uworker returns True during preprocess on
    an orchestration tworker for a batch fuzz task, triggering signed URL
    generation for data bundles."""
    environment.set_value('TASK_NAME', 'fuzz')
    environment.set_value('JOB_NAME', 'linux_asan_chrome')
    environment.set_value('TWORKER', True)

    result = task_types.task_main_runs_on_uworker()

    self.assertTrue(result)

  def test_fuzz_trusted_pooled_bot(self):
    """Tests that task_main_runs_on_uworker returns False on trusted pooled bots
    """
    environment.set_value('TASK_NAME', 'fuzz')
    environment.set_value('JOB_NAME', 'linux_asan_chrome')
    environment.set_value('TWORKER', False)
    environment.set_value('UWORKER', False)

    result = task_types.task_main_runs_on_uworker()

    self.assertFalse(result)

  def test_trusted_task(self):
    """Tests that task_main_runs_on_uworker returns False for trusted tasks
    (e.g. impact) even on orchestration tworkers."""
    environment.set_value('TASK_NAME', 'impact')
    environment.set_value('JOB_NAME', 'linux_asan_chrome')
    environment.set_value('TWORKER', True)

    result = task_types.task_main_runs_on_uworker()

    self.assertFalse(result)


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

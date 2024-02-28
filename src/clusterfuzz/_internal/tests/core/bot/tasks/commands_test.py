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
"""commands tests."""
import datetime
import os
import unittest
from unittest import mock

from google.cloud import ndb

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@commands.set_task_payload
def dummy(*args, **kwargs):
  """A dummy function."""
  del args
  del kwargs
  return os.environ['TASK_PAYLOAD']


def dummy_wrapper():
  return dummy('payload', 'argument', 'jobname', False, preprocess=False)


@commands.set_task_payload
def dummy_exception(*args, **kwargs):
  """A dummy function."""
  raise RuntimeError(os.environ['TASK_PAYLOAD'])


class SetTaskPayloadTest(unittest.TestCase):
  """Test set_task_payload."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, ['clusterfuzz._internal.base.tasks.construct_payload'])
    self.mock.construct_payload.return_value = 'payload something'

  def test_set(self):
    """Test set."""
    self.assertEqual('payload something', dummy_wrapper())
    self.assertIsNone(os.getenv('TASK_PAYLOAD'))

  def test_exc(self):
    """Test when exception occurs."""
    task = mock.Mock()
    task.payload.return_value = 'payload something'
    with self.assertRaises(Exception) as cm:
      self.assertEqual('payload something', dummy_exception(
          'task', 'arg', 'job'))
      self.assertEqual('payload something', str(cm.exception))
    self.assertEqual({'task_payload': 'payload something'}, cm.exception.extras)
    self.assertIsNone(os.getenv('TASK_PAYLOAD'))


@test_utils.with_cloud_emulators('datastore')
class RunCommandTest(unittest.TestCase):
  """Tests for run_command."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        ('fuzz_utask_main',
         'clusterfuzz._internal.bot.tasks.utasks.fuzz_task.utask_main'),
        ('progression_utask_main',
         'clusterfuzz._internal.bot.tasks.utasks.progression_task.utask_main'),
        ('progression_utask_preprocess',
         'clusterfuzz._internal.bot.tasks.utasks.progression_task.utask_preprocess'
        ),
        'clusterfuzz._internal.bot.tasks.utasks.tworker_postprocess_no_io',
        'clusterfuzz._internal.base.utils.utcnow',
        'clusterfuzz._internal.bot.tasks.setup.preprocess_update_fuzzer_and_data_bundles',
        'clusterfuzz._internal.google_cloud_utils.blobs.get_signed_upload_url',
    ])

    self.mock.get_signed_upload_url.return_value = 'https://upload'

    os.environ['BOT_NAME'] = 'bot_name'
    os.environ['TASK_LEASE_SECONDS'] = '60'
    os.environ['FAIL_WAIT'] = '60'
    os.environ['TEST_TIMEOUT'] = '10'
    self.mock.utcnow.return_value = test_utils.CURRENT_TIME

  def test_run_command_postprocess(self):
    """Tests that the postprocess command is executed properly."""
    worker_output_url = '/worker-output'
    with mock.patch('clusterfuzz._internal.bot.tasks.utasks.tworker_postprocess'
                   ) as postprocess:
      commands.run_command('postprocess', worker_output_url, 'none', {})
    postprocess.assert_called_with(worker_output_url)

  def test_run_command_fuzz(self):
    """Test run_command with a normal command."""
    self.mock.preprocess_update_fuzzer_and_data_bundles.return_value = (
        uworker_msg_pb2.SetupInput())

    job_name = 'libfuzzer_job'
    os.environ['JOB_NAME'] = job_name
    commands.run_command('fuzz', 'fuzzer', job_name, {})

    uworker_input = self.mock.fuzz_utask_main.call_args_list[0][0][0]
    self.assertEqual(1, self.mock.fuzz_utask_main.call_count)
    self.assertEqual(uworker_input.fuzzer_name, 'fuzzer')
    self.assertEqual(uworker_input.job_type, job_name)

    # Fuzz task should not create any TaskStatus entities.
    task_status_entities = list(data_types.TaskStatus.query())
    self.assertEqual(0, len(task_status_entities))

  def test_run_command_progression(self):
    """Test run_command with a progression task."""

    self.mock.progression_utask_preprocess.return_value = uworker_msg_pb2.Input(
        job_type='job', testcase_id='123')
    commands.run_command('progression', '123', 'job', {})

    self.assertEqual(1, self.mock.progression_utask_main.call_count)
    uworker_input = self.mock.progression_utask_main.call_args_list[0][0][0]
    self.assertEqual(uworker_input.testcase_id, '123')
    self.assertEqual(uworker_input.job_type, 'job')

    # TaskStatus should indicate success.
    task_status_entities = list(data_types.TaskStatus.query())
    self.assertEqual(1, len(task_status_entities))

    task_status = task_status_entities[0]
    self.assertEqual(
        ndb.Key(data_types.TaskStatus, 'progression 123 job'), task_status.key)

    self.assertDictEqual({
        'bot_name': 'bot_name',
        'status': 'finished',
        'time': test_utils.CURRENT_TIME,
    }, task_status.to_dict())

  def test_run_command_exception(self):
    """Test run_command with an exception."""
    self.mock.progression_utask_main.side_effect = Exception

    with self.assertRaises(Exception):
      commands.run_command('progression', '123', 'job', {})

    # TaskStatus should indicate failure.
    task_status_entities = list(data_types.TaskStatus.query())
    self.assertEqual(1, len(task_status_entities))

    task_status = task_status_entities[0]
    self.assertDictEqual({
        'bot_name': 'bot_name',
        'status': 'errored out',
        'time': test_utils.CURRENT_TIME,
    }, task_status.to_dict())

  def test_run_command_invalid_testcase(self):
    """Test run_command with an invalid testcase exception."""
    self.mock.progression_utask_preprocess.side_effect = errors.InvalidTestcaseError(
        123)
    commands.run_command('progression', '123', 'job', {})

    task_status_entities = list(data_types.TaskStatus.query())
    self.assertEqual(1, len(task_status_entities))

    # TaskStatus should still indicate success.
    task_status = task_status_entities[0]
    self.assertDictEqual({
        'bot_name': 'bot_name',
        'status': 'finished',
        'time': test_utils.CURRENT_TIME,
    }, task_status.to_dict())

  def test_run_command_already_running(self):
    """Test run_command with another instance currently running."""
    data_types.TaskStatus(
        id='progression 123 job',
        bot_name='another_bot',
        time=test_utils.CURRENT_TIME,
        status='started').put()

    with self.assertRaises(commands.AlreadyRunningError):
      commands.run_command('progression', '123', 'job', {})

    self.assertEqual(0, self.mock.progression_utask_main.call_count)

    task_status_entities = list(data_types.TaskStatus.query())
    self.assertEqual(1, len(task_status_entities))

    task_status = task_status_entities[0]
    self.assertDictEqual({
        'bot_name': 'another_bot',
        'status': 'started',
        'time': test_utils.CURRENT_TIME,
    }, task_status.to_dict())

  def test_run_command_already_running_expired(self):
    """Test run_command with another instance currently running, but its lease
    has expired."""
    data_types.TaskStatus(
        id='progression 123 job',
        bot_name='another_bot',
        time=datetime.datetime(1970, 1, 1),
        status='started').put()

    self.mock.progression_utask_preprocess.return_value = uworker_msg_pb2.Input(
        job_type='job', testcase_id='123')
    commands.run_command('progression', '123', 'job', {})
    self.assertEqual(1, self.mock.progression_utask_main.call_count)

    task_status_entities = list(data_types.TaskStatus.query())
    self.assertEqual(1, len(task_status_entities))

    task_status = task_status_entities[0]
    self.assertDictEqual({
        'bot_name': 'bot_name',
        'status': 'finished',
        'time': test_utils.CURRENT_TIME,
    }, task_status.to_dict())


class UpdateEnvironmentForJobTest(unittest.TestCase):
  """update_environment_for_job tests."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_basic(self):
    """Basic tests."""
    commands.update_environment_for_job('FUZZ_TEST_TIMEOUT = 123\n'
                                        'MAX_TESTCASES = 5\n'
                                        'B = abcdef\n')
    self.assertEqual(123, environment.get_value('FUZZ_TEST_TIMEOUT'))
    self.assertEqual(5, environment.get_value('MAX_TESTCASES'))
    self.assertEqual('abcdef', environment.get_value('B'))

  def test_timeout_overrides(self):
    """Test timeout overrides."""
    environment.set_value('FUZZ_TEST_TIMEOUT_OVERRIDE', 9001)
    environment.set_value('MAX_TESTCASES_OVERRIDE', 42)
    commands.update_environment_for_job(
        'FUZZ_TEST_TIMEOUT = 123\nMAX_TESTCASES = 5\n')
    self.assertEqual(9001, environment.get_value('FUZZ_TEST_TIMEOUT'))
    self.assertEqual(42, environment.get_value('MAX_TESTCASES'))

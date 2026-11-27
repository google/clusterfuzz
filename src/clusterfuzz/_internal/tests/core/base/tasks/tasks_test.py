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
"""Tests for tasks."""
import os
import tempfile
import unittest
from unittest import mock

from clusterfuzz._internal.base import feature_flags
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base.tasks import pub_sub_task_queue
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class InitializeTaskTest(unittest.TestCase):
  """Tests for initialize_task."""

  def setUp(self):
    self.command = 'symbolize'
    self.argument = 'blah'
    self.job = 'linux_asan_chrome_mp'
    self.path = 'worker.output'
    self.message = mock.MagicMock()

  def test_initialize_trusted_task(self):
    """Tests that a normal trusted task is initialized properly."""
    self.message.attributes = {
        'command': self.command,
        'argument': self.argument,
        'job': self.job,
        'eta': 1,
    }
    task = tasks.initialize_task(self.message)
    self.assertIsInstance(task, tasks.PubSubTask)
    self.assertEqual(task.command, self.command)
    self.assertEqual(task.argument, self.argument)
    self.assertEqual(task.job, self.job)

  def test_initialize_untrusted_task(self):
    """Tests that an untrusted task is initialized properly."""
    self.message.attributes = {
        'eventType':
            'OBJECT_FINALIZE',
        'objectGeneration':
            '1698182630721865',
        'eventTime':
            '2023-10-24T21:23:50.761055Z',
        'payloadFormat':
            'JSON_API_V1',
        'bucketId':
            'uworker-output',
        'notificationConfig':
            'projects/_/buckets/uworker-output/notificationConfigs/4',
        'objectId':
            'm9'
    }
    self.message.data = (
        b'''{\n  "kind": "storage#object",\n  "id": "uworker-output/uworker.output/1698182630721865",\n  '''
        b'''"selfLink": "https://www.googleapis.com/storage/v1/b/uworker-output/o/uworker.output",\n  '''
        b'''"name": "worker.output",\n  "bucket": "uworker-output",\n  "generation": "1698182630721865",\n'''
        b'''"metageneration": "1",\n  "contentType": "application/octet-stream",\n  "timeCreated": "2023-10-24T21:23:50.761Z",\n'''
        b''' "updated": "2023-10-24T21:23:50.761Z",\n  "storageClass": "STANDARD",\n  '''
        b'''"timeStorageClassUpdated": "2023-10-24T21:23:50.761Z",\n  "size": "0",\n  "md5Hash": "1B2M2Y8AsgTpgAmY7PhCfg==",\n'''
        b'''"mediaLink": "https://storage.googleapis.com/download/storage/v1/b/uworker-output/o/uworker.output?generation=1698'''
        b'''182630721865&alt=media",\n  "contentLanguage": "en",\n  "crc32c": "AAAAAA==",\n  "etag": "CMmS36PPj4IDEAE="\n}\n'''
    )
    task = tasks.initialize_task(self.message)
    self.assertIsInstance(task, tasks.PostprocessPubSubTask)
    self.assertEqual(task.command, 'postprocess')
    self.assertEqual(task.argument, 'gs://uworker-output/worker.output')
    self.assertEqual(task.job, 'none')


class GetMachineTemplateForQueueTests(unittest.TestCase):
  """Tests that we know the specs of an instance to launch a batch task on."""

  def setUp(self):
    self.maxDiff = None

  def test_get_machine_template_for_linux_queue(self):
    """Tests that the correct specs are found for preemptible linux tasks."""
    queue_name = 'jobs-linux'
    template = tasks.get_machine_template_for_queue(queue_name)
    expected_template = {
        'description': '{"version": 1}',
        'name': 'clusterfuzz-linux-pre',
        'properties': {
            'disks': [{
                'autoDelete': True,
                'boot': True,
                'initializeParams': {
                    'diskSizeGb':
                        100,
                    'diskType':
                        'pd-standard',
                    'sourceImage':
                        'projects/cos-cloud/global/images/family/cos-stable'
                }
            }],
            'machineType':
                'n1-standard-1',
            'metadata': {
                'items': [{
                    'key':
                        'docker-image',
                    'value':
                        'gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654'
                }, {
                    'key': 'user-data',
                    'value': 'file://linux-init.yaml'
                }]
            },
            'networkInterfaces': [{
                'accessConfigs': [{
                    'name': 'External '
                            'NAT',
                    'type': 'ONE_TO_ONE_NAT'
                }],
                'network':
                    'global/networks/default'
            }],
            'scheduling': {
                'preemptible': True
            },
            'serviceAccounts': [{
                'email':
                    'test-clusterfuzz-service-account-email',
                'scopes': [
                    'https://www.googleapis.com/auth/cloud-platform',
                    'https://www.googleapis.com/auth/prodxmon'
                ]
            }]
        }
    }

    self.assertEqual(template, expected_template)

  def test_get_machine_template_for_windows_queue(self):
    """Tests that the correct specs are found for preemptible windows tasks."""
    queue_name = 'jobs-windows'
    template = tasks.get_machine_template_for_queue(queue_name)
    expected_template = {
        'description': '{"version": 1}',
        'name': 'clusterfuzz-windows-pre',
        'properties': {
            'disks': [{
                'autoDelete': True,
                'boot': True,
                'initializeParams': {
                    'diskSizeGb':
                        100,
                    'diskType':
                        'pd-standard',
                    'sourceImage':
                        'https://www.googleapis.com/compute/v1/projects/windows-cloud/global/images/family/windows-2016'
                }
            }],
            'machineType':
                'n1-standard-2',
            'metadata': {
                'items': [{
                    'key': 'windows-startup-script-ps1',
                    'value': 'file://windows-init.ps1'
                }]
            },
            'networkInterfaces': [{
                'accessConfigs': [{
                    'name': 'External '
                            'NAT',
                    'type': 'ONE_TO_ONE_NAT'
                }],
                'network':
                    'global/networks/default'
            }],
            'scheduling': {
                'preemptible': True
            },
            'serviceAccounts': [{
                'email':
                    'test-clusterfuzz-service-account-email',
                'scopes': [
                    'https://www.googleapis.com/auth/cloud-platform',
                    'https://www.googleapis.com/auth/prodxmon'
                ]
            }]
        }
    }

    self.assertEqual(template, expected_template)

  def test_get_machine_template_for_high_end_linux_queue(self):
    """Tests that the correct specs are found for nonpreemptible linux tasks."""
    queue_name = 'high-end-jobs-linux'
    template = tasks.get_machine_template_for_queue(queue_name)
    expected_template = {
        'description': '{"version": 1}',
        'name': 'clusterfuzz-linux',
        'properties': {
            'disks': [{
                'autoDelete': True,
                'boot': True,
                'initializeParams': {
                    'diskSizeGb':
                        100,
                    'diskType':
                        'pd-standard',
                    'sourceImage':
                        'projects/cos-cloud/global/images/family/cos-stable'
                }
            }],
            'machineType':
                'n1-standard-1',
            'metadata': {
                'items': [{
                    'key':
                        'docker-image',
                    'value':
                        'gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654'
                }, {
                    'key': 'user-data',
                    'value': 'file://linux-init.yaml'
                }]
            },
            'networkInterfaces': [{
                'accessConfigs': [{
                    'name': 'External '
                            'NAT',
                    'type': 'ONE_TO_ONE_NAT'
                }],
                'network':
                    'global/networks/default'
            }],
            'serviceAccounts': [{
                'email':
                    'test-clusterfuzz-service-account-email',
                'scopes': [
                    'https://www.googleapis.com/auth/cloud-platform',
                    'https://www.googleapis.com/auth/prodxmon'
                ]
            }]
        }
    }

    self.assertEqual(template, expected_template)


class GetTaskFromMessageTest(unittest.TestCase):
  """Tests for get_task_from_message."""

  def setUp(self):
    self.mock_message = mock.MagicMock()
    self.mock_task = mock.Mock(defer=mock.Mock(return_value=False))
    self.mock_task.set_queue.return_value = self.mock_task

    self.initialize_task_patcher = mock.patch(
        'clusterfuzz._internal.base.tasks.initialize_task',
        return_value=self.mock_task)
    self.mock_initialize_task = self.initialize_task_patcher.start()

    self.env_patcher = mock.patch(
        'clusterfuzz._internal.system.environment.get_value')
    self.mock_env_get = self.env_patcher.start()
    self.mock_env_get.return_value = None

  def tearDown(self):
    self.initialize_task_patcher.stop()
    self.env_patcher.stop()

  def test_no_message(self):
    """Test that no task is returned when the message is None."""
    self.assertIsNone(tasks.get_task_from_message(None))

  def test_success(self):
    """Test successful task creation from a message."""
    self.mock_env_get.return_value = None
    self.mock_message.attributes = {}
    self.assertEqual(
        tasks.get_task_from_message(self.mock_message), self.mock_task)

  def test_key_error(self):
    """Test that a message is acked and skipped on a KeyError."""
    self.mock_initialize_task.side_effect = KeyError
    self.assertIsNone(tasks.get_task_from_message(self.mock_message))
    self.mock_message.ack.assert_called_with()

  def test_defer(self):
    """Test that a task is deferred if its ETA is in the future."""
    self.mock_task.defer.return_value = True
    self.assertIsNone(tasks.get_task_from_message(self.mock_message))

  def test_set_queue(self):
    """Tests the set_queue method of a task."""
    mock_queue = mock.Mock()
    self.mock_env_get.return_value = None
    self.mock_message.attributes = {}
    task = tasks.get_task_from_message(self.mock_message, queue=mock_queue)
    task.set_queue.assert_called_with(mock_queue)

  @mock.patch('clusterfuzz._internal.metrics.logs.warning')
  def test_os_mismatch(self, mock_log_warning):
    """Test that a message is skipped and acked if OS versions mismatch."""
    self.mock_env_get.return_value = 'ubuntu-24-04'
    self.mock_message.attributes = {'base_os_version': 'ubuntu-22-04'}

    result = tasks.get_task_from_message(self.mock_message)

    self.assertIsNone(result)
    self.mock_message.ack.assert_called_once()
    mock_log_warning.assert_called_with(
        'Skipping task for different OS.',
        queue=None,
        message_os_version='ubuntu-22-04',
        base_os_version='ubuntu-24-04')

  def test_os_match(self):
    """Test that a message is processed if OS versions match."""
    self.mock_env_get.return_value = 'ubuntu-24-04'
    self.mock_message.attributes = {'base_os_version': 'ubuntu-24-04'}

    result = tasks.get_task_from_message(self.mock_message)

    self.assertEqual(result, self.mock_task)
    self.mock_message.ack.assert_not_called()

  def test_bot_has_os_message_does_not(self):
    """Test that a message is processed if the bot has an OS but the message does not."""
    self.mock_env_get.return_value = 'ubuntu-24-04'
    self.mock_message.attributes = {}

    result = tasks.get_task_from_message(self.mock_message)

    self.assertEqual(result, self.mock_task)
    self.mock_message.ack.assert_not_called()

  @mock.patch('clusterfuzz._internal.metrics.logs.warning')
  def test_bot_has_no_os_message_does(self, mock_log_warning):
    """Test that a message is skipped if it has an OS but the bot does not."""
    self.mock_env_get.return_value = None
    self.mock_message.attributes = {'base_os_version': 'ubuntu-24-04'}

    result = tasks.get_task_from_message(self.mock_message)

    self.assertIsNone(result)
    self.mock_message.ack.assert_called_once()
    mock_log_warning.assert_called_with(
        'Skipping task for different OS.',
        queue=None,
        message_os_version='ubuntu-24-04',
        base_os_version=None)

  def test_swarming_queues_bypass_os_mismatch_filter(self):
    """Tests shared Swarming queues never drop messages on OS mismatch."""
    self.mock_env_get.return_value = None
    self.mock_message.attributes = {'base_os_version': 'ubuntu-24-04'}

    for swarming_queue in ('preprocess-swarming', 'utask_main-swarming'):
      result = tasks.get_task_from_message(
          self.mock_message, queue=swarming_queue)
      self.assertEqual(result, self.mock_task)
      self.mock_message.ack.assert_not_called()
      self.mock_task.set_queue.assert_called_with(swarming_queue)


@test_utils.with_cloud_emulators('datastore')
class AddTaskTest(unittest.TestCase):
  """Tests for add_task."""

  def setUp(self):
    self.oss_fuzz_project = data_types.OssFuzzProject(
        name='d8', base_os_version='ubuntu-24-04')
    self.oss_fuzz_project.put()

  @mock.patch('clusterfuzz._internal.base.tasks.bulk_add_tasks')
  @mock.patch('clusterfuzz._internal.base.external_tasks.add_external_task')
  @mock.patch('clusterfuzz._internal.base.tasks.data_types.Job.query')
  def test_add_task_external_job_without_os_version(
      self, mock_job_query, mock_add_external, mock_bulk_add):
    """Test add_task with an external (OSS-Fuzz) job."""
    mock_job = mock.MagicMock()
    mock_job.is_external.return_value = True
    mock_job_query.return_value.get.return_value = mock_job

    tasks.add_task('regression', '123', 'linux_asan_d8_dbg')

    mock_bulk_add.assert_not_called()
    mock_add_external.assert_called_once()

  @mock.patch('clusterfuzz._internal.base.tasks.bulk_add_tasks')
  @mock.patch('clusterfuzz._internal.base.external_tasks.add_external_task')
  @mock.patch('clusterfuzz._internal.base.tasks.data_types.Job.query')
  def test_add_task_internal_job_without_os_version(
      self, mock_job_query, mock_add_external, mock_bulk_add):
    """Test add_task with an internal job."""
    mock_job = mock.MagicMock()
    mock_job.is_external.return_value = False
    mock_job_query.return_value.get.return_value = mock_job

    tasks.add_task('regression', '123', 'linux_asan_d8_dbg')

    mock_add_external.assert_not_called()
    mock_bulk_add.assert_called_once()

  @mock.patch('clusterfuzz._internal.base.tasks.bulk_add_tasks')
  @mock.patch('clusterfuzz._internal.base.tasks.data_types.Job.query')
  def test_add_task_internal_job_with_os_version(self, mock_job_query,
                                                 mock_bulk_add):
    """Test add_task with an internal job and an OS version."""
    mock_job = mock.MagicMock()
    mock_job.base_os_version = 'ubuntu-20-04'
    mock_job.project = 'd8'
    mock_job.is_external.return_value = False
    mock_job_query.return_value.get.return_value = mock_job

    tasks.add_task('regression', '123', 'linux_asan_d8_dbg')

    mock_bulk_add.assert_called_once()
    task_payload = mock_bulk_add.call_args[0][0][0]
    self.assertEqual(task_payload.extra_info['base_os_version'], 'ubuntu-20-04')

  @mock.patch('clusterfuzz._internal.base.external_tasks.add_external_task')
  @mock.patch('clusterfuzz._internal.base.tasks.data_types.Job.query')
  def test_add_task_external_job_with_os_version(self, mock_job_query,
                                                 mock_add_external_task):
    """Test add_task with an external (OSS-Fuzz) job and an OS version."""
    mock_job = mock.MagicMock()
    mock_job.base_os_version = None  # No version on job.
    mock_job.project = 'd8'
    mock_job.is_external.return_value = True
    mock_job_query.return_value.get.return_value = mock_job

    tasks.add_task('regression', '123', 'linux_asan_d8_dbg')

    mock_add_external_task.assert_called_once()


@mock.patch('clusterfuzz._internal.base.tasks.PubSubPuller')
@mock.patch('clusterfuzz._internal.system.environment.get_value')
class GetTaskQueueSelectionTest(unittest.TestCase):
  """Tests for dynamic queue selection in get_*_task functions."""

  def test_get_preprocess_task_without_os_version(self, mock_env_get,
                                                  mock_puller):
    """Tests that get_preprocess_task selects the default queue."""
    mock_puller.return_value.get_messages.return_value = []
    mock_env_get.return_value = None
    tasks.get_preprocess_task()
    mock_puller.assert_called_with('preprocess')

  def test_get_preprocess_task_with_os_version(self, mock_env_get, mock_puller):
    """Tests that get_preprocess_task selects the suffixed queue."""
    mock_puller.return_value.get_messages.return_value = []
    mock_env_get.return_value = 'ubuntu-24-04'
    tasks.get_preprocess_task()
    mock_puller.assert_called_with('preprocess-ubuntu-24-04')

  @mock.patch(
      'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks'
  )
  def test_get_postprocess_task_without_os_version(self, mock_is_remote,
                                                   mock_env_get, mock_puller):
    """Tests that get_postprocess_task selects the default queue."""
    mock_is_remote.return_value = True
    mock_puller.return_value.get_messages.return_value = []
    with mock.patch(
        'clusterfuzz._internal.system.environment.platform') as mock_platform:
      mock_platform.return_value.lower.return_value = 'linux'
      mock_env_get.return_value = None
      tasks.get_postprocess_task()
      mock_puller.assert_called_with('postprocess')

  @mock.patch(
      'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks'
  )
  def test_get_postprocess_task_with_os_version(self, mock_is_remote,
                                                mock_env_get, mock_puller):
    """Tests postprocess always pulls unsuffixed queue for GCS notifications."""
    mock_is_remote.return_value = True
    mock_puller.return_value.get_messages.return_value = []
    with mock.patch(
        'clusterfuzz._internal.system.environment.platform') as mock_platform:
      mock_platform.return_value.lower.return_value = 'linux'
      mock_env_get.return_value = 'ubuntu-24-04'
      tasks.get_postprocess_task()
      mock_puller.assert_called_with('postprocess')

  def test_get_utask_mains_without_os_version(self, mock_env_get, mock_puller):
    """Tests that get_utask_mains selects the default queue."""
    mock_puller.return_value.get_messages_time_limited.return_value = []
    mock_env_get.return_value = None
    tasks.get_utask_mains(pub_sub_task_queue.UTASK_MAIN_QUEUE.name)
    mock_puller.assert_called_with('utask_main')

  def test_get_utask_mains_with_os_version(self, mock_env_get, mock_puller):
    """Tests that get_utask_mains selects the suffixed queue."""
    mock_puller.return_value.get_messages_time_limited.return_value = []
    mock_env_get.return_value = 'ubuntu-24-04'
    tasks.get_utask_mains(pub_sub_task_queue.UTASK_MAIN_QUEUE.name)
    mock_puller.assert_called_with('utask_main-ubuntu-24-04')

  def test_get_utask_mains_with_custom_queue(self, mock_env_get, mock_puller):
    """Tests that get_utask_mains selects the custom queue."""
    mock_puller.return_value.get_messages_time_limited.return_value = []
    mock_env_get.return_value = None
    tasks.get_utask_mains('custom_queue')
    mock_puller.assert_called_with('custom_queue')

  def test_get_utask_mains_with_custom_queue_and_os_version(
      self, mock_env_get, mock_puller):
    """Tests that get_utask_mains selects the custom queue with OS suffix."""
    mock_puller.return_value.get_messages_time_limited.return_value = []
    mock_env_get.return_value = 'ubuntu-24-04'
    tasks.get_utask_mains('custom_queue')
    mock_puller.assert_called_with('custom_queue-ubuntu-24-04')

  def test_get_utask_mains_swarming_queue_keeps_unsuffixed_subscription(
      self, mock_env_get, mock_puller):
    """Tests that Swarming utask_main queue is not suffixed with OS version."""
    mock_puller.return_value.get_messages_time_limited.return_value = []
    mock_env_get.return_value = 'ubuntu-24-04'
    tasks.get_utask_mains(pub_sub_task_queue.SWARMING_UTASK_MAIN_QUEUE.name)
    mock_puller.assert_called_with('utask_main-swarming')

  @mock.patch(
      'clusterfuzz._internal.base.tasks.full_utask_task_model',
      return_value=False)
  @mock.patch('clusterfuzz._internal.base.tasks.get_task_from_message')
  @mock.patch(
      'clusterfuzz._internal.system.environment.platform', return_value='LINUX')
  def test_get_regular_task_linux_with_os_version_preserves_base_topic_queue(
      self, unused_mock_platform, mock_get_task_from_msg, unused_mock_utask,
      mock_env_get, mock_puller):
    """Tests that get_regular_task pulls from suffixed subscription but sets base queue."""
    fake_msg = mock.Mock()
    fake_task = mock.Mock(command='minimize')
    mock_puller.return_value.get_messages.return_value = [fake_msg]
    mock_get_task_from_msg.return_value = fake_task
    mock_env_get.side_effect = lambda key, default='': {
        'BASE_OS_VERSION': 'ubuntu-24-04',
        'QUEUE_OVERRIDE': '',}.get(key, default)

    result = tasks.get_regular_task()

    self.assertEqual(result, fake_task)
    mock_puller.assert_called_with('jobs-linux-ubuntu-24-04')
    mock_get_task_from_msg.assert_called_once_with(fake_msg, 'jobs-linux')

  @mock.patch(
      'clusterfuzz._internal.base.tasks.full_utask_task_model',
      return_value=False)
  @mock.patch('clusterfuzz._internal.base.tasks.get_task_from_message')
  @mock.patch(
      'clusterfuzz._internal.system.environment.platform', return_value='LINUX')
  def test_get_high_end_task_linux_with_os_version_preserves_base_topic_queue(
      self, unused_mock_platform, mock_get_task_from_msg, unused_mock_utask,
      mock_env_get, mock_puller):
    """Tests that get_high_end_task pulls from suffixed subscription but sets base queue."""
    fake_msg = mock.Mock()
    fake_task = mock.Mock(command='minimize', high_end=False)
    mock_puller.return_value.get_messages.return_value = [fake_msg]
    mock_get_task_from_msg.return_value = fake_task
    mock_env_get.side_effect = lambda key, default='': {
        'BASE_OS_VERSION': 'ubuntu-24-04',
        'QUEUE_OVERRIDE': '',}.get(key, default)

    result = tasks.get_high_end_task()

    self.assertEqual(result, fake_task)
    self.assertTrue(result.high_end)
    mock_puller.assert_called_with('high-end-jobs-linux-ubuntu-24-04')
    mock_get_task_from_msg.assert_called_once_with(fake_msg,
                                                   'high-end-jobs-linux')

  def test_get_regular_task_swarming_override_keeps_unsuffixed_subscription(
      self, mock_env_get, mock_puller):
    """Tests that preprocess-swarming override is not suffixed with OS version."""
    mock_puller.return_value.get_messages.return_value = []
    mock_env_get.return_value = 'ubuntu-24-04'
    tasks.get_regular_task(queue='preprocess-swarming')
    mock_puller.assert_called_with('preprocess-swarming')

  def test_get_utask_mains_swarming_queue_processes_cross_os_messages(
      self, mock_env_get, mock_puller):
    """Tests get_utask_mains preserves Swarming messages across OS versions."""
    for worker_os in (None, 'ubuntu-24-04'):
      msg = mock.MagicMock()
      msg.attributes = {
          'command': 'fuzz',
          'argument': 'https://example.com/in',
          'job': 'android_asan_chrome',
          'eta': '1',
          'base_os_version': 'ubuntu-24-04',
      }
      mock_puller.return_value.get_messages_time_limited.return_value = [msg]
      mock_env_get.return_value = worker_os

      pulled = tasks.get_utask_mains(
          pub_sub_task_queue.SWARMING_UTASK_MAIN_QUEUE.name)

      self.assertEqual(1, len(pulled))
      self.assertEqual('utask_main-swarming', pulled[0].queue)
      msg.ack.assert_not_called()

  @mock.patch(
      'clusterfuzz._internal.system.environment.is_tworker', return_value=True)
  def test_get_regular_task_swarming_override_processes_cross_os_messages(
      self, unused_is_tworker, mock_env_get, mock_puller):
    """Tests preprocess-swarming preserves OS-tagged messages on legacy tworkers."""
    msg = mock.MagicMock()
    msg.attributes = {
        'command': 'fuzz',
        'argument': 'libFuzzer',
        'job': 'android_asan_chrome',
        'eta': '1',
        'base_os_version': 'ubuntu-24-04',
    }
    mock_puller.return_value.get_messages.return_value = [msg]
    mock_env_get.return_value = None

    with mock.patch.object(tasks.PubSubTask, 'defer', return_value=False):
      pulled = tasks.get_regular_task(queue='preprocess-swarming')

    self.assertIsNotNone(pulled)
    self.assertEqual('preprocess-swarming', pulled.queue)
    msg.ack.assert_not_called()


@mock.patch('clusterfuzz._internal.system.environment.get_value')
@mock.patch('clusterfuzz._internal.system.environment.platform')
class QueueNameGenerationTest(unittest.TestCase):
  """Tests for queue and subscription name generation functions."""

  def test_default_queue_suffix_linux_no_os_version(self, mock_platform,
                                                    mock_env_get):
    """Tests base topic queue suffix for Linux without an OS version."""
    mock_env_get.side_effect = lambda key, default='': {
        'QUEUE_OVERRIDE': ''
    }.get(key, default)
    mock_platform.return_value = 'LINUX'
    self.assertEqual(tasks.default_queue_suffix(), '-linux')

  @mock.patch(
      'clusterfuzz._internal.base.tasks.full_utask_task_model',
      return_value=False)
  def test_default_queue_and_suffix_linux_with_os_version_return_base_topic(
      self, unused_mock_utask, mock_platform, mock_env_get):
    """Tests topic queue helpers omit OS version suffix on Linux workers."""
    mock_env_get.side_effect = lambda key, default='': {
        'BASE_OS_VERSION': 'ubuntu-24-04',
        'QUEUE_OVERRIDE': '',
        'THREAD_MULTIPLIER': 1,}.get(key, default)
    mock_platform.return_value = 'LINUX'
    self.assertEqual(tasks.default_queue_suffix(), '-linux')
    self.assertEqual(tasks.regular_queue(), 'jobs-linux')
    self.assertEqual(tasks.high_end_queue(), 'high-end-jobs-linux')
    self.assertEqual(tasks.default_queue(), 'jobs-linux')

  def test_subscription_name_for_queue_with_os_version(self, mock_platform,
                                                       mock_env_get):
    """Tests OS-versioned subscription resolution across queue types."""
    del mock_platform
    mock_env_get.side_effect = lambda key, default='': {
        'BASE_OS_VERSION': 'ubuntu-24-04',}.get(key, default)
    for versioned_queue in ('jobs-linux', 'high-end-jobs-linux', 'preprocess',
                            'utask_main'):
      self.assertEqual(
          tasks.subscription_name_for_queue(versioned_queue),
          f'{versioned_queue}-ubuntu-24-04')

    self.assertEqual(
        tasks.subscription_name_for_queue('jobs-linux-ubuntu-24-04'),
        'jobs-linux-ubuntu-24-04')

    for unsuffixed_queue in ('postprocess', 'preprocess-swarming',
                             'utask_main-swarming', 'jobs-linux-untrusted',
                             'high-end-jobs-linux-untrusted',
                             'jobs-linux-with-gpu', 'jobs-linux-x86',
                             'jobs-curl-linux', 'ml-jobs-linux', 'jobs-fuchsia',
                             'jobs-android-x86', 'jobs-android', 'jobs-mac'):
      self.assertEqual(
          tasks.subscription_name_for_queue(unsuffixed_queue), unsuffixed_queue)

  def test_subscription_name_for_queue_respects_declarative_queues_yaml(
      self, mock_platform, mock_env_get):
    """Tests queues.yaml supported_os_versions gates suffixed subscriptions."""
    del mock_platform
    with tempfile.TemporaryDirectory() as dev_cfg, \
        tempfile.TemporaryDirectory() as prod_cfg:
      os.makedirs(os.path.join(dev_cfg, 'pubsub'))
      with open(
          os.path.join(dev_cfg, 'pubsub', 'queues.yaml'), 'w',
          encoding='utf-8') as f:
        f.write('resources:\n'
                '  - name: jobs-linux\n'
                '    type: queue.jinja\n'
                '  - name: preprocess\n'
                '    type: queue.jinja\n')

      os.makedirs(os.path.join(prod_cfg, 'pubsub'))
      with open(
          os.path.join(prod_cfg, 'pubsub', 'queues.yaml'),
          'w',
          encoding='utf-8') as f:
        f.write('resources:\n'
                '  - name: jobs-linux\n'
                '    type: queue.jinja\n'
                '    properties:\n'
                '      supported_os_versions: [ubuntu-24-04]\n'
                '  - name: high-end-jobs-linux\n'
                '    type: queue.jinja\n'
                '  - name: jobs-fuchsia\n'
                '    type: queue.jinja\n'
                '    properties:\n'
                '      supported_os_versions: [ubuntu-24-04]\n')

      mock_env_get.side_effect = lambda key, default='': {
          'BASE_OS_VERSION': 'ubuntu-24-04',
          'CONFIG_DIR_OVERRIDE': dev_cfg,}.get(key, default)
      self.assertEqual(
          tasks.subscription_name_for_queue('jobs-linux'), 'jobs-linux')
      self.assertEqual(
          tasks.subscription_name_for_queue('preprocess'), 'preprocess')

      mock_env_get.side_effect = lambda key, default='': {
          'BASE_OS_VERSION': 'ubuntu-24-04',
          'CONFIG_DIR_OVERRIDE': prod_cfg,}.get(key, default)
      self.assertEqual(
          tasks.subscription_name_for_queue('jobs-linux'),
          'jobs-linux-ubuntu-24-04')
      self.assertEqual(
          tasks.subscription_name_for_queue('high-end-jobs-linux'),
          'high-end-jobs-linux')
      self.assertEqual(
          tasks.subscription_name_for_queue('jobs-fuchsia'), 'jobs-fuchsia')

  def test_strip_os_version_suffix_handles_cross_os_and_missing_env(
      self, mock_platform, mock_env_get):
    """Tests _strip_os_version_suffix strips OS suffixes without worker env."""
    del mock_platform
    mock_env_get.return_value = None
    self.assertEqual(
        tasks._strip_os_version_suffix('jobs-linux-ubuntu-24-04'),  # pylint: disable=protected-access
        'jobs-linux')
    self.assertEqual(
        tasks._strip_os_version_suffix('utask_main-swarming'),  # pylint: disable=protected-access
        'utask_main-swarming')

    mock_env_get.return_value = 'ubuntu-24-04'
    self.assertEqual(
        tasks._strip_os_version_suffix('jobs-linux-ubuntu-20-04'),  # pylint: disable=protected-access
        'jobs-linux')

  def test_subscription_name_for_queue_when_root_and_config_dirs_are_unset(
      self, mock_platform, mock_env_get):
    """Tests subscription_name_for_queue handles None ROOT_DIR and CONFIG_DIR."""
    del mock_platform
    mock_env_get.side_effect = lambda key, default=None: {
        'BASE_OS_VERSION': 'ubuntu-24-04',}.get(key, default)
    self.assertEqual(
        tasks.subscription_name_for_queue('jobs-linux'),
        'jobs-linux-ubuntu-24-04')

  def test_default_queue_suffix_mac_no_os_version(self, mock_platform,
                                                  mock_env_get):
    """Tests queue suffix for Mac without an OS version."""
    mock_env_get.side_effect = lambda key, default='': {
        'BASE_OS_VERSION': '',
        'QUEUE_OVERRIDE': ''
    }.get(key, default)
    mock_platform.return_value = 'MAC'
    self.assertEqual(tasks.default_queue_suffix(), '-mac')

  def test_default_queue_suffix_mac_with_os_version(self, mock_platform,
                                                    mock_env_get):
    """Tests queue suffix for Mac with an OS version (should be ignored)."""
    mock_env_get.side_effect = lambda key, default='': {
        'BASE_OS_VERSION': 'ubuntu-24-04',
        'QUEUE_OVERRIDE': ''
    }.get(key, default)
    mock_platform.return_value = 'MAC'
    self.assertEqual(tasks.default_queue_suffix(), '-mac')


class TworkerGetTaskTest(unittest.TestCase):
  """Tests for tworker_get_task."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.is_tworker',
        'clusterfuzz._internal.base.tasks.get_regular_task',
        'clusterfuzz._internal.base.tasks.get_postprocess_task',
        'clusterfuzz._internal.base.tasks.get_preprocess_task',
        'random.random',
    ])
    self.mock.is_tworker.return_value = True

  def test_not_tworker(self):
    """Test that assertion fails if not a tworker."""
    self.mock.is_tworker.return_value = False
    with self.assertRaises(AssertionError):
      tasks.tworker_get_task()

  def test_fallback_to_random_choice(self):
    """Test that tworker_get_task falls back to random choice when override_queue is None or empty."""
    self.mock.random.return_value = 0.4
    self.mock.get_postprocess_task.return_value = 'task2'

    # Test with None
    self.assertEqual(tasks.tworker_get_task(override_queue=None), 'task2')
    self.mock.get_postprocess_task.assert_called_once()
    self.mock.get_preprocess_task.assert_not_called()

    self.mock.get_postprocess_task.reset_mock()

    # Test with empty string
    self.assertEqual(tasks.tworker_get_task(override_queue=''), 'task2')
    self.mock.get_postprocess_task.assert_called_once()
    self.mock.get_preprocess_task.assert_not_called()


class GetTaskFuzzingFeatureFlagTest(unittest.TestCase):
  """Tests for ENABLE_FUZZ_FOR_BOTS feature flag in get_task."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.get_command_override',
        'clusterfuzz._internal.base.tasks.get_postprocess_task',
        'clusterfuzz._internal.base.tasks.get_high_end_task',
        'clusterfuzz._internal.base.tasks.get_regular_task',
        'clusterfuzz._internal.base.tasks.get_fuzz_task',
        'clusterfuzz._internal.system.environment.is_android',
        'clusterfuzz._internal.system.environment.platform',
    ])
    self.mock.get_command_override.return_value = None
    self.mock.get_postprocess_task.return_value = None
    self.mock.get_high_end_task.return_value = None
    self.mock.get_regular_task.return_value = None
    self.mock.is_android.return_value = False
    self.mock.platform.return_value = 'LINUX'
    self.mock_fuzz_task = mock.Mock()
    self.mock.get_fuzz_task.return_value = self.mock_fuzz_task

  def test_flag_none(self):
    """Test that fuzz task is not returned when feature flag is not set."""
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = None
      self.assertIsNone(tasks.get_task())
      self.mock.get_fuzz_task.assert_not_called()

  def test_flag_disabled(self):
    """Test that fuzz task is not returned when feature flag is disabled."""
    mock_flag_obj = mock.MagicMock(enabled=False, string_value='linux')
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = mock_flag_obj
      self.assertIsNone(tasks.get_task())
      self.mock.get_fuzz_task.assert_not_called()

  def test_platform_in_string_value(self):
    """Test that fuzz task is returned when platform matches string value."""
    mock_flag_obj = mock.MagicMock(enabled=True, string_value='linux,windows')
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = mock_flag_obj
      self.assertEqual(tasks.get_task(), self.mock_fuzz_task)
      self.mock.get_fuzz_task.assert_called_once()

  def test_platform_not_in_string_value(self):
    """Test fuzz task is not returned when platform not in string value."""
    mock_flag_obj = mock.MagicMock(enabled=True, string_value='windows,mac')
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = mock_flag_obj
      self.assertIsNone(tasks.get_task())
      self.mock.get_fuzz_task.assert_not_called()

  def test_empty_string_value(self):
    """Test that fuzz task is not returned when string value is empty."""
    mock_flag_obj = mock.MagicMock(enabled=True, string_value='')
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = mock_flag_obj
      self.assertIsNone(tasks.get_task())
      self.mock.get_fuzz_task.assert_not_called()

  def test_base_platform_in_string_value(self):
    """Test fuzz task is returned when subqueue base platform matches."""
    self.mock.platform.return_value = 'ANDROID:PIXEL6'
    mock_flag_obj = mock.MagicMock(enabled=True, string_value='linux,android')
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = mock_flag_obj
      self.assertEqual(tasks.get_task(), self.mock_fuzz_task)
      self.mock.get_fuzz_task.assert_called_once()

  def test_subqueue_platform_in_string_value(self):
    """Test fuzz task is returned when full subqueue platform matches."""
    self.mock.platform.return_value = 'ANDROID:PIXEL6'
    mock_flag_obj = mock.MagicMock(
        enabled=True, string_value='linux,android:pixel6')
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = mock_flag_obj
      self.assertEqual(tasks.get_task(), self.mock_fuzz_task)
      self.mock.get_fuzz_task.assert_called_once()

  def test_subqueue_and_base_platform_not_in_string_value(self):
    """Test fuzz task is not returned when neither platform nor base matches."""
    self.mock.platform.return_value = 'ANDROID_MTE:PIXEL8'
    mock_flag_obj = mock.MagicMock(enabled=True, string_value='linux,android')
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = mock_flag_obj
      self.assertIsNone(tasks.get_task())
      self.mock.get_fuzz_task.assert_not_called()


class PubSubLeaserThreadTest(unittest.TestCase):
  """Tests for _PubSubLeaserThread error handling and shutdown."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.error',
        'clusterfuzz._internal.metrics.logs.info',
    ])

  def test_stops_promptly_when_modify_ack_deadline_raises(self):
    """Test leaser thread exits on done_event instead of spinning forever."""
    import threading

    done_event = threading.Event()
    attempted = threading.Event()

    def fail_deadline(unused_seconds):
      del unused_seconds
      attempted.set()
      raise OSError(24, 'Too many open files')

    message = mock.Mock()
    message.modify_ack_deadline.side_effect = fail_deadline

    leaser = tasks._PubSubLeaserThread(  # pylint: disable=protected-access
        message,
        done_event,
        max_lease_seconds=600)
    leaser.FAILURE_WAIT_SECONDS = 10
    leaser.start()

    self.assertTrue(attempted.wait(timeout=2.0))
    done_event.set()
    leaser.join(timeout=2.0)

    self.assertFalse(leaser.is_alive())
    self.mock.error.assert_called_with('Leaser thread failed.')

  def test_retries_after_transient_error_until_done(self):
    """Test leaser thread backs off and succeeds on subsequent renewal."""
    import threading

    done_event = threading.Event()
    renewed = threading.Event()
    calls = []

    def flaky_deadline(seconds):
      calls.append(seconds)
      if len(calls) == 1:
        raise OSError(24, 'Too many open files')
      renewed.set()

    message = mock.Mock()
    message.modify_ack_deadline.side_effect = flaky_deadline

    leaser = tasks._PubSubLeaserThread(  # pylint: disable=protected-access
        message,
        done_event,
        max_lease_seconds=600)
    leaser.FAILURE_WAIT_SECONDS = 0.05
    leaser.start()

    self.assertTrue(renewed.wait(timeout=2.0))
    done_event.set()
    leaser.join(timeout=2.0)

    self.assertFalse(leaser.is_alive())
    self.assertGreaterEqual(len(calls), 2)


@test_utils.with_cloud_emulators('datastore')
class SwarmingNonFuzzTaskRoutingTest(unittest.TestCase):
  """Tests for routing non-fuzz tasks of Swarming jobs to platform queues."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.bulk_add_tasks',
    ])
    data_types.Job(
        name='android_emulator_swarming',
        platform='ANDROID_EMULATOR',
        environment_string='IS_SWARMING_JOB = True\n').put()
    data_types.Job(
        name='android_emulator_non_swarming',
        platform='ANDROID_EMULATOR',
        environment_string='').put()
    self.flag = data_types.FeatureFlag(
        id='swarming_remote_execution', enabled=True)
    self.flag.put()

  def _queue_used(self):
    return self.mock.bulk_add_tasks.call_args[1]['queue']

  def test_swarming_job_routes_to_platform_queue(self):
    """Tests that a Swarming job task with no explicit queue is routed to its
    platform queue when SWARMING_REMOTE_EXECUTION is enabled."""
    tasks.add_task('minimize', '123', 'android_emulator_swarming')
    self.assertEqual(self._queue_used(), 'jobs-android-emulator')

  def test_swarming_disabled_keeps_default_queue(self):
    """Tests that Swarming jobs keep the default queue when
    SWARMING_REMOTE_EXECUTION is disabled."""
    self.flag.enabled = False
    self.flag.put()
    tasks.add_task('minimize', '123', 'android_emulator_swarming')
    self.assertIsNone(self._queue_used())

  def test_non_swarming_job_keeps_default_queue(self):
    """Tests that non-Swarming jobs keep the default queue even when
    SWARMING_REMOTE_EXECUTION is enabled."""
    tasks.add_task('minimize', '123', 'android_emulator_non_swarming')
    self.assertIsNone(self._queue_used())

  def test_explicit_queue_is_not_overridden(self):
    """Tests that an explicitly provided queue is preserved for Swarming
    jobs."""
    tasks.add_task(
        'minimize', '123', 'android_emulator_swarming', queue='custom-queue')
    self.assertEqual(self._queue_used(), 'custom-queue')

  def test_mac_arm64_display_name_and_platform_queue_routing(self):
    """Tests that MAC_ARM64 is registered in TASK_QUEUE_DISPLAY_NAMES and
    routes non-fuzz Swarming tasks to jobs-mac-arm64."""
    self.assertEqual(
        tasks.TASK_QUEUE_DISPLAY_NAMES.get('MAC_ARM64'), 'Mac (ARM64)')
    self.assertEqual(tasks.queue_for_platform('MAC_ARM64'), 'jobs-mac-arm64')

    data_types.Job(
        name='mac_arm64_swarming',
        platform='MAC_ARM64',
        environment_string='IS_SWARMING_JOB = True\n').put()
    tasks.add_task('minimize', '456', 'mac_arm64_swarming')
    self.assertEqual(self._queue_used(), 'jobs-mac-arm64')


@test_utils.with_cloud_emulators('datastore')
class RedoTestcaseProgressionRetryResetTest(unittest.TestCase):
  """Tests redo_testcase resets progression confirmation retry metadata."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
    ])
    data_types.Job(name='linux_asan_app', platform='LINUX').put()

  def test_redo_progression_clears_retry_markers(self):
    """Tests redoing progression clears prior retry markers and reopens testcase."""
    testcase = test_utils.create_generic_testcase()
    testcase.job_type = 'linux_asan_app'
    testcase.open = False
    testcase.fixed = 'NA'
    testcase.set_metadata('progression_retry', True, update_testcase=False)
    testcase.set_metadata(
        'progression_bad_min_build_retry', True, update_testcase=False)
    testcase.set_metadata('potentially_flaky', True, update_testcase=False)
    testcase.put()

    tasks.redo_testcase(testcase, ['progression'], 'sheriff@example.com')

    updated = testcase.key.get()
    self.assertTrue(updated.open)
    self.assertEqual('', updated.fixed)
    self.assertTrue(updated.get_metadata('progression_pending'))
    self.assertIsNone(updated.get_metadata('progression_retry'))
    self.assertIsNone(updated.get_metadata('progression_bad_min_build_retry'))
    self.assertIsNone(updated.get_metadata('potentially_flaky'))

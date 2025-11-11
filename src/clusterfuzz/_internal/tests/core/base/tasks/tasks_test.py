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
import unittest
from unittest import mock

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.datastore import data_types
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

  def test_bot_has_no_os_message_does(self):
    """Test that a message is processed if the message has an OS but the bot does not."""
    self.mock_env_get.return_value = None
    self.mock_message.attributes = {'base_os_version': 'ubuntu-24-04'}

    result = tasks.get_task_from_message(self.mock_message)

    self.assertEqual(result, self.mock_task)
    self.mock_message.ack.assert_not_called()


@test_utils.with_cloud_emulators('datastore')
@mock.patch('clusterfuzz._internal.base.tasks.bulk_add_tasks')
@mock.patch('clusterfuzz._internal.base.external_tasks.add_external_task')
class AddTaskTest(unittest.TestCase):
  """Tests for add_task."""

  def setUp(self):
    self.oss_fuzz_project = data_types.OssFuzzProject(
        name='d8', base_os_version='ubuntu-24-04')
    self.oss_fuzz_project.put()

  @mock.patch('clusterfuzz._internal.base.tasks.data_types.Job.query')
  def test_add_task_internal_job_with_os_version(
      self, mock_job_query, mock_add_external, mock_bulk_add):
    """Test add_task with an internal job and an OS version."""
    mock_job = mock.MagicMock()
    mock_job.base_os_version = 'ubuntu-20-04'
    mock_job.project = 'd8'
    mock_job.is_external.return_value = False
    mock_job_query.return_value.get.return_value = mock_job

    tasks.add_task('regression', '123', 'linux_asan_d8_dbg')

    mock_add_external.assert_not_called()
    mock_bulk_add.assert_called_once()
    task_payload = mock_bulk_add.call_args[0][0][0]
    self.assertEqual(task_payload.extra_info['base_os_version'], 'ubuntu-20-04')

  @mock.patch('clusterfuzz._internal.base.tasks.data_types.Job.query')
  def test_add_task_external_job_with_os_version(
      self, mock_job_query, mock_add_external, mock_bulk_add):
    """Test add_task with an external (OSS-Fuzz) job and an OS version."""
    mock_job = mock.MagicMock()
    mock_job.base_os_version = 'ubuntu-20-04'
    mock_job.project = 'd8'
    mock_job.is_external.return_value = True
    mock_job_query.return_value.get.return_value = mock_job

    tasks.add_task('regression', '123', 'linux_asan_d8_dbg')

    mock_bulk_add.assert_not_called()
    mock_add_external.assert_called_once()


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
    """Tests that get_postprocess_task selects the suffixed queue."""
    mock_is_remote.return_value = True
    mock_puller.return_value.get_messages.return_value = []
    with mock.patch(
        'clusterfuzz._internal.system.environment.platform') as mock_platform:
      mock_platform.return_value.lower.return_value = 'linux'
      mock_env_get.return_value = 'ubuntu-24-04'
      tasks.get_postprocess_task()
      mock_puller.assert_called_with('postprocess-ubuntu-24-04')

  def test_get_utask_mains_without_os_version(self, mock_env_get, mock_puller):
    """Tests that get_utask_mains selects the default queue."""
    mock_puller.return_value.get_messages_time_limited.return_value = []
    mock_env_get.return_value = None
    tasks.get_utask_mains()
    mock_puller.assert_called_with('utask_main')

  def test_get_utask_mains_with_os_version(self, mock_env_get, mock_puller):
    """Tests that get_utask_mains selects the suffixed queue."""
    mock_puller.return_value.get_messages_time_limited.return_value = []
    mock_env_get.return_value = 'ubuntu-24-04'
    tasks.get_utask_mains()
    mock_puller.assert_called_with('utask_main-ubuntu-24-04')


@mock.patch('clusterfuzz._internal.system.environment.get_value')
@mock.patch('clusterfuzz._internal.system.environment.platform')
class QueueNameGenerationTest(unittest.TestCase):
  """Tests for queue name generation functions."""

  def test_default_queue_suffix_linux_no_os_version(self, mock_platform,
                                                    mock_env_get):
    """Tests queue suffix for Linux without an OS version."""
    mock_env_get.side_effect = lambda key, default='': {'QUEUE_OVERRIDE': ''}.get(key, default)
    mock_platform.return_value = 'LINUX'
    self.assertEqual(tasks.default_queue_suffix(), '-linux')

  def test_default_queue_suffix_linux_with_os_version(self, mock_platform,
                                                      mock_env_get):
    """Tests queue suffix for Linux with an OS version."""
    mock_env_get.side_effect = lambda key, default='': {
        'BASE_OS_VERSION': 'ubuntu-24-04',
        'QUEUE_OVERRIDE': ''
    }.get(key, default)
    mock_platform.return_value = 'LINUX'
    self.assertEqual(tasks.default_queue_suffix(), '-linux-ubuntu-24-04')

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

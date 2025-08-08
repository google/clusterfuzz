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

  def test_no_message(self):
    self.assertEqual(tasks.get_task_from_message(None), None)

  def test_success(self):
    mock_task = mock.Mock(defer=mock.Mock(return_value=False))
    mock_task.set_queue.return_value = mock_task
    with mock.patch(
        'clusterfuzz._internal.base.tasks.initialize_task',
        return_value=mock_task):
      self.assertEqual(tasks.get_task_from_message(mock.Mock()), mock_task)

  def test_key_error(self):
    mock_message = mock.Mock()
    with mock.patch(
        'clusterfuzz._internal.base.tasks.initialize_task',
        side_effect=KeyError):
      self.assertEqual(tasks.get_task_from_message(mock_message), None)
      mock_message.ack.assert_called_with()

  def test_defer(self):
    mock_task = mock.Mock(defer=mock.Mock(return_value=True))
    with mock.patch(
        'clusterfuzz._internal.base.tasks.initialize_task',
        return_value=mock_task):
      self.assertEqual(tasks.get_task_from_message(mock.Mock()), None)

  def test_set_queue(self):
    """Tests the set_queue method of a task."""
    mock_queue = mock.Mock()
    mock_task = mock.Mock()

    mock_task.configure_mock(
        queue=mock_queue,
        set_queue=mock.Mock(return_value=mock_task),
        defer=mock.Mock(return_value=False))

    with mock.patch(
        'clusterfuzz._internal.base.tasks.initialize_task',
        return_value=mock_task):
      task = tasks.get_task_from_message(mock.Mock())

      self.assertEqual(task.queue, mock_queue)


class AddUTaskMainTest(unittest.TestCase):
  """Tests for add_utask_main."""

  def setUp(self):
    self.mock_add_task = mock.patch(
        'clusterfuzz._internal.base.tasks.add_task').start()
    self.mock_environment = mock.patch(
        'clusterfuzz._internal.system.environment.get_value').start()
    self.mock_queue_for_platform = mock.patch(
        'clusterfuzz._internal.base.tasks.queue_for_platform',
        return_value='jobs-windows').start()

  def tearDown(self):
    self.mock_add_task.stop()
    self.mock_environment.stop()
    self.mock_queue_for_platform.stop()

  def test_add_utask_main_linux(self):
    """Test that linux jobs are added to the utask_main queue."""
    self.mock_environment.side_effect = \
        lambda key, default=None: {
            'PLATFORM': 'LINUX',
            'TASK_PAYLOAD': 'initial_command'
        }.get(key, default)
    tasks.add_utask_main('command', 'input_url', 'job_type')
    self.mock_add_task.assert_called_with(
        'command',
        'input_url',
        'job_type',
        queue=tasks.UTASK_MAIN_QUEUE,
        wait_time=None,
        extra_info={'initial_command': 'initial_command'})

  def test_add_utask_main_non_linux(self):
    """Test that non-linux jobs are added to their specific queue."""
    self.mock_environment.side_effect = \
        lambda key, default=None: {
            'PLATFORM': 'WINDOWS',
            'TASK_PAYLOAD': 'initial_command',
            'THREAD_MULTIPLIER': 1
        }.get(key, default)
    tasks.add_utask_main('command', 'input_url', 'job_type')
    self.mock_add_task.assert_called_with(
        'command',
        'input_url',
        'job_type',
        queue='jobs-windows',
        wait_time=None,
        extra_info={'initial_command': 'initial_command'})
    self.mock_queue_for_platform.assert_called_with(
        'WINDOWS', is_high_end=False, force_true_queue=True)

  def test_add_utask_main_non_linux_high_end(self):
    """Test that non-linux high-end jobs are added to their specific queue."""
    self.mock_environment.side_effect = \
        lambda key, default=None: {
            'PLATFORM': 'WINDOWS',
            'TASK_PAYLOAD': 'initial_command',
            'THREAD_MULTIPLIER': 2
        }.get(key, default)
    self.mock_queue_for_platform.return_value = 'high-end-jobs-windows'
    tasks.add_utask_main('command', 'input_url', 'job_type')
    self.mock_add_task.assert_called_with(
        'command',
        'input_url',
        'job_type',
        queue='high-end-jobs-windows',
        wait_time=None,
        extra_info={'initial_command': 'initial_command'})
    self.mock_queue_for_platform.assert_called_with(
        'WINDOWS', is_high_end=True, force_true_queue=True)


class QueueForJobTest(unittest.TestCase):
  """Tests for queue_for_job."""

  def setUp(self):
    self.mock_job = mock.MagicMock()
    self.mock_job_query = mock.patch(
        'clusterfuzz._internal.datastore.data_types.Job.query',
        return_value=mock.MagicMock(get=lambda: self.mock_job))
    self.mock_full_utask_task_model = mock.patch(
        'clusterfuzz._internal.base.tasks.full_utask_task_model').start()
    self.mock_job_query.start()

  def tearDown(self):
    self.mock_job_query.stop()
    self.mock_full_utask_task_model.stop()

  def test_queue_for_job_force_true_queue(self):
    """Test that force_true_queue gets the true queue."""
    self.mock_job.platform = 'WINDOWS'
    self.mock_full_utask_task_model.return_value = True
    queue = tasks.queue_for_job('job_type', force_true_queue=True)
    self.assertEqual(queue, 'jobs-windows')

  def test_queue_for_job_no_force(self):
    """Test that no force gets the preprocess queue."""
    self.mock_job.platform = 'WINDOWS'
    self.mock_full_utask_task_model.return_value = True
    queue = tasks.queue_for_job('job_type')
    self.assertEqual(queue, tasks.PREPROCESS_QUEUE)

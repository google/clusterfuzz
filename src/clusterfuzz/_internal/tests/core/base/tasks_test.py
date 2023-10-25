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
    task = tasks.initialize_task([self.message])
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
    task = tasks.initialize_task([self.message])
    self.assertFalse(isinstance(task, tasks.PubSubTask))
    self.assertEqual(task.command, 'postprocess')
    self.assertEqual(task.argument, 'gs://uworker-output/worker.output')
    self.assertEqual(task.job, 'none')


class GetUtaskFiltersTest(unittest.TestCase):
  """Tests for get_utask_filters."""

  def test_chromium_linux(self):
    """Tests that the get_utask_filters only has linux bots in chrome
    clusterfuzz executing preprocess and postprocess. This test is temporary and
    will be removed when the migration is complete."""
    # TOOD(metzman): Delete this test when it is no longer needed.
    filters = tasks.get_utask_filters(is_chromium=True, is_linux=True)
    self.assertEqual(filters, 'attribute.name = postprocess')

  def test_chromium_nonlinux(self):
    """Tests that the get_utask_filters only has linux bots in chrome
    clusterfuzz executing preprocess and postprocess. This test is temporary and
    will be removed when the migration is complete."""
    # TOOD(metzman): Delete this test when it is no longer needed.
    filters = tasks.get_utask_filters(is_chromium=True, is_linux=False)
    self.assertEqual(filters, '-attribute.name = postprocess')

  def test_external_linux(self):
    """Tests that the get_utask_filters only has linux bots in chrome
    clusterfuzz executing preprocess and postprocess."""
    filters = tasks.get_utask_filters(is_chromium=False, is_linux=True)
    self.assertIsNone(filters)

  def test_external_nonlinux(self):
    """Tests that the get_utask_filters only has linux bots in chrome
    clusterfuzz executing preprocess and postprocess."""
    filters = tasks.get_utask_filters(is_chromium=False, is_linux=False)
    self.assertIsNone(filters)


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

# Copyright 2025 Google LLC
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
"""Tests for the Kubernetes batch client."""
import unittest
from unittest import mock

import yaml

from clusterfuzz._internal.batch import kubernetes
from clusterfuzz._internal.tests.test_libs import helpers


class KubernetesJobClientTest(unittest.TestCase):
  """Tests for KubernetesJobClient."""

  def setUp(self):
    helpers.patch(self, [
        'kubernetes.config.load_kube_config',
        'kubernetes.client.CoreV1Api',
        'kubernetes.client.BatchV1Api',
    ])
    self.k8s_client = kubernetes.KubernetesJobClient(
        'test-job', 'test-image', 'test-spec.yaml')

  def test_create_job(self):
    """Tests that create_job works as expected."""
    job_spec = {
        'metadata': {
            'name': 'test-job'
        },
        'spec': {
            'template': {
                'spec': {
                    'containers': [{
                        'name': 'test-container',
                        'image': 'test-image',
                        'env': []
                    }]
                }
            }
        }
    }
    input_urls = ['url1', 'url2']

    with mock.patch('builtins.open',
                    mock.mock_open(read_data=yaml.dump(job_spec))):
      with mock.patch.object(self.k8s_client, '_delete_job') as mock_delete:
        self.k8s_client.create_job(None, input_urls)
        mock_delete.assert_called_once_with('test-job')
        self.k8s_client._batch_api.create_namespaced_job.assert_called_once()
        called_args, called_kwargs = self.k8s_client._batch_api.create_namespaced_job.call_args
        self.assertEqual(called_args, ())
        job_body = called_kwargs['body']
        self.assertEqual(job_body['metadata']['name'], 'test-job')
        self.assertEqual(
            job_body['spec']['template']['spec']['containers'][0]['image'],
            'test-image')
        self.assertIn({
            'name': 'UWORKER_INPUT_DOWNLOAD_URL_0',
            'value': 'url1'
        }, job_body['spec']['template']['spec']['containers'][0]['env'])
        self.assertIn({
            'name': 'UWORKER_INPUT_DOWNLOAD_URL_1',
            'value': 'url2'
        }, job_body['spec']['template']['spec']['containers'][0]['env'])

  def test_delete_job(self):
    """Tests that _delete_job works as expected."""
    self.k8s_client._delete_job('test-job')
    self.k8s_client._batch_api.delete_namespaced_job.assert_called_once_with(
        name='test-job',
        namespace='default',
        body=mock.ANY)

  def test_delete_job_not_found(self):
    """Tests that _delete_job handles not found errors."""
    self.k8s_client._batch_api.delete_namespaced_job.side_effect = (
        kubernetes.k8s_client.ApiException(status=404))
    self.k8s_client._delete_job('test-job')
    self.k8s_client._batch_api.read_namespaced_job.assert_not_called()

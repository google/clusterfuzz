# pylint: disable=protected-access
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
import uuid

from clusterfuzz._internal.k8s import service as kubernetes_service
from clusterfuzz._internal.tests.test_libs import helpers


class MockRemoteTask():
  """Mock RemoteTask for testing."""
  job_type = 'test-job'
  docker_image = 'test-image'
  command = 'fuzz'


class KubernetesJobClientTest(unittest.TestCase):
  """Tests for KubernetesJobClient."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.k8s.service.KubernetesService._load_gke_credentials',
        'kubernetes.config.load_kube_config',
        'kubernetes.client.CoreV1Api',
        'kubernetes.client.BatchV1Api',
        'uuid.uuid4',
    ])
    self.mock.uuid4.return_value = uuid.UUID(
        'a0b1c2d3-e4f5-6789-0123-456789abcdef')
    self.job_spec = {
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
    self.k8s_client = kubernetes_service.KubernetesService()

  def test_create_job(self):
    """Tests that create_job works as expected."""
    input_url = 'url1'
    remote_task = MockRemoteTask()

    config = kubernetes_service.KubernetesJobConfig(
        job_type=remote_task.job_type,
        docker_image=remote_task.docker_image,
        command=remote_task.command,
        disk_size_gb=10,
        service_account_email='test-email',
        clusterfuzz_release='prod',
        is_kata=True)

    self.k8s_client.create_job(config, input_url)
    self.k8s_client._batch_api.create_namespaced_job.assert_called_once()
    called_args, called_kwargs = self.k8s_client._batch_api.create_namespaced_job.call_args
    self.assertEqual(called_args, ())
    job_body = called_kwargs['body']
    self.assertEqual(job_body['metadata']['name'],
                     'cf-job-a0b1c2d3-e4f5-6789-0123-456789abcdef')
    self.assertEqual(job_body['metadata']['labels']['task_name'], 'fuzz')
    self.assertEqual(job_body['metadata']['labels']['job_name'], 'test-job')
    self.assertEqual(
        job_body['spec']['template']['spec']['containers'][0]['image'],
        'test-image')
    self.assertIn({
        'name': 'UWORKER_INPUT_DOWNLOAD_URL',
        'value': 'url1'
    }, job_body['spec']['template']['spec']['containers'][0]['env'])
    self.assertIn({
        'name': 'CLUSTERFUZZ_RELEASE',
        'value': 'prod'
    }, job_body['spec']['template']['spec']['containers'][0]['env'])

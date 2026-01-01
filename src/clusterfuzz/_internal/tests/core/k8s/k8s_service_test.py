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

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.k8s import service
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
@mock.patch('kubernetes.config.load_kube_config')
class KubernetesServiceTest(unittest.TestCase):
  """Tests for the KubernetesService class."""

  def setUp(self):
    patcher = mock.patch(
        'clusterfuzz._internal.k8s.service.KubernetesService._load_gke_credentials'
    )
    self.addCleanup(patcher.stop)
    self.mock_load_gke = patcher.start()

    data_types.Job(name='job1', platform='LINUX').put()
    data_types.Job(
        name='job2', platform='LINUX',
        environment_string='CUSTOM_VAR = value').put()

  @mock.patch.object(service.KubernetesService, '_get_pending_jobs_count')
  @mock.patch.object(service.KubernetesService, 'create_kata_container_job')
  @mock.patch.object(service.KubernetesService, 'create_job')
  def test_create_uworker_main_batch_jobs(
      self, mock_create_job, mock_create_kata_job, mock_get_pending_count, _):
    """Tests the creation of uworker main batch jobs."""
    mock_get_pending_count.return_value = 0
    tasks = [
        service.RemoteTask('fuzz', 'job1', 'url1'),
        service.RemoteTask('fuzz', 'job1', 'url2'),
        service.RemoteTask('command2', 'job2', 'url3'),
    ]

    kube_service = service.KubernetesService()
    kube_service.create_uworker_main_batch_jobs(tasks)

    # Assuming default config implies Kata, and no batching of URLs.
    # Total 3 tasks, so 3 calls.
    self.assertEqual(3, mock_create_kata_job.call_count)
    self.assertEqual(0, mock_create_job.call_count)

    urls = sorted(
        [call.args[1] for call in mock_create_kata_job.call_args_list])
    self.assertEqual(urls, ['url1', 'url2', 'url3'])

  @mock.patch('kubernetes.client.CoreV1Api')
  def test_get_pending_jobs_count(self, mock_core_api_cls, _):
    """Tests _get_pending_jobs_count."""
    mock_core_api = mock_core_api_cls.return_value
    kube_service = service.KubernetesService()

    # Mock pods
    mock_core_api.list_namespaced_pod.return_value.items = [
        mock.Mock(), mock.Mock()
    ]

    self.assertEqual(2, kube_service._get_pending_jobs_count())
    mock_core_api.list_namespaced_pod.assert_called_with(
        namespace='default',
        label_selector='app.kubernetes.io/name=clusterfuzz-kata-job',
        field_selector='status.phase=Pending')

  @mock.patch.object(service.KubernetesService, '_get_pending_jobs_count')
  def test_create_uworker_main_batch_jobs_limit_reached(
      self, mock_get_pending_count, _):
    """Tests that create_uworker_main_batch_jobs nacks when limit reached."""
    mock_get_pending_count.return_value = 100
    kube_service = service.KubernetesService()

    mock_pubsub_task = mock.Mock()
    mock_pubsub_task.do_not_ack = False
    task = service.RemoteTask(
        'fuzz', 'job1', 'url1', pubsub_task=mock_pubsub_task)

    result = kube_service.create_uworker_main_batch_jobs([task])
    self.assertEqual(result, [])
    self.assertTrue(mock_pubsub_task.do_not_ack)

  @mock.patch('kubernetes.client.BatchV1Api')
  def test_create_kata_container_job_spec(self, mock_batch_api_cls, _):
    """Tests that create_kata_container_job generates the correct spec."""
    mock_batch_api = mock_batch_api_cls.return_value
    kube_service = service.KubernetesService()
    # Force _batch_api to be our mock (though init usually does it if we patched class before init)
    # The patch is applied for this method, so init inside will use the mock class.

    config = service.KubernetesJobConfig(
        job_type='test-job',
        docker_image='test-image',
        command='fuzz',
        disk_size_gb=10,
        service_account_email='email',
        clusterfuzz_release='prod',
        is_kata=True)

    kube_service.create_kata_container_job(config, 'input_url')

    self.assertTrue(mock_batch_api.create_namespaced_job.called)
    call_args = mock_batch_api.create_namespaced_job.call_args
    job_body = call_args.kwargs['body']

    # Check Spec
    pod_spec = job_body['spec']['template']['spec']
    container = pod_spec['containers'][0]

    # Check capabilities
    self.assertEqual(['ALL'],
                     container['securityContext']['capabilities']['add'])

    # Check HOST_UID env var
    env_names = {e['name']: e['value'] for e in container['env']}
    self.assertEqual('1337', env_names['HOST_UID'])

    # Check shm size
    volumes = {v['name']: v for v in pod_spec['volumes']}
    self.assertEqual('1.9Gi', volumes['dshm']['emptyDir']['sizeLimit'])

  @mock.patch(
      'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module')
  @mock.patch.object(service.KubernetesService,
                     'create_uworker_main_batch_jobs')
  def test_create_uworker_main_batch_job(self, mock_create_batch_jobs,
                                         mock_get_command, _):
    """Tests the creation of a single uworker main batch job."""
    mock_get_command.return_value = 'command'
    kube_service = service.KubernetesService()
    kube_service.create_uworker_main_batch_job('module', 'job', 'url')

    self.assertEqual(1, mock_create_batch_jobs.call_count)
    tasks = mock_create_batch_jobs.call_args[0][0]
    self.assertEqual(1, len(tasks))
    self.assertEqual('command', tasks[0].command)
    self.assertEqual('job', tasks[0].job_type)
    self.assertEqual('url', tasks[0].input_download_url)

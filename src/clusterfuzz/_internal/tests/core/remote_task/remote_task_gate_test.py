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
"""Tests for the RemoteTaskGate class."""

# pylint: disable=protected-access, unused-argument

import unittest
from unittest import mock

from clusterfuzz._internal.batch.service import GcpBatchService
from clusterfuzz._internal.cloud_run import service as cloud_run_service
from clusterfuzz._internal.k8s.service import KubernetesService
from clusterfuzz._internal.remote_task import remote_task_adapters
from clusterfuzz._internal.remote_task import remote_task_gate
from clusterfuzz._internal.remote_task import remote_task_types


class RemoteTaskGateTest(unittest.TestCase):
  """Tests for the RemoteTaskGate class."""

  def setUp(self):
    super().setUp()
    self.mock_k8s_service = mock.Mock(spec=KubernetesService)
    self.mock_cloud_run_service = mock.Mock(spec=cloud_run_service.CloudRunService)
    self.mock_gcp_batch_service = mock.Mock(spec=GcpBatchService)

    self.mock_k8s_service.create_utask_main_jobs.return_value = []
    self.mock_cloud_run_service.create_utask_main_jobs.return_value = []
    self.mock_gcp_batch_service.create_utask_main_jobs.return_value = []

    # Patch RemoteTaskAdapters to return our mock services
    self.patcher = mock.patch.dict(
        remote_task_adapters.RemoteTaskAdapters._member_map_, {
            'KUBERNETES':
                mock.Mock(
                    id='kubernetes',
                    service=mock.Mock(return_value=self.mock_k8s_service),
                    feature_flag=None,
                    default_weight=0.0),
            'CLOUD_RUN':
                mock.Mock(
                    id='cloud_run',
                    service=mock.Mock(return_value=self.mock_cloud_run_service),
                    feature_flag=None,
                    default_weight=0.0),
            'GCP_BATCH':
                mock.Mock(
                    id='gcp_batch',
                    service=mock.Mock(return_value=self.mock_gcp_batch_service),
                    feature_flag=None,
                    default_weight=1.0),
        })
    self.patcher.start()
    self.addCleanup(self.patcher.stop)

  def test_init(self):
    """Tests that the RemoteTaskGate initializes correctly and creates
    service map."""
    gate = remote_task_gate.RemoteTaskGate()
    self.assertIn('kubernetes', gate._service_map)
    self.assertIn('cloud_run', gate._service_map)
    self.assertIn('gcp_batch', gate._service_map)
    self.assertEqual(gate._service_map['kubernetes'], self.mock_k8s_service)
    self.assertEqual(gate._service_map['cloud_run'], self.mock_cloud_run_service)
    self.assertEqual(gate._service_map['gcp_batch'],
                     self.mock_gcp_batch_service)

  @mock.patch('random.choices')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_get_adapter(self, mock_get_job_frequency, mock_random_choices):
    """Tests that _get_adapter returns the correct adapter based on
    job_frequency."""
    mock_get_job_frequency.return_value = {
        'kubernetes': 0.1,
        'cloud_run': 0.2,
        'gcp_batch': 0.7
    }
    mock_random_choices.return_value = ['cloud_run']

    gate = remote_task_gate.RemoteTaskGate()
    selected_adapter = gate._get_adapter()

    mock_get_job_frequency.assert_called_once()
    mock_random_choices.assert_called_once_with(
        ['kubernetes', 'cloud_run', 'gcp_batch'], [0.1, 0.2, 0.7])
    self.assertEqual(selected_adapter, 'cloud_run')

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_kubernetes(self, mock_get_adapter):
    """Tests that create_utask_main_job calls the Kubernetes service
    when kubernetes adapter is chosen."""
    mock_get_adapter.return_value = 'kubernetes'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')
    self.mock_k8s_service.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')
    self.mock_cloud_run_service.create_utask_main_job.assert_not_called()
    self.mock_gcp_batch_service.create_utask_main_job.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_cloud_run(self, mock_get_adapter):
    """Tests that create_utask_main_job calls the Cloud Run service
    when cloud_run adapter is chosen."""
    mock_get_adapter.return_value = 'cloud_run'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')
    self.mock_cloud_run_service.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')
    self.mock_k8s_service.create_utask_main_job.assert_not_called()
    self.mock_gcp_batch_service.create_utask_main_job.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_gcp_batch(self, mock_get_adapter):
    """Tests that create_utask_main_job calls the GCP Batch service
    when gcp_batch adapter is chosen."""
    mock_get_adapter.return_value = 'gcp_batch'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')
    self.mock_gcp_batch_service.create_utask_main_job.assert_called_once_with(
        'module',
        'job',
        'url',
    )
    self.mock_k8s_service.create_utask_main_job.assert_not_called()
    self.mock_cloud_run_service.create_utask_main_job.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_jobs_single_task(self, mock_get_adapter):
    """Tests that create_utask_main_jobs correctly routes a single task
    based on _get_adapter."""
    tasks = [
        remote_task_types.RemoteTask('command1', 'job1', 'url1'),
    ]
    mock_get_adapter.return_value = 'kubernetes'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_multiple_tasks_slicing(
      self, mock_get_job_frequency):
    """Tests that create_utask_main_jobs correctly routes multiple tasks
    using deterministic slicing."""
    tasks = [
        remote_task_types.RemoteTask('command', 'job1', 'url1'),
        remote_task_types.RemoteTask('command', 'job1', 'url2'),
        remote_task_types.RemoteTask('command', 'job1', 'url3'),
        remote_task_types.RemoteTask('command', 'job1', 'url4'),
    ]

    # 50% split
    mock_get_job_frequency.return_value = {'kubernetes': 0.5, 'gcp_batch': 0.5}

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    # 4 * 0.5 = 2 tasks for k8s, 2 for gcp_batch.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        tasks[:2])
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once_with(
        tasks[2:])

  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_remainder_distribution(
      self, mock_get_job_frequency):
    """Tests that create_utask_main_jobs correctly distributes remainder
    tasks."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
        remote_task_types.RemoteTask('c', 'j', 'u3'),
    ]

    # 33/33/33 split - one task will be a remainder
    mock_get_job_frequency.return_value = {
        'kubernetes': 0.33,
        'gcp_batch': 0.33
    }

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    # Expect 1 for k8s, 1 for gcp_batch, and 1 remainder distributed round robin.
    # In this case, first k8s gets 1, then gcp_batch gets 1, then k8s gets the last one.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[0], tasks[2]])
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[1]])

  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_full_kubernetes(self, mock_get_job_frequency):
    """Tests that all tasks are routed to Kubernetes when frequency is 1.0."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
    ]
    mock_get_job_frequency.return_value = {'kubernetes': 1.0, 'gcp_batch': 0.0}
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_full_gcp_batch(self, mock_get_job_frequency):
    """Tests that all tasks are routed to GCP Batch when frequency is 1.0."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
    ]
    mock_get_job_frequency.return_value = {'kubernetes': 0.0, 'gcp_batch': 1.0}
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once_with(
        tasks)
    self.mock_k8s_service.create_utask_main_jobs.assert_not_called()

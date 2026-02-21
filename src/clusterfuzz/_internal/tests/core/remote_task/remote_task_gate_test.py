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

from clusterfuzz._internal.base import feature_flags
from clusterfuzz._internal.batch.service import GcpBatchService
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.k8s.service import KubernetesService
from clusterfuzz._internal.remote_task import remote_task_adapters
from clusterfuzz._internal.remote_task import remote_task_gate
from clusterfuzz._internal.remote_task import remote_task_types


class RemoteTaskGateTest(unittest.TestCase):
  """Tests for the RemoteTaskGate class."""

  def setUp(self):
    super().setUp()
    self.mock_k8s_service = mock.Mock(spec=KubernetesService)
    self.mock_gcp_batch_service = mock.Mock(spec=GcpBatchService)

    self.mock_k8s_service.create_utask_main_jobs.return_value = []
    self.mock_gcp_batch_service.create_utask_main_jobs.return_value = []

    # Mock the JOB_RUNTIME_ROUTING feature flag to be disabled by default.
    self.mock_routing_flag = mock.PropertyMock(return_value=False)
    mock.patch.object(feature_flags.FeatureFlags.JOB_RUNTIME_ROUTING.__class__,
                      'enabled', self.mock_routing_flag).start()

    # Patch RemoteTaskAdapters to return our mock services
    self.patcher = mock.patch.dict(
        remote_task_adapters.RemoteTaskAdapters._member_map_, {
            'KUBERNETES':
                mock.Mock(
                    id='kubernetes',
                    service=mock.Mock(return_value=self.mock_k8s_service),
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
    self.addCleanup(mock.patch.stopall)

  def test_init(self):
    """Tests that the RemoteTaskGate initializes correctly and creates
    service map."""
    gate = remote_task_gate.RemoteTaskGate()
    self.assertIn('kubernetes', gate._service_map)
    self.assertIn('gcp_batch', gate._service_map)
    self.assertEqual(gate._service_map['kubernetes'], self.mock_k8s_service)
    self.assertEqual(gate._service_map['gcp_batch'],
                     self.mock_gcp_batch_service)

  @mock.patch('random.choices')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_get_adapter(self, mock_get_job_frequency, mock_random_choices):
    """Tests that _get_adapter returns the correct adapter based on
    job_frequency."""
    mock_get_job_frequency.return_value = {'kubernetes': 0.3, 'gcp_batch': 0.7}
    mock_random_choices.return_value = ['gcp_batch']

    gate = remote_task_gate.RemoteTaskGate()
    selected_adapter = gate._get_adapter()

    mock_get_job_frequency.assert_called_once()
    mock_random_choices.assert_called_once_with(['kubernetes', 'gcp_batch'],
                                                [0.3, 0.7])
    self.assertEqual(selected_adapter, 'gcp_batch')

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_kubernetes(self, mock_get_adapter):
    """Tests that create_utask_main_job calls the Kubernetes service
    when kubernetes adapter is chosen."""
    mock_get_adapter.return_value = 'kubernetes'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')
    self.mock_k8s_service.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')
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

  def test_create_utask_main_jobs_single_task(self):
    """Tests that create_utask_main_jobs correctly routes a single task."""
    tasks = [
        remote_task_types.RemoteTask('command1', 'job1', 'url1'),
    ]
    # Set frequency to 100% k8s to ensure it goes there even if no JobRuntime.
    self.patcher.stop()
    self.patcher = mock.patch.dict(
        remote_task_adapters.RemoteTaskAdapters._member_map_, {
            'KUBERNETES':
                mock.Mock(
                    id='kubernetes',
                    service=mock.Mock(return_value=self.mock_k8s_service),
                    feature_flag=None,
                    default_weight=1.0),
            'GCP_BATCH':
                mock.Mock(
                    id='gcp_batch',
                    service=mock.Mock(return_value=self.mock_gcp_batch_service),
                    feature_flag=None,
                    default_weight=0.0),
        })
    self.patcher.start()

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_not_called()

  def test_create_utask_main_jobs_empty(self):
    """Tests that create_utask_main_jobs handles empty lists."""
    gate = remote_task_gate.RemoteTaskGate()
    result = gate.create_utask_main_jobs([])
    self.assertEqual(result, [])

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

    # 50/50 split - one task will be a remainder
    mock_get_job_frequency.return_value = {'kubernetes': 0.5, 'gcp_batch': 0.5}

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    # Expect 1 for k8s, 1 for gcp_batch, and 1 remainder distributed round robin.
    # In this case, first k8s gets 1, then gcp_batch gets 1, then k8s gets the last one.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[0], tasks[2]])
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[1]])

  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_unscheduled(self, mock_get_job_frequency):
    """Tests that create_utask_main_jobs returns remainder as unscheduled
    when sum < 1.0."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
        remote_task_types.RemoteTask('c', 'j', 'u3'),
        remote_task_types.RemoteTask('c', 'j', 'u4'),
    ]

    # 0.25 each. Sum 0.5.
    mock_get_job_frequency.return_value = {
        'kubernetes': 0.25,
        'gcp_batch': 0.25
    }

    gate = remote_task_gate.RemoteTaskGate()
    result = gate.create_utask_main_jobs(tasks)

    # 4 * 0.25 = 1 task each.
    # Total assigned = 2.
    # Total unscheduled = 2.

    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[0]])
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[1]])

    # Result should contain unscheduled (tasks[2], tasks[3]).
    self.assertEqual(result, [tasks[2], tasks[3]])

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

  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_returns_unscheduled_tasks(
      self, mock_get_job_frequency):
    """Tests that create_utask_main_jobs returns unscheduled tasks directly."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
    ]
    unscheduled_tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
    ]

    mock_get_job_frequency.return_value = {'kubernetes': 1.0, 'gcp_batch': 0.0}
    self.mock_k8s_service.create_utask_main_jobs.return_value = unscheduled_tasks

    gate = remote_task_gate.RemoteTaskGate()
    result = gate.create_utask_main_jobs(tasks)

    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)
    self.assertEqual(result, unscheduled_tasks)


class RemoteTaskGateRoutingTest(unittest.TestCase):
  """Tests for job runtime routing logic in RemoteTaskGate."""

  def setUp(self):
    super().setUp()
    self.mock_k8s_service = mock.Mock(spec=KubernetesService)
    self.mock_gcp_batch_service = mock.Mock(spec=GcpBatchService)

    self.mock_k8s_service.create_utask_main_jobs.return_value = []
    self.mock_gcp_batch_service.create_utask_main_jobs.return_value = []

    # Mock the JOB_RUNTIME_ROUTING feature flag to be enabled.
    mock.patch.object(
        feature_flags.FeatureFlags.JOB_RUNTIME_ROUTING.__class__,
        'enabled',
        mock.PropertyMock(return_value=True)).start()

    # Patch RemoteTaskAdapters to return our mock services
    # 70% GCP_BATCH, 30% KUBERNETES
    self.patcher = mock.patch.dict(
        remote_task_adapters.RemoteTaskAdapters._member_map_, {
            'KUBERNETES':
                mock.Mock(
                    id='kubernetes',
                    service=mock.Mock(return_value=self.mock_k8s_service),
                    feature_flag=None,
                    default_weight=0.3),
            'GCP_BATCH':
                mock.Mock(
                    id='gcp_batch',
                    service=mock.Mock(return_value=self.mock_gcp_batch_service),
                    feature_flag=None,
                    default_weight=0.7),
        })
    self.patcher.start()
    self.addCleanup(self.patcher.stop)
    self.addCleanup(mock.patch.stopall)

  @mock.patch('google.cloud.ndb.Key')
  @mock.patch('google.cloud.ndb.get_multi')
  def test_create_utask_main_jobs_capped_routing(self, mock_get_multi,
                                                 mock_key):
    """Tests that routing is capped by frequency (min rule)."""
    # 10 tasks. Budget: 7 batch, 3 kata.
    tasks = [
        remote_task_types.RemoteTask('c', f'job_{i}', 'u') for i in range(10)
    ]

    # 10 tasks prefer kata.
    mock_runtimes = []
    for i in range(10):
      jr = mock.Mock(spec=data_types.JobRuntime)
      jr.job_name = f'job_{i}'
      jr.runtime = 'kata'
      mock_runtimes.append(jr)

    mock_get_multi.return_value = mock_runtimes

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    # Kata budget is 3. Only 3 should be sent to kubernetes.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once()
    self.assertEqual(
        len(self.mock_k8s_service.create_utask_main_jobs.call_args[0][0]), 3)

    # The other 7 MUST be sent to batch to satisfy frequency.
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once()
    self.assertEqual(
        len(self.mock_gcp_batch_service.create_utask_main_jobs.call_args[0][0]),
        7)

  @mock.patch('google.cloud.ndb.Key')
  def test_get_adapter_routing(self, mock_key):
    """Tests that _get_adapter respects JobRuntime."""
    mock_jr = mock.Mock(spec=data_types.JobRuntime)
    mock_jr.runtime = 'kata'
    mock_key.return_value.get.return_value = mock_jr

    gate = remote_task_gate.RemoteTaskGate()
    # Should return kubernetes regardless of weights because of JobRuntime.
    self.assertEqual(gate._get_adapter('some_job'), 'kubernetes')


class RemoteTaskGateProcessingTest(unittest.TestCase):
  """Tests for logic in RemoteTaskGate that doesn't require full service mocking."""

  def setUp(self):
    super().setUp()
    # Mock adapters to avoid real service instantiation
    self.patcher = mock.patch.dict(
        remote_task_adapters.RemoteTaskAdapters._member_map_, {
            'KUBERNETES':
                mock.Mock(
                    id='kubernetes',
                    service=mock.Mock(),
                    feature_flag=None,
                    default_weight=0.0),
            'GCP_BATCH':
                mock.Mock(
                    id='gcp_batch',
                    service=mock.Mock(),
                    feature_flag=None,
                    default_weight=1.0),
        })
    self.patcher.start()
    self.addCleanup(self.patcher.stop)
    self.gate = remote_task_gate.RemoteTaskGate()

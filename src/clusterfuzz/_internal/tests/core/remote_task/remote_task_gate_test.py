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
from clusterfuzz._internal.k8s.service import KubernetesService
from clusterfuzz._internal.remote_task import remote_task_adapters
from clusterfuzz._internal.remote_task import remote_task_gate
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.swarming.service import SwarmingService


class RemoteTaskGateTest(unittest.TestCase):
  """Tests for the RemoteTaskGate class."""

  def setUp(self):
    super().setUp()
    self.mock_k8s_service = mock.Mock(spec=KubernetesService)
    self.mock_gcp_batch_service = mock.Mock(spec=GcpBatchService)
    self.mock_swarming_service = mock.Mock(spec=SwarmingService)

    self.mock_k8s_service.create_utask_main_jobs.return_value = []
    self.mock_gcp_batch_service.create_utask_main_jobs.return_value = []
    self.mock_swarming_service.create_utask_main_jobs.return_value = []

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
            'SWARMING':
                mock.Mock(
                    id='swarming',
                    service=mock.Mock(return_value=self.mock_swarming_service),
                    feature_flag=None,
                    default_weight=0.0),
        })
    self.patcher.start()
    self.addCleanup(self.patcher.stop)

  def test_init(self):
    """Tests that the RemoteTaskGate initializes correctly and creates
    service map."""
    gate = remote_task_gate.RemoteTaskGate()
    self.assertIn('kubernetes', gate._service_map)
    self.assertIn('gcp_batch', gate._service_map)
    self.assertIn('swarming', gate._service_map)
    self.assertEqual(gate._service_map['kubernetes'], self.mock_k8s_service)
    self.assertEqual(gate._service_map['gcp_batch'],
                     self.mock_gcp_batch_service)
    self.assertEqual(gate._service_map['swarming'], self.mock_swarming_service)

  @mock.patch('random.choices')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_get_adapter(self, mock_get_job_frequency, mock_random_choices):
    """Tests that _get_adapter returns the correct adapter based on
    job_frequency."""
    mock_get_job_frequency.return_value = {
        'kubernetes': 0.3,
        'gcp_batch': 0.7,
        'swarming': 0.0
    }
    mock_random_choices.return_value = ['gcp_batch']

    gate = remote_task_gate.RemoteTaskGate()
    selected_adapter = gate._get_adapter()

    mock_get_job_frequency.assert_called_once()
    mock_random_choices.assert_called_once_with(
        ['kubernetes', 'gcp_batch', 'swarming'], [0.3, 0.7, 0.0])
    self.assertEqual(selected_adapter, 'gcp_batch')

  @mock.patch('clusterfuzz._internal.remote_task.remote_task_gate.task_utils')
  @mock.patch('clusterfuzz._internal.remote_task.remote_task_gate.swarming')
  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  def test_create_utask_main_job_swarming_priority(
      self, mock_swarming_flag, mock_swarming, mock_task_utils):
    """Tests that create_utask_main_job prioritizes Swarming tasks when
    flag is enabled and it is a swarming task."""
    mock_swarming_flag.return_value = True
    mock_task_utils.get_command_from_module.return_value = 'fuzz'
    mock_swarming.is_swarming_task.return_value = True
    self.mock_swarming_service.create_utask_main_job.return_value = mock.Mock()

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')

    self.mock_swarming_service.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')
    self.mock_k8s_service.create_utask_main_job.assert_not_called()
    self.mock_gcp_batch_service.create_utask_main_job.assert_not_called()

  @mock.patch('clusterfuzz._internal.remote_task.remote_task_gate.task_utils')
  @mock.patch('clusterfuzz._internal.remote_task.remote_task_gate.swarming')
  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_kubernetes(self, mock_get_adapter,
                                            mock_swarming_flag, mock_swarming,
                                            mock_task_utils):
    """Tests that create_utask_main_job calls the Kubernetes service
    when it is NOT a swarming task."""
    mock_swarming_flag.return_value = True
    mock_task_utils.get_command_from_module.return_value = 'fuzz'
    mock_swarming.is_swarming_task.return_value = False

    mock_get_adapter.return_value = 'kubernetes'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')

    self.mock_swarming_service.create_utask_main_job.assert_not_called()
    self.mock_k8s_service.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')
    self.mock_gcp_batch_service.create_utask_main_job.assert_not_called()

  @mock.patch('clusterfuzz._internal.remote_task.remote_task_gate.task_utils')
  @mock.patch('clusterfuzz._internal.remote_task.remote_task_gate.swarming')
  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_gcp_batch(self, mock_get_adapter,
                                           mock_swarming_flag, mock_swarming,
                                           mock_task_utils):
    """Tests that create_utask_main_job calls the GCP Batch service
    when it is NOT a swarming task."""
    mock_swarming_flag.return_value = True
    mock_task_utils.get_command_from_module.return_value = 'fuzz'
    mock_swarming.is_swarming_task.return_value = False

    mock_get_adapter.return_value = 'gcp_batch'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')

    self.mock_swarming_service.create_utask_main_job.assert_not_called()
    self.mock_gcp_batch_service.create_utask_main_job.assert_called_once_with(
        'module',
        'job',
        'url',
    )
    self.mock_k8s_service.create_utask_main_job.assert_not_called()

  @mock.patch('clusterfuzz._internal.remote_task.remote_task_gate.task_utils')
  @mock.patch('clusterfuzz._internal.remote_task.remote_task_gate.swarming')
  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_swarming_disabled(
      self, mock_get_adapter, mock_swarming_flag, mock_swarming,
      mock_task_utils):
    """Tests that create_utask_main_job does NOT call Swarming when flag
    is disabled."""
    mock_swarming_flag.return_value = False
    mock_task_utils.get_command_from_module.return_value = 'fuzz'
    mock_swarming.is_swarming_task.return_value = True
    mock_get_adapter.return_value = 'kubernetes'

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')

    self.mock_swarming_service.create_utask_main_job.assert_not_called()
    self.mock_k8s_service.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_jobs_single_task(self, mock_get_adapter,
                                              mock_swarming_flag):
    """Tests that create_utask_main_jobs correctly routes a single task
    based on _get_adapter."""
    tasks = [
        remote_task_types.RemoteTask('command1', 'job1', 'url1'),
    ]
    mock_swarming_flag.return_value = False
    mock_get_adapter.return_value = 'kubernetes'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_not_called()

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_multiple_tasks_slicing(
      self, mock_get_job_frequency, mock_swarming_flag):
    """Tests that create_utask_main_jobs correctly routes multiple tasks
    using deterministic slicing."""
    tasks = [
        remote_task_types.RemoteTask('command', 'job1', 'url1'),
        remote_task_types.RemoteTask('command', 'job1', 'url2'),
        remote_task_types.RemoteTask('command', 'job1', 'url3'),
        remote_task_types.RemoteTask('command', 'job1', 'url4'),
    ]
    mock_swarming_flag.return_value = False

    # 50% split
    mock_get_job_frequency.return_value = {
        'kubernetes': 0.5,
        'gcp_batch': 0.5,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    # 4 * 0.5 = 2 tasks for k8s, 2 for gcp_batch.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        tasks[:2])
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once_with(
        tasks[2:])

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_remainder_distribution(
      self, mock_get_job_frequency, mock_swarming_flag):
    """Tests that create_utask_main_jobs correctly distributes remainder
    tasks."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
        remote_task_types.RemoteTask('c', 'j', 'u3'),
    ]
    mock_swarming_flag.return_value = False

    # 50/50 split - one task will be a remainder
    mock_get_job_frequency.return_value = {
        'kubernetes': 0.5,
        'gcp_batch': 0.5,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    # Expect 1 for k8s, 1 for gcp_batch, and 1 remainder distributed round robin.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[0], tasks[2]])
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[1]])

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_unscheduled(self, mock_get_job_frequency,
                                              mock_swarming_flag):
    """Tests that create_utask_main_jobs returns remainder as unscheduled
    when sum < 1.0."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
        remote_task_types.RemoteTask('c', 'j', 'u3'),
        remote_task_types.RemoteTask('c', 'j', 'u4'),
    ]
    mock_swarming_flag.return_value = False

    # 0.25 each. Sum 0.5.
    mock_get_job_frequency.return_value = {
        'kubernetes': 0.25,
        'gcp_batch': 0.25,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    result = gate.create_utask_main_jobs(tasks)

    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[0]])
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[1]])

    self.assertEqual(result, [tasks[2], tasks[3]])

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_full_kubernetes(self, mock_get_job_frequency,
                                                  mock_swarming_flag):
    """Tests that all tasks are routed to Kubernetes when frequency is 1.0."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
    ]
    mock_swarming_flag.return_value = False
    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_not_called()

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_full_gcp_batch(self, mock_get_job_frequency,
                                                 mock_swarming_flag):
    """Tests that all tasks are routed to GCP Batch when frequency is 1.0."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
    ]
    mock_swarming_flag.return_value = False
    mock_get_job_frequency.return_value = {
        'kubernetes': 0.0,
        'gcp_batch': 1.0,
        'swarming': 0.0
    }
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_called_once_with(
        tasks)
    self.mock_k8s_service.create_utask_main_jobs.assert_not_called()

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_returns_unscheduled_tasks(
      self, mock_get_job_frequency, mock_swarming_flag):
    """Tests that create_utask_main_jobs returns unscheduled tasks directly."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
    ]
    unscheduled_tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
    ]
    mock_swarming_flag.return_value = False
    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }
    self.mock_k8s_service.create_utask_main_jobs.return_value = unscheduled_tasks

    gate = remote_task_gate.RemoteTaskGate()
    result = gate.create_utask_main_jobs(tasks)

    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)
    self.assertEqual(result, unscheduled_tasks)

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_swarming_remote_execution_enabled(
      self, mock_get_job_frequency, mock_swarming_flag):
    """Tests that create_utask_main_jobs passes tasks to swarming service when the
    feature flag is enabled."""
    tasks = [
        remote_task_types.RemoteTask('swarming_cmd', 'job1', 'url1'),
        remote_task_types.RemoteTask('regular_cmd', 'job2', 'url2'),
    ]

    mock_swarming_flag.return_value = True
    # SwarmingService should process the swarming task and return the regular task.
    self.mock_swarming_service.create_utask_main_jobs.return_value = [tasks[1]]

    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    result = gate.create_utask_main_jobs(tasks)

    # ALL tasks should be sent to SwarmingService initially.
    self.mock_swarming_service.create_utask_main_jobs.assert_called_once_with(
        tasks)

    # The regular task returned by SwarmingService should be routed to Kubernetes.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[1]])

    # No tasks should be unscheduled.
    self.assertEqual(result, [])

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  def test_create_utask_main_jobs_swarming_remote_execution_all_swarming(
      self, mock_swarming_flag):
    """Tests that create_utask_main_jobs handles the case where all tasks
    are swarming tasks."""
    tasks = [
        remote_task_types.RemoteTask('swarming_cmd', 'job1', 'url1'),
        remote_task_types.RemoteTask('swarming_cmd', 'job2', 'url2'),
    ]

    mock_swarming_flag.return_value = True
    # All tasks successfully scheduled as swarming.
    self.mock_swarming_service.create_utask_main_jobs.return_value = []

    gate = remote_task_gate.RemoteTaskGate()
    result = gate.create_utask_main_jobs(tasks)

    # Both tasks should be sent to SwarmingService.
    self.mock_swarming_service.create_utask_main_jobs.assert_called_once_with(
        tasks)
    self.mock_k8s_service.create_utask_main_jobs.assert_not_called()
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_not_called()

    # No tasks should be unscheduled.
    self.assertEqual(result, [])

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_swarming_failure_preservation(
      self, mock_get_job_frequency, mock_swarming_flag):
    """Tests that failed swarming tasks are correctly included in
    unscheduled_tasks."""
    tasks = [
        remote_task_types.RemoteTask('swarming_cmd1', 'job1', 'url1'),
        remote_task_types.RemoteTask('swarming_cmd2', 'job2', 'url2'),
        remote_task_types.RemoteTask('regular_cmd', 'job3', 'url3'),
    ]

    mock_swarming_flag.return_value = True
    # Mock one success, one failure (by returning it as unscheduled) and one regular task.
    self.mock_swarming_service.create_utask_main_jobs.return_value = [
        tasks[1], tasks[2]
    ]

    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    result = gate.create_utask_main_jobs(tasks)

    # All tasks sent to SwarmingService.
    self.mock_swarming_service.create_utask_main_jobs.assert_called_once_with(
        tasks)

    # The tasks returned by SwarmingService (failed swarming + regular) sent to k8s.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [tasks[1], tasks[2]])

    # Both should be successfully processed by K8s (mocked to return [] by default).
    self.assertEqual(result, [])

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_swarming_remote_execution_disabled(
      self, mock_get_job_frequency, mock_swarming_flag):
    """Tests that swarming tasks are NOT intercepted when the flag is disabled."""
    tasks = [
        remote_task_types.RemoteTask('swarming_cmd', 'job1', 'url1'),
    ]

    mock_swarming_flag.return_value = False
    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    # Flag disabled: should NOT call SwarmingService.
    self.mock_swarming_service.create_utask_main_jobs.assert_not_called()

    # Should be routed normally to Kubernetes.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)


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
            'SWARMING':
                mock.Mock(
                    id='swarming',
                    service=mock.Mock(),
                    feature_flag=None,
                    default_weight=0.0),
        })
    self.patcher.start()
    self.addCleanup(self.patcher.stop)
    self.gate = remote_task_gate.RemoteTaskGate()

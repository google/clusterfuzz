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
                    feature_flag=mock.Mock(enabled=True),
                    default_weight=0.0),
            'GCP_BATCH':
                mock.Mock(
                    id='gcp_batch',
                    service=mock.Mock(return_value=self.mock_gcp_batch_service),
                    feature_flag=mock.Mock(enabled=True),
                    default_weight=1.0),
            'SWARMING':
                mock.Mock(
                    id='swarming',
                    service=mock.Mock(return_value=self.mock_swarming_service),
                    feature_flag=mock.Mock(enabled=True),
                    default_weight=0.0),
        })
    self.patcher.start()
    self.addCleanup(self.patcher.stop)
    is_swarming_task_patcher = mock.patch.object(
        remote_task_gate.RemoteTaskGate,
        '_is_swarming_task',
        return_value=False)
    is_swarming_task_patcher.start()
    self.addCleanup(is_swarming_task_patcher.stop)

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

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_handle_swarming_job')
  def test_create_utask_main_job_swarming_priority(
      self, mock_handle_swarming_job, mock_is_swarming_task,
      mock_is_swarming_applicable):
    """Tests that create_utask_main_job prioritizes Swarming tasks when
    flag is enabled and it is a swarming task."""
    mock_is_swarming_applicable.return_value = True
    mock_is_swarming_task.return_value = True
    mock_handle_swarming_job.return_value = mock.Mock()

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')

    mock_handle_swarming_job.assert_called_once_with('module', 'job', 'url')
    self.mock_k8s_service.create_utask_main_job.assert_not_called()
    self.mock_gcp_batch_service.create_utask_main_job.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_kubernetes(self, mock_get_adapter,
                                            mock_is_swarming_task,
                                            mock_is_swarming_applicable):
    """Tests that create_utask_main_job calls the Kubernetes service
    when it is NOT a swarming task."""
    mock_is_swarming_applicable.return_value = True
    mock_is_swarming_task.return_value = False

    mock_get_adapter.return_value = 'kubernetes'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')

    self.mock_swarming_service.create_utask_main_job.assert_not_called()
    self.mock_k8s_service.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')
    self.mock_gcp_batch_service.create_utask_main_job.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_gcp_batch(self, mock_get_adapter,
                                           mock_is_swarming_task,
                                           mock_is_swarming_applicable):
    """Tests that create_utask_main_job calls the GCP Batch service
    when it is NOT a swarming task."""
    mock_is_swarming_applicable.return_value = True
    mock_is_swarming_task.return_value = False

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

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_job_swarming_disabled(self, mock_get_adapter,
                                                   mock_is_swarming_task,
                                                   mock_is_swarming_applicable):
    """Tests that create_utask_main_job does NOT call Swarming when flag
    is disabled."""
    mock_is_swarming_applicable.return_value = False
    mock_is_swarming_task.return_value = True
    mock_get_adapter.return_value = 'kubernetes'

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')

    self.mock_swarming_service.create_utask_main_job.assert_not_called()
    self.mock_k8s_service.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_get_adapter')
  def test_create_utask_main_jobs_single_task(self, mock_get_adapter,
                                              mock_is_swarming_applicable):
    """Tests that create_utask_main_jobs correctly routes a single task
    based on _get_adapter."""
    tasks = [
        remote_task_types.RemoteTask('command1', 'job1', 'url1'),
    ]
    mock_is_swarming_applicable.return_value = False
    mock_get_adapter.return_value = 'kubernetes'
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_multiple_tasks_slicing(
      self, mock_get_job_frequency, mock_is_swarming_applicable):
    """Tests that create_utask_main_jobs correctly routes multiple tasks
    using deterministic slicing."""
    tasks = [
        remote_task_types.RemoteTask('command', 'job1', 'url1'),
        remote_task_types.RemoteTask('command', 'job1', 'url2'),
        remote_task_types.RemoteTask('command', 'job1', 'url3'),
        remote_task_types.RemoteTask('command', 'job1', 'url4'),
    ]
    mock_is_swarming_applicable.return_value = False

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

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_remainder_distribution(
      self, mock_get_job_frequency, mock_is_swarming_applicable):
    """Tests that create_utask_main_jobs correctly distributes remainder
    tasks."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
        remote_task_types.RemoteTask('c', 'j', 'u3'),
    ]
    mock_is_swarming_applicable.return_value = False

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

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_unscheduled(self, mock_get_job_frequency,
                                              mock_is_swarming_applicable):
    """Tests that create_utask_main_jobs returns remainder as unscheduled
    when sum < 1.0."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
        remote_task_types.RemoteTask('c', 'j', 'u3'),
        remote_task_types.RemoteTask('c', 'j', 'u4'),
    ]
    mock_is_swarming_applicable.return_value = False

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

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_full_kubernetes(self, mock_get_job_frequency,
                                                  mock_is_swarming_applicable):
    """Tests that all tasks are routed to Kubernetes when frequency is 1.0."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
    ]
    mock_is_swarming_applicable.return_value = False
    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }
    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_full_gcp_batch(self, mock_get_job_frequency,
                                                 mock_is_swarming_applicable):
    """Tests that all tasks are routed to GCP Batch when frequency is 1.0."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
        remote_task_types.RemoteTask('c', 'j', 'u2'),
    ]
    mock_is_swarming_applicable.return_value = False
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

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_returns_unscheduled_tasks(
      self, mock_get_job_frequency, mock_is_swarming_applicable):
    """Tests that create_utask_main_jobs returns unscheduled tasks directly."""
    tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
    ]
    unscheduled_tasks = [
        remote_task_types.RemoteTask('c', 'j', 'u1'),
    ]
    mock_is_swarming_applicable.return_value = False
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

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_handle_swarming_jobs')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_swarming_remote_execution_enabled(
      self, mock_get_job_frequency, mock_handle_swarming_jobs,
      mock_is_swarming_task, mock_is_swarming_applicable):
    """Tests that create_utask_main_jobs passes swarming tasks to swarming
    service when the feature flag is enabled."""
    swarming_task = remote_task_types.RemoteTask('swarming_cmd', 'swarming_job',
                                                 'url1')
    other_task = remote_task_types.RemoteTask('regular_cmd', 'regular_job',
                                              'url2')

    mock_is_swarming_applicable.return_value = True
    mock_is_swarming_task.side_effect = lambda job_type: job_type == 'swarming_job'
    mock_handle_swarming_jobs.return_value = []

    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    unscheduled_tasks = gate.create_utask_main_jobs([swarming_task, other_task])

    mock_handle_swarming_jobs.assert_called_once_with([swarming_task])
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [other_task])
    self.assertEqual(unscheduled_tasks, [])

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_handle_swarming_jobs')
  def test_create_utask_main_jobs_swarming_remote_execution_all_swarming(
      self, mock_handle_swarming_jobs, mock_is_swarming_task,
      mock_is_swarming_applicable):
    """Tests that create_utask_main_jobs handles the case where all tasks
    are swarming tasks."""
    tasks = [
        remote_task_types.RemoteTask('swarming_cmd', 'job1', 'url1'),
        remote_task_types.RemoteTask('swarming_cmd', 'job2', 'url2'),
    ]

    mock_is_swarming_applicable.return_value = True
    mock_is_swarming_task.return_value = True
    # All tasks successfully scheduled as swarming.
    mock_handle_swarming_jobs.return_value = []

    gate = remote_task_gate.RemoteTaskGate()
    result = gate.create_utask_main_jobs(tasks)

    # Both tasks should be sent to _handle_swarming_jobs.
    mock_handle_swarming_jobs.assert_called_once_with(tasks)
    self.mock_k8s_service.create_utask_main_jobs.assert_not_called()
    self.mock_gcp_batch_service.create_utask_main_jobs.assert_not_called()

    # No tasks should be unscheduled.
    self.assertEqual(result, [])

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_handle_swarming_jobs')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_swarming_failure_preservation(
      self, mock_get_job_frequency, mock_handle_swarming_jobs,
      mock_is_swarming_task, mock_is_swarming_applicable):
    """Tests that failed swarming tasks are correctly included in
    unscheduled_tasks."""
    swarming_task = remote_task_types.RemoteTask('cmd', 'swarming_job', 'url1')
    failed_swarming_task = remote_task_types.RemoteTask('cmd2', 'swarming_job',
                                                        'url2')
    other_task = remote_task_types.RemoteTask('cmd', 'job3', 'url3')
    tasks = [swarming_task, failed_swarming_task, other_task]

    mock_is_swarming_applicable.return_value = True
    mock_is_swarming_task.side_effect = (
        lambda job_type: job_type == 'swarming_job')
    mock_handle_swarming_jobs.return_value = [failed_swarming_task]

    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    unscheduled_tasks = gate.create_utask_main_jobs(tasks)

    mock_handle_swarming_jobs.assert_called_once_with(
        [swarming_task, failed_swarming_task])
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [other_task])
    self.assertEqual(unscheduled_tasks, [failed_swarming_task])

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_create_utask_main_jobs_swarming_remote_execution_disabled(
      self, mock_get_job_frequency, mock_is_swarming_applicable):
    """Tests that swarming tasks are NOT intercepted when the flag is disabled."""
    tasks = [
        remote_task_types.RemoteTask('swarming_cmd', 'job1', 'url1'),
    ]

    mock_is_swarming_applicable.return_value = False
    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    # Flag disabled: should NOT call swarming service.
    self.mock_swarming_service.create_utask_main_jobs.assert_not_called()

    # Should be routed normally to Kubernetes.
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(tasks)

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  def test_unscheduled_swarming_tasks_dont_get_tried_on_other_services(
      self, mock_is_swarming_task, mock_is_swarming_applicable):
    """Tests that if swarming is unable to schedule a task, it doesn't get
    tried on other services."""
    swarming_tasks = [
        remote_task_types.RemoteTask('swarming_cmd', 'swarming_job', 'url'),
        remote_task_types.RemoteTask('swarming_cmd', 'swarming_job', 'url')
    ]
    self.mock_swarming_service.create_utask_main_jobs.return_value = swarming_tasks
    mock_is_swarming_applicable.return_value = True
    mock_is_swarming_task.side_effect = (
        lambda job_type: job_type == 'swarming_job')

    gate = remote_task_gate.RemoteTaskGate()
    unscheduled_tasks = gate.create_utask_main_jobs(swarming_tasks)

    self.assertCountEqual(unscheduled_tasks, swarming_tasks)
    self.mock_k8s_service.create_utask_main_jobs.assert_not_called()

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_swarming_tasks_dont_try_on_other_services_when_feature_flag_disabled(
      self, mock_get_job_frequency, mock_is_swarming_task,
      mock_is_swarming_applicable):
    """Tests that when a swarming task is pulled, and the feature flag is
    disabled, we don't try to schedule it on other services."""
    swarming_tasks = [
        remote_task_types.RemoteTask('swarming_cmd', 'swarming_job', 'url'),
        remote_task_types.RemoteTask('swarming_cmd', 'swarming_job', 'url')
    ]
    k8s_task = remote_task_types.RemoteTask('k8s_cmd', 'k8s_job', 'url')
    tasks = swarming_tasks + [k8s_task]
    mock_is_swarming_applicable.return_value = False
    mock_is_swarming_task.side_effect = (
        lambda job_type: job_type == 'swarming_job')
    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    unscheduled_tasks = gate.create_utask_main_jobs(tasks)

    self.assertCountEqual(unscheduled_tasks, swarming_tasks)
    self.mock_swarming_service.create_utask_main_jobs.assert_not_called()
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [k8s_task])

  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_applicable')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, '_is_swarming_task')
  @mock.patch.object(remote_task_gate.RemoteTaskGate, 'get_job_frequency')
  def test_swarming_service_only_recieves_swarming_tasks(
      self, mock_get_job_frequency, mock_is_swarming_task,
      mock_is_swarming_applicable):
    """Tests that the gate filters non swarming task so that the swarming
    service only receives swarming tasks."""
    swarming_tasks = [
        remote_task_types.RemoteTask('swarming_cmd', 'swarming_job', 'url'),
        remote_task_types.RemoteTask('swarming_cmd', 'swarming_job', 'url')
    ]
    k8s_task = remote_task_types.RemoteTask('k8s_cmd', 'k8s_job', 'url')
    tasks = swarming_tasks + [k8s_task]
    mock_is_swarming_applicable.return_value = True
    mock_is_swarming_task.side_effect = (
        lambda job_type: job_type == 'swarming_job')
    mock_get_job_frequency.return_value = {
        'kubernetes': 1.0,
        'gcp_batch': 0.0,
        'swarming': 0.0
    }

    gate = remote_task_gate.RemoteTaskGate()
    unscheduled_tasks = gate.create_utask_main_jobs(tasks)

    self.assertCountEqual(unscheduled_tasks, [])
    self.mock_k8s_service.create_utask_main_jobs.assert_called_once_with(
        [k8s_task])
    self.mock_swarming_service.create_utask_main_jobs.assert_called_once_with(
        swarming_tasks)


class RemoteTaskGateProcessingTest(unittest.TestCase):
  """Tests for logic in RemoteTaskGate that doesn't require full service mocking."""

  def setUp(self):
    super().setUp()
    self.mock_swarming_service = mock.Mock(spec=SwarmingService)
    # Mock adapters to avoid real service instantiation
    self.patcher = mock.patch.dict(
        remote_task_adapters.RemoteTaskAdapters._member_map_, {
            'KUBERNETES':
                mock.Mock(
                    id='kubernetes',
                    service=mock.Mock(),
                    feature_flag=mock.Mock(enabled=True),
                    default_weight=0.0),
            'GCP_BATCH':
                mock.Mock(
                    id='gcp_batch',
                    service=mock.Mock(),
                    feature_flag=mock.Mock(enabled=True),
                    default_weight=1.0),
            'SWARMING':
                mock.Mock(
                    id='swarming',
                    service=mock.Mock(return_value=self.mock_swarming_service),
                    feature_flag=mock.Mock(enabled=True),
                    default_weight=0.0),
        })
    self.patcher.start()
    self.addCleanup(self.patcher.stop)
    self.gate = remote_task_gate.RemoteTaskGate()

  @mock.patch(
      'clusterfuzz._internal.base.feature_flags.FeatureFlags.enabled',
      new_callable=mock.PropertyMock)
  def test_is_swarming_applicable(self, mock_swarming_flag):
    """Tests _is_swarming_applicable."""
    mock_swarming_flag.return_value = True
    self.assertTrue(self.gate._is_swarming_applicable())

    mock_swarming_flag.return_value = False
    self.assertFalse(self.gate._is_swarming_applicable())

  @mock.patch('clusterfuzz._internal.remote_task.remote_task_gate.swarming')
  def test_is_swarming_task(self, mock_swarming):
    """Tests _is_swarming_task."""
    mock_swarming.is_swarming_task.return_value = True

    self.assertTrue(self.gate._is_swarming_task('job'))
    mock_swarming.is_swarming_task.assert_called_once_with(
        'job', ignore_feature_flag=True)

  def test_handle_swarming_job(self):
    """Tests _handle_swarming_job."""
    self.gate._handle_swarming_job('module', 'job', 'url')
    self.mock_swarming_service.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')

  def test_handle_swarming_jobs(self):
    """Tests _handle_swarming_jobs."""
    tasks = [mock.Mock()]
    self.gate._handle_swarming_jobs(tasks)
    self.mock_swarming_service.create_utask_main_jobs.assert_called_once_with(
        tasks)

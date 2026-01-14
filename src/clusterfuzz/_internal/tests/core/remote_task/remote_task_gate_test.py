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

from clusterfuzz._internal import remote_task


@mock.patch('clusterfuzz._internal.k8s.service.KubernetesService')
@mock.patch('clusterfuzz._internal.batch.service.GcpBatchService')
class RemoteTaskGateTest(unittest.TestCase):
  """Tests for the RemoteTaskGate class."""

  def test_init(self, mock_gcp_batch_service, mock_kubernetes_service):
    """Tests that the RemoteTaskGate initializes correctly."""
    remote_task.RemoteTaskGate()
    mock_gcp_batch_service.assert_called_once()
    mock_kubernetes_service.assert_called_once()

  @mock.patch.object(remote_task.RemoteTaskGate, '_should_use_kubernetes')
  def test_create_uworker_main_batch_job_kubernetes(
      self, mock_should_use_kubernetes, mock_gcp_batch_service,
      mock_kubernetes_service):
    """
    Tests that create_utask_main_job calls the Kubernetes service
    when _should_use_kubernetes returns True.
    """
    mock_should_use_kubernetes.return_value = True
    gate = remote_task.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')
    mock_kubernetes_service.return_value.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')
    mock_gcp_batch_service.return_value.create_utask_main_job.assert_not_called(
    )

  @mock.patch.object(remote_task.RemoteTaskGate, '_should_use_kubernetes')
  def test_create_uworker_main_batch_job_gcp_batch(
      self, mock_should_use_kubernetes, mock_gcp_batch_service,
      mock_kubernetes_service):
    """
    Tests that create_utask_main_job calls the GCP Batch service
    when _should_use_kubernetes returns False.
    """
    mock_should_use_kubernetes.return_value = False
    gate = remote_task.RemoteTaskGate()
    gate.create_utask_main_job('module', 'job', 'url')
    mock_gcp_batch_service.return_value.create_utask_main_job.assert_called_once_with(
        'module', 'job', 'url')
    mock_kubernetes_service.return_value.create_utask_main_job.assert_not_called(
    )

  @mock.patch(
      'clusterfuzz._internal.remote_task.job_frequency.get_job_frequency')
  @mock.patch('random.random')
  def test_should_use_kubernetes(self, mock_random, mock_get_job_frequency,
                                 mock_gcp_batch_service,
                                 mock_kubernetes_service):
    """
    Tests that _should_use_kubernetes returns the correct value based on
    the configured frequency and a random roll.
    """
    mock_get_job_frequency.return_value = {'kubernetes': 0.5}
    gate = remote_task.RemoteTaskGate()

    mock_random.return_value = 0.4
    self.assertTrue(gate._should_use_kubernetes())

    mock_random.return_value = 0.6
    self.assertFalse(gate._should_use_kubernetes())

  @mock.patch.object(remote_task.RemoteTaskGate, '_should_use_kubernetes')
  def test_create_uworker_main_batch_jobs(self, mock_should_use_kubernetes,
                                          mock_gcp_batch_service,
                                          mock_kubernetes_service):
    """
    Tests that create_utask_main_jobs correctly routes a single task
    based on _should_use_kubernetes.
    """
    tasks = [
        remote_task.RemoteTask('command1', 'job1', 'url1'),
    ]
    mock_should_use_kubernetes.return_value = True
    gate = remote_task.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    mock_kubernetes_service.return_value.create_utask_main_jobs.assert_called_once(
    )
    k8s_call_args = mock_kubernetes_service.return_value.create_utask_main_jobs.call_args[
        0][0]
    self.assertEqual(len(k8s_call_args), 1)
    self.assertIn(tasks[0], k8s_call_args)

    mock_gcp_batch_service.return_value.create_utask_main_jobs.assert_not_called(
    )

  @mock.patch(
      'clusterfuzz._internal.remote_task.job_frequency.get_job_frequency')
  def test_create_uworker_main_batch_jobs_slicing(self, mock_get_job_frequency,
                                                  mock_gcp_batch_service,
                                                  mock_kubernetes_service):
    """
    Tests that create_utask_main_jobs correctly routes tasks using
    deterministic slicing when tasks share the same job type.
    """
    # 4 tasks with same job type
    tasks = [
        remote_task.RemoteTask('command', 'job1', 'url1'),
        remote_task.RemoteTask('command', 'job1', 'url2'),
        remote_task.RemoteTask('command', 'job1', 'url3'),
        remote_task.RemoteTask('command', 'job1', 'url4'),
    ]

    # 50% split
    mock_get_job_frequency.return_value = {'kubernetes': 0.5, 'gcp_batch': 0.5}

    gate = remote_task.RemoteTaskGate()
    gate.create_utask_main_jobs(tasks)

    # 4 * 0.5 = 2 tasks for k8s.
    # The code takes the first chunk for k8s.

    mock_kubernetes_service.return_value.create_utask_main_jobs.assert_called_once(
    )
    k8s_call_args = mock_kubernetes_service.return_value.create_utask_main_jobs.call_args[
        0][0]
    self.assertEqual(len(k8s_call_args), 2)
    self.assertEqual(k8s_call_args, tasks[:2])

    mock_gcp_batch_service.return_value.create_utask_main_jobs.assert_called_once(
    )
    batch_call_args = mock_gcp_batch_service.return_value.create_utask_main_jobs.call_args[
        0][0]
    self.assertEqual(len(batch_call_args), 2)
    self.assertEqual(batch_call_args, tasks[2:])

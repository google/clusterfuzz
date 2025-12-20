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

from clusterfuzz._internal.remote_task import RemoteTask
from clusterfuzz._internal.remote_task import RemoteTaskGate


@mock.patch('clusterfuzz._internal.k8s.service.KubernetesService')
@mock.patch('clusterfuzz._internal.batch.service.GcpBatchService')
class RemoteTaskGateTest(unittest.TestCase):
  """Tests for the RemoteTaskGate class."""

  def test_init(self, mock_gcp_batch_service, mock_kubernetes_service):
    """Tests that the RemoteTaskGate initializes correctly."""
    RemoteTaskGate()
    mock_gcp_batch_service.assert_called_once()
    mock_kubernetes_service.assert_called_once()

  @mock.patch.object(RemoteTaskGate, '_should_use_kubernetes')
  def test_create_uworker_main_batch_job_kubernetes(
      self, mock_should_use_kubernetes, mock_gcp_batch_service,
      mock_kubernetes_service):
    """
    Tests that create_uworker_main_batch_job calls the Kubernetes service
    when _should_use_kubernetes returns True.
    """
    mock_should_use_kubernetes.return_value = True
    gate = RemoteTaskGate()
    gate.create_uworker_main_batch_job('module', 'job', 'url')
    mock_kubernetes_service.return_value.create_uworker_main_batch_job.assert_called_once_with(
        'module', 'job', 'url')
    mock_gcp_batch_service.return_value.create_uworker_main_batch_job.assert_not_called(
    )

  @mock.patch.object(RemoteTaskGate, '_should_use_kubernetes')
  def test_create_uworker_main_batch_job_gcp_batch(
      self, mock_should_use_kubernetes, mock_gcp_batch_service,
      mock_kubernetes_service):
    """
    Tests that create_uworker_main_batch_job calls the GCP Batch service
    when _should_use_kubernetes returns False.
    """
    mock_should_use_kubernetes.return_value = False
    gate = RemoteTaskGate()
    gate.create_uworker_main_batch_job('module', 'job', 'url')
    mock_gcp_batch_service.return_value.create_uworker_main_batch_job.assert_called_once_with(
        'module', 'job', 'url')
    mock_kubernetes_service.return_value.create_uworker_main_batch_job.assert_not_called(
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
    gate = RemoteTaskGate()

    mock_random.return_value = 0.4
    self.assertTrue(gate._should_use_kubernetes('job'))

    mock_random.return_value = 0.6
    self.assertFalse(gate._should_use_kubernetes('job'))

  @mock.patch.object(RemoteTaskGate, '_should_use_kubernetes')
  def test_create_uworker_main_batch_jobs(self, mock_should_use_kubernetes,
                                          mock_gcp_batch_service,
                                          mock_kubernetes_service):
    """
    Tests that create_uworker_main_batch_jobs correctly routes tasks to
    the appropriate service.
    """
    tasks = [
        RemoteTask('command1', 'job1', 'url1'),
        RemoteTask('command2', 'job2', 'url2'),
        RemoteTask('command3', 'job3', 'url3'),
    ]
    mock_should_use_kubernetes.side_effect = [True, False, True]
    gate = RemoteTaskGate()
    gate.create_uworker_main_batch_jobs(tasks)
    mock_kubernetes_service.return_value.create_uworker_main_batch_jobs.assert_called_once_with(
        [tasks[0], tasks[2]])
    mock_gcp_batch_service.return_value.create_uworker_main_batch_jobs.assert_called_once_with(
        [tasks[1]])

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
"""Tests for remote_task."""

import unittest
from unittest import mock

from clusterfuzz._internal.k8s import service as k8s_service
from clusterfuzz._internal.remote_task import RemoteTask
from clusterfuzz._internal.remote_task import RemoteTaskGate
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class RemoteTaskGateTest(unittest.TestCase):
  """Tests for RemoteTaskGate."""

  def setUp(self):
    self.gate = RemoteTaskGate()

  @mock.patch(
      'clusterfuzz._internal.remote_task.job_frequency.get_job_frequency')
  @mock.patch.object(k8s_service.KubernetesService,
                     'create_uworker_main_batch_jobs')
  @mock.patch(
      'clusterfuzz._internal.batch.service.GcpBatchService.create_uworker_main_batch_jobs'
  )
  def test_create_uworker_main_batch_jobs_k8s_limit_reached(
      self, mock_gcp_create, mock_k8s_create, mock_get_frequency):
    """Test delegation when K8s limit is reached (handled by service)."""
    # Setup tasks to go to Kubernetes
    mock_get_frequency.return_value = {'kubernetes': 1.0}

    task = RemoteTask('fuzz', 'job1', 'url1')

    # Simulate K8s service returning empty list (limit reached)
    mock_k8s_create.return_value = []

    result = self.gate.create_uworker_main_batch_jobs([task])

    # Verify K8s was attempted
    self.assertTrue(mock_k8s_create.called)

    # Verify GCP was NOT attempted
    self.assertFalse(mock_gcp_create.called)

    # Verify result is empty list
    self.assertEqual(result, [])

  @mock.patch(
      'clusterfuzz._internal.remote_task.job_frequency.get_job_frequency')
  @mock.patch.object(k8s_service.KubernetesService,
                     'create_uworker_main_batch_jobs')
  @mock.patch(
      'clusterfuzz._internal.batch.service.GcpBatchService.create_uworker_main_batch_jobs'
  )
  def test_create_uworker_main_batch_jobs_success(
      self, mock_gcp_create, mock_k8s_create, mock_get_frequency):
    """Test successful creation."""
    mock_get_frequency.return_value = {'kubernetes': 1.0}
    mock_pubsub_task = mock.Mock()
    mock_pubsub_task.do_not_ack = False
    task = RemoteTask('fuzz', 'job1', 'url1', pubsub_task=mock_pubsub_task)

    self.gate.create_uworker_main_batch_jobs([task])

    self.assertTrue(mock_k8s_create.called)
    self.assertFalse(mock_pubsub_task.do_not_ack)

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
"""Tests for the Kubernetes batch client limit logic."""

import unittest
from unittest import mock

from clusterfuzz._internal.k8s import service
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
@mock.patch('kubernetes.config.load_kube_config')
class KubernetesServiceLimitTest(unittest.TestCase):
  """Tests for the KubernetesService limit logic."""

  def setUp(self):
    patcher = mock.patch(
        'clusterfuzz._internal.k8s.service.KubernetesService._load_gke_credentials'
    )
    self.addCleanup(patcher.stop)
    self.mock_load_gke = patcher.start()

    # Create a job to prevent KeyError in _get_k8s_job_configs
    from clusterfuzz._internal.datastore import data_types
    data_types.Job(name='job1', platform='LINUX').put()

  @mock.patch.object(service.KubernetesService, '_get_pending_jobs_count')
  def test_create_uworker_main_batch_jobs_limit_not_reached(
      self, mock_get_pending_count, _):
    """Tests that create_uworker_main_batch_jobs proceeds when limit not reached."""
    mock_get_pending_count.return_value = 99
    kube_service = service.KubernetesService()

    # We expect this to proceed to job creation logic (which we mock to avoid actual creation)
    with mock.patch.object(service.KubernetesService,
                           'create_kata_container_job') as mock_create:
      kube_service.create_uworker_main_batch_jobs(
          [service.RemoteTask('fuzz', 'job1', 'url1')])
      self.assertTrue(mock_create.called)

  @mock.patch.object(service.KubernetesService, '_get_pending_jobs_count')
  def test_create_uworker_main_batch_jobs_limit_reached(
      self, mock_get_pending_count, _):
    """Tests that create_uworker_main_batch_jobs nacks tasks when limit reached."""
    mock_get_pending_count.return_value = service.MAX_PENDING_JOBS
    kube_service = service.KubernetesService()

    mock_pubsub_task = mock.Mock()
    mock_pubsub_task.do_not_ack = False
    task = service.RemoteTask(
        'fuzz', 'job1', 'url1', pubsub_task=mock_pubsub_task)

    result = kube_service.create_uworker_main_batch_jobs([task])

    self.assertEqual(result, [])
    self.assertTrue(mock_pubsub_task.do_not_ack)

  @mock.patch.object(service.KubernetesService, '_get_pending_jobs_count')
  def test_create_uworker_main_batch_jobs_limit_exceeded(
      self, mock_get_pending_count, _):
    """Tests that create_uworker_main_batch_jobs nacks tasks when limit exceeded."""
    mock_get_pending_count.return_value = service.MAX_PENDING_JOBS + 1
    kube_service = service.KubernetesService()

    mock_pubsub_task = mock.Mock()
    mock_pubsub_task.do_not_ack = False
    task = service.RemoteTask(
        'fuzz', 'job1', 'url1', pubsub_task=mock_pubsub_task)

    result = kube_service.create_uworker_main_batch_jobs([task])

    self.assertEqual(result, [])
    self.assertTrue(mock_pubsub_task.do_not_ack)

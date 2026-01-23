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
"""End-to-end tests for the Kubernetes service."""

# pylint: disable=unused-argument

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.k8s import service as kubernetes_service
from clusterfuzz._internal.k8s.service import KubernetesJobConfig
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class KubernetesServiceE2ETest(unittest.TestCase):
  """End-to-end tests for the Kubernetes service."""

  @classmethod
  def setUpClass(cls):
    """Set up the test environment."""
    if not os.getenv('K8S_E2E'):
      raise unittest.SkipTest('K8S_E2E environment variable not set.')

    cls.cluster_name = 'test-cluster-for-e2e-test'
    cls.image = 'gcr.io/clusterfuzz-images/base:000dc1f-202511191429'

    # Find `kind` executable.
    cls.kind_path = (
        shutil.which('kind') or os.path.expanduser('~/.local/bin/kind'))
    if not cls.kind_path or not os.path.exists(cls.kind_path):
      raise unittest.SkipTest('kind executable not found.')

    # Ensure no old cluster exists and create a new one.
    subprocess.run(
        [cls.kind_path, 'delete', 'cluster', '--name', cls.cluster_name],
        check=False)
    subprocess.run(
        [cls.kind_path, 'create', 'cluster', '--name', cls.cluster_name],
        check=True)

    # Get kubeconfig and load it.
    kubeconfig = subprocess.check_output(
        [cls.kind_path, 'get', 'kubeconfig', '--name',
         cls.cluster_name]).decode('utf-8')

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
      f.write(kubeconfig)
      cls.kubeconfig_path = f.name
    k8s_config.load_kube_config(config_file=cls.kubeconfig_path)

    cls.api_client = k8s_client.BatchV1Api()
    cls.kubernetes_client = kubernetes_service.KubernetesService(
        k8s_config_loaded=True)

    # Setup dummy jobs in datastore.
    data_types.Job(name='test-job', platform='LINUX').put()
    data_types.Job(name='test-job1', platform='LINUX').put()
    data_types.Job(name='test-job2', platform='LINUX').put()

  @classmethod
  def tearDownClass(cls):
    """Tear down the test environment."""
    if hasattr(cls, 'kubeconfig_path') and os.path.exists(cls.kubeconfig_path):
      os.remove(cls.kubeconfig_path)
    if hasattr(cls, 'kind_path') and cls.kind_path:
      subprocess.run(
          [cls.kind_path, 'delete', 'cluster', '--name', cls.cluster_name],
          check=True)

  def _wait_for_job_and_delete(self, job_name):
    """Waits for a job to start running and then deletes it."""
    # Wait for the job to be created in the API.
    time.sleep(2)

    # Wait for the job to start running (at least one active pod).
    job_running = False
    for _ in range(60):
      job = self.api_client.read_namespaced_job(job_name, 'default')
      if job.status.active or job.status.succeeded:
        job_running = True
        break
      time.sleep(1)

    self.assertTrue(
        job_running,
        f'Job {job_name} did not start running. Status: {job.status}')

    # Cleanup.
    self.api_client.delete_namespaced_job(
        name=job_name,
        namespace='default',
        body=k8s_client.V1DeleteOptions(propagation_policy='Foreground'))

  def test_create_job(self):
    """Tests creating a job."""
    config = KubernetesJobConfig(
        job_type='test-job',
        docker_image=self.image,
        command='fuzz',
        disk_size_gb=10,
        service_account_email='test-email',
        clusterfuzz_release='prod',
        is_kata=False)
    actual_job_name = self.kubernetes_client.create_job(config, 'url')
    self._wait_for_job_and_delete(actual_job_name)

  @mock.patch('clusterfuzz._internal.k8s.service._get_k8s_job_configs')
  @mock.patch(
      'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module')
  def test_create_uworker_main_batch_job(self, mock_get_command_from_module,
                                         mock_get_k8s_job_configs):
    """Tests creating a single uworker main batch job."""
    mock_get_command_from_module.return_value = 'fuzz'
    config = KubernetesJobConfig(
        job_type='test-job',
        docker_image=self.image,
        command='fuzz',
        disk_size_gb=10,
        service_account_email='test-email',
        clusterfuzz_release='prod',
        is_kata=False)
    mock_get_k8s_job_configs.return_value = {('fuzz', 'test-job'): config}

    actual_job_name = self.kubernetes_client.create_utask_main_job(
        'module', 'test-job', 'url1')
    self._wait_for_job_and_delete(actual_job_name)

  @mock.patch('clusterfuzz._internal.k8s.service._get_k8s_job_configs')
  @mock.patch(
      'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module')
  def test_create_uworker_main_batch_jobs(self, mock_get_command_from_module,
                                          mock_get_k8s_job_configs):
    """Tests creating multiple uworker main batch jobs."""
    mock_get_command_from_module.return_value = 'fuzz'
    config1 = KubernetesJobConfig(
        job_type='test-job1',
        docker_image=self.image,
        command='fuzz',
        disk_size_gb=10,
        service_account_email='test-email',
        clusterfuzz_release='prod',
        is_kata=False)
    config2 = KubernetesJobConfig(
        job_type='test-job2',
        docker_image=self.image,
        command='fuzz',
        disk_size_gb=20,
        service_account_email='test-email',
        clusterfuzz_release='prod',
        is_kata=False)

    mock_get_k8s_job_configs.return_value = {
        ('fuzz', 'test-job1'): config1,
        ('fuzz', 'test-job2'): config2
    }

    tasks = [
        remote_task_types.RemoteTask('fuzz', 'test-job1', 'url1'),
        remote_task_types.RemoteTask('fuzz', 'test-job2', 'url2'),
    ]

    actual_job_names = self.kubernetes_client.create_utask_main_jobs(tasks)
    self.assertEqual(len(actual_job_names), 2)

    for job_name in actual_job_names:
      self._wait_for_job_and_delete(job_name)


if __name__ == '__main__':
  unittest.main()

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
from clusterfuzz._internal.remote_task import types
from clusterfuzz._internal.tests.test_libs import test_utils


@mock.patch(
    'clusterfuzz._internal.metrics.logs.get_logging_config_dict',
    return_value={
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'simpleFormatter': {
                'format': '%(levelname)s:%(module)s:%(lineno)d:%(message)s'
            }
        },
        'handlers': {
            'consoleHandler': {
                'class': 'logging.StreamHandler',
                'formatter': 'simpleFormatter'
            }
        },
        'loggers': {
            'root': {
                'handlers': ['consoleHandler'],
                'level': 'INFO'
            }
        }
    })
@test_utils.with_cloud_emulators('datastore')
class KubernetesServiceE2ETest(unittest.TestCase):
  """End-to-end tests for the Kubernetes service."""

  @classmethod
  def setUpClass(cls):
    """Set up the test environment."""
    if not os.getenv('K8S_E2E'):
      raise unittest.SkipTest('K8S_E2E environment variable not set.')

    cls.mock_batch_config = mock.Mock()
    cls.mock_batch_config.get.return_value = 'test-project'

    def get_batch_config(key):
      return {
          'project': 'test-project',
          'mapping': {
              'LINUX-PREEMPTIBLE-UNPRIVILEGED': {
                  'clusterfuzz_release': 'prod',
                  'docker_image': cls.image,
                  'user_data': 'file://linux-init.yaml',
                  'disk_size_gb': 10,
                  'disk_type': 'pd-standard',
                  'service_account_email': 'test-email',
                  'preemptible': True,
                  'machine_type': 'machine-type',
                  'subconfigs': [{
                      'name': 'subconfig1',
                      'weight': 1
                  }]
              },
              'LINUX-NONPREEMPTIBLE-UNPRIVILEGED': {
                  'clusterfuzz_release': 'prod',
                  'docker_image': cls.image,
                  'user_data': 'file://linux-init.yaml',
                  'disk_size_gb': 20,
                  'disk_type': 'pd-standard',
                  'service_account_email': 'test-email',
                  'preemptible': False,
                  'machine_type': 'machine-type',
                  'subconfigs': [{
                      'name': 'subconfig1',
                      'weight': 1
                  }]
              }
          },
          'subconfigs': {
              'subconfig1': {
                  'region': 'region',
                  'network': 'network',
                  'subnetwork': 'subnetwork'
              }
          }
      }.get(key)

    cls.mock_batch_config.get.side_effect = get_batch_config

    cls.mock_local_config = mock.Mock()
    cls.mock_local_config.BatchConfig.return_value = cls.mock_batch_config

    with mock.patch(
        'clusterfuzz._internal.config.local_config', new=cls.mock_local_config):
      cls.cluster_name = 'test-cluster-for-e2e-test'
      cls.image = 'gcr.io/clusterfuzz-images/base:000dc1f-202511191429'

      # First, try to find `kind` in the user's local bin directory.
      home_dir = os.path.expanduser('~')
      local_kind_path = os.path.join(home_dir, '.local', 'bin', 'kind')

      if os.path.exists(local_kind_path):
        cls.kind_path = local_kind_path
      else:
        # Fallback to searching the PATH.
        cls.kind_path = shutil.which('kind')

      # Ensure no old cluster exists.
      subprocess.run(
          [cls.kind_path, 'delete', 'cluster', '--name', cls.cluster_name],
          check=False)

      subprocess.run(
          [cls.kind_path, 'create', 'cluster', '--name', cls.cluster_name],
          check=True)

      # Explicitly get the kubeconfig from the kind cluster.
      kubeconfig = subprocess.check_output(
          [cls.kind_path, 'get', 'kubeconfig', '--name',
           cls.cluster_name]).decode('utf-8')

      # Write the kubeconfig to a temporary file and load it.
      with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(kubeconfig)
        cls.kubeconfig_path = f.name
      k8s_config.load_kube_config(config_file=cls.kubeconfig_path)
      cls.api_client = k8s_client.BatchV1Api()

    cls.kubernetes_client = kubernetes_service.KubernetesService(
        k8s_config_loaded=True)
    data_types.Job(name='test-job', platform='LINUX').put()
    data_types.Job(name='test-job1', platform='LINUX').put()
    data_types.Job(name='test-job2', platform='LINUX').put()

    cls.mock_get_config_names = mock.Mock(
        return_value={
            ('fuzz', 'test-job'): ('LINUX-PREEMPTIBLE-UNPRIVILEGED', 10, None),
            ('fuzz', 'test-job1'): ('LINUX-PREEMPTIBLE-UNPRIVILEGED', 10, None),
            ('fuzz', 'test-job2'): ('LINUX-NONPREEMPTIBLE-UNPRIVILEGED', 20,
                                    None),
        })
    cls.mock_get_config_names_patcher = mock.patch(
        'clusterfuzz._internal.batch.service._get_config_names',
        new=cls.mock_get_config_names)
    cls.mock_get_config_names_patcher.start()

  @classmethod
  def tearDownClass(cls):
    """Tear down the test environment."""
    os.remove(cls.kubeconfig_path)
    subprocess.run(
        [cls.kind_path, 'delete', 'cluster', '--name', cls.cluster_name],
        check=True)
    cls.mock_get_config_names_patcher.stop()

  def test_create_job(self, mock_get_logging_config_dict):
    """Tests creating a job."""
    input_url = 'url'
    task = types.RemoteTask(None, 'test-job', None)
    task.docker_image = self.image

    config = KubernetesJobConfig(
        job_type='test-job',
        docker_image=self.image,
        command=task.command,
        disk_size_gb=10,
        service_account_email='test-email',
        clusterfuzz_release='prod',
        is_kata=False)
    actual_job_name = self.kubernetes_client.create_job(config, input_url)

    # Wait for the job to be created.
    time.sleep(5)

    job = self.api_client.read_namespaced_job(actual_job_name, 'default')
    self.assertIsNotNone(job)
    self.assertEqual(job.metadata.name, actual_job_name)

    # Check for sidecar container and volume.
    pod_spec = job.spec.template.spec
    containers = pod_spec.containers
    container_names = [c.name for c in containers]
    self.assertIn('cpu-monitor', container_names)

    # Find the cpu-monitor container.
    monitor_container = next(c for c in containers if c.name == 'cpu-monitor')
    self.assertEqual(monitor_container.image, 'busybox')

    # Check volume mounts for main container.
    main_container = next(c for c in containers if c.name == actual_job_name)
    mount_paths = [m.mount_path for m in main_container.volume_mounts]
    self.assertIn('/etc/cpu-usage', mount_paths)

    # Check volumes.
    volume_names = [v.name for v in pod_spec.volumes]
    self.assertIn('cpu-usage', volume_names)

    # Wait for the job to start running.
    job_running = False
    for _ in range(180):
      job = self.api_client.read_namespaced_job(actual_job_name, 'default')
      if job.status.active or job.status.succeeded:
        job_running = True
        break
      time.sleep(1)

    self.assertTrue(
        job_running,
        f"Job {actual_job_name} did not start running. Status: {job.status}")

    self.api_client.delete_namespaced_job(
        name=actual_job_name,
        namespace='default',
        body=k8s_client.V1DeleteOptions(propagation_policy='Foreground'))

  @unittest.skip('Should be implemented against a cluster that supports kata')
  def test_create_kata_container_job(self, mock_get_logging_config_dict):
    """Tests creating a Kata container job."""
    input_urls = []
    actual_job_name = self.kubernetes_client.create_kata_container_job(
        self.image, input_urls)

    # Wait for the job to be created.
    time.sleep(5)

    job = self.api_client.read_namespaced_job(actual_job_name, 'default')
    self.assertIsNotNone(job)
    self.assertEqual(job.metadata.name, actual_job_name)
    self.assertEqual(job.spec.template.spec.runtime_class_name, 'kata')

    # Check for sidecar container and volume.
    pod_spec = job.spec.template.spec
    containers = pod_spec.containers
    container_names = [c.name for c in containers]
    self.assertIn('cpu-monitor', container_names)

    # Find the cpu-monitor container.
    monitor_container = next(c for c in containers if c.name == 'cpu-monitor')
    self.assertEqual(monitor_container.image, 'busybox')

    # Check volumes.
    volume_names = [v.name for v in pod_spec.volumes]
    self.assertIn('cpu-usage', volume_names)

    # Wait for the job to start running.
    job_running = False
    for _ in range(180):
      job = self.api_client.read_namespaced_job(actual_job_name, 'default')
      if job.status.active or job.status.succeeded:
        job_running = True
        break
      time.sleep(1)

    self.assertTrue(
        job_running,
        f"Kata Job {actual_job_name} did not start running. Status: {job.status}"
    )

    self.api_client.delete_namespaced_job(
        name=actual_job_name,
        namespace='default',
        body=k8s_client.V1DeleteOptions(propagation_policy='Foreground'))

  @mock.patch('clusterfuzz._internal.k8s.service._get_k8s_job_configs')
  @mock.patch(
      'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module')
  def test_create_uworker_main_batch_job(self, mock_get_command_from_module,
                                         mock_get_k8s_job_configs,
                                         mock_get_logging_config_dict):
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

    actual_job_name = \
        self.kubernetes_client.create_utask_main_job(
            'module', 'test-job', 'url1')

    # Wait for the job to be created.
    time.sleep(5)

    job = self.api_client.read_namespaced_job(actual_job_name, 'default')
    self.assertIsNotNone(job)
    self.assertEqual(job.metadata.name, actual_job_name)

    # Wait for the job to start running.
    job_running = False
    for _ in range(180):
      job = self.api_client.read_namespaced_job(actual_job_name, 'default')
      if job.status.active or job.status.succeeded:
        job_running = True
        break
      time.sleep(1)

    self.assertTrue(
        job_running,
        f"Job {actual_job_name} did not start running. Status: {job.status}")

    self.api_client.delete_namespaced_job(
        name=actual_job_name,
        namespace='default',
        body=k8s_client.V1DeleteOptions(propagation_policy='Foreground'))

  @mock.patch('clusterfuzz._internal.k8s.service._get_k8s_job_configs')
  @mock.patch(
      'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module')
  def test_create_uworker_main_batch_jobs(self, mock_get_command_from_module,
                                          mock_get_k8s_job_configs,
                                          mock_get_logging_config_dict):
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
        docker_image='different-image',
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
        types.RemoteTask('fuzz', 'test-job1', 'url1'),
        types.RemoteTask('fuzz', 'test-job2', 'url2'),
    ]

    actual_job_names = \
        self.kubernetes_client.create_utask_main_jobs(tasks)
    self.assertEqual(len(actual_job_names), 2)

    for job_name in actual_job_names:
      # Wait for the job to be created.
      time.sleep(5)

      job = self.api_client.read_namespaced_job(job_name, 'default')
      self.assertIsNotNone(job)
      self.assertEqual(job.metadata.name, job_name)

      # Wait for the job to start running.
      job_running = False
      for _ in range(180):
        job = self.api_client.read_namespaced_job(job_name, 'default')
        if job.status.active or job.status.succeeded:
          job_running = True
          break
        time.sleep(1)

      self.assertTrue(
          job_running,
          f"Job {job_name} did not start running. Status: {job.status}")

      self.api_client.delete_namespaced_job(
          name=job_name,
          namespace='default',
          body=k8s_client.V1DeleteOptions(propagation_policy='Foreground'))


if __name__ == '__main__':
  unittest.main()

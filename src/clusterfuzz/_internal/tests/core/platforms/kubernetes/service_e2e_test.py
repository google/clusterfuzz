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
import os
import subprocess
import tempfile
import time
import unittest

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
import yaml

from clusterfuzz._internal.platforms.kubernetes import service


class KubernetesServiceE2ETest(unittest.TestCase):
  """End-to-end tests for the Kubernetes service."""

  @classmethod
  def setUpClass(cls):
    """Set up the test environment."""
    cls.cluster_name = 'test-cluster-for-e2e-test'
    cls.image = 'gcr.io/clusterfuzz-images/base:000dc1f-202511191429'
    cls.job_spec = {
        'apiVersion': 'batch/v1',
        'kind': 'Job',
        'metadata': {
            'name': 'test-job'
        },
        'spec': {
            'template': {
                'spec': {
                    'containers': [{
                        'name': 'test-container',
                        'image': cls.image,
                        'command': ['echo', 'hello world']
                    }],
                    'restartPolicy': 'Never'
                }
            },
            'backoffLimit': 0
        }
    }

    home_dir = os.getenv('HOME')
    cls.kind_path = os.path.join(home_dir, '.local', 'bin', 'kind')

    # Ensure no old cluster exists.
    subprocess.run(
        [cls.kind_path, 'delete', 'cluster', '--name', cls.cluster_name])

    subprocess.run(
        [cls.kind_path, 'create', 'cluster', '--name', cls.cluster_name],
        check=True)

    # Explicitly get the kubeconfig from the kind cluster.
    kubeconfig = subprocess.check_output([
        cls.kind_path, 'get', 'kubeconfig', '--name', cls.cluster_name
    ]).decode('utf-8')

    # Write the kubeconfig to a temporary file and load it.
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
      f.write(kubeconfig)
      cls.kubeconfig_path = f.name
    k8s_config.load_kube_config(config_file=cls.kubeconfig_path)
    cls.api_client = k8s_client.BatchV1Api()

  @classmethod
  def tearDownClass(cls):
    """Tear down the test environment."""
    os.remove(cls.kubeconfig_path)
    subprocess.run(
        [cls.kind_path, 'delete', 'cluster', '--name', cls.cluster_name],
        check=True)

  def test_create_job(self):
    """Tests creating a job."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
      yaml.dump(self.job_spec, f)
      job_spec_file = f.name

    job_name = 'test-job'
    input_urls = []
    service.create_job(job_name, self.image, job_spec_file, input_urls)

    # Wait for the job to be created.
    time.sleep(5)

    job = self.api_client.read_namespaced_job(job_name, 'default')
    self.assertIsNotNone(job)
    self.assertEqual(job.metadata.name, job_name)

    # Wait for the job to complete.
    for _ in range(180):
      job = self.api_client.read_namespaced_job(job_name, 'default')
      if job.status.succeeded:
        break
      time.sleep(1)
    if job.status.succeeded is None:
      print("Job status after timeout:", job.status)
    self.assertEqual(job.status.succeeded, 1)

    self.api_client.delete_namespaced_job(
        name=job_name,
        namespace='default',
        body=k8s_client.V1DeleteOptions(propagation_policy='Foreground'))
    os.remove(job_spec_file)

if __name__ == '__main__':
  unittest.main()

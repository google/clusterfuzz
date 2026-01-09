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
"""Integration tests for KubernetesService."""

import base64
import os
import unittest
from unittest import mock

from kubernetes import client

from clusterfuzz._internal.k8s import service


class KubernetesIntegrationTest(unittest.TestCase):
  """Integration tests for KubernetesService."""

  @mock.patch('googleapiclient.discovery.build')
  def test_load_credentials(self, mock_discovery_build):
    """Test that credentials can be loaded manually using the fallback logic."""
    # Ensure no kubeconfig interferes to force manual path (if local kubeconfig exists)
    # Note: os.environ changes are process-local.
    old_kubeconfig = os.environ.get('KUBECONFIG')
    os.environ['KUBECONFIG'] = '/dev/null'

    # Mock GKE response
    mock_service = mock.Mock()
    mock_discovery_build.return_value = mock_service

    mock_clusters_list = mock_service.projects().locations().clusters().list(
    ).execute
    mock_clusters_list.return_value = {
        'clusters': [{
            'name': 'clusterfuzz-cronjobs-gke',
            'endpoint': '1.2.3.4',
            'masterAuth': {
                'clusterCaCertificate':
                    base64.b64encode(b'fake-cert').decode('utf-8')
            }
        }]
    }

    # Mock list_namespaced_job to avoid actual network call to 1.2.3.4
    with mock.patch('kubernetes.client.BatchV1Api.list_namespaced_job'):
      try:
        # This will trigger _load_gke_credentials
        # It should try load_kube_config (fail), load_incluster (fail), then manual.
        k8s_service = service.KubernetesService()

        # Verify api client is initialized
        self.assertIsNotNone(k8s_service._batch_api)
        self.assertIsInstance(k8s_service._batch_api, client.BatchV1Api)

        # Verify configuration
        config = client.Configuration.get_default_copy()
        print(f"Loaded Host: {config.host}")

        # Check that we got a valid https endpoint
        self.assertTrue(config.host.startswith("https://"))
        self.assertTrue(config.verify_ssl)
        self.assertIsNotNone(config.ssl_ca_cert)

        # Verify API key fix is present (Crucial for manual path)
        self.assertIn("authorization", config.api_key)

        # Verify hook is present
        self.assertIsNotNone(config.refresh_api_key_hook)

        # Verify actual connectivity and auth
        print("Attempting to list jobs to verify authentication...")
        k8s_service._batch_api.list_namespaced_job(namespace='default', limit=1)
        print("Successfully listed jobs.")

      finally:
        if old_kubeconfig:
          os.environ['KUBECONFIG'] = old_kubeconfig
        else:
          del os.environ['KUBECONFIG']


if __name__ == '__main__':
  unittest.main()

# Copyright 2026 Google LLC
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
"""Tests for KubernetesService credential loading."""

import os
import unittest
from unittest import mock

from clusterfuzz._internal.k8s import service
from clusterfuzz._internal.tests.test_libs import helpers


class KubernetesCredentialsTest(unittest.TestCase):
  """Tests for KubernetesService credential loading."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.get_value',
        'google.auth.default',
        'googleapiclient.discovery.build',
        'kubernetes.client.Configuration',
        'kubernetes.config.load_kube_config',
    ])
    self.mock.get_value.return_value = 'test-project'
    creds = mock.Mock()
    creds.token = 'test-token'
    self.mock.default.return_value = (creds, 'test-project')

    self.mock_discovery = self.mock.build.return_value
    self.mock_clusters = self.mock_discovery.projects.return_value.locations.return_value.clusters.return_value

    self.mock_config_instance = self.mock.Configuration.return_value

    os.environ['BOT_DIR'] = '/tmp'

  def test_load_gke_credentials_ip_endpoint(self):
    """Test loading credentials with an IP endpoint (should set ssl_ca_cert)."""
    self.mock_clusters.list.return_value.execute.return_value = {
        'clusters': [{
            'name': 'clusterfuzz-cronjobs-gke',
            'endpoint': '1.2.3.4',
            'masterAuth': {
                'clusterCaCertificate': 'dGVzdA=='  # base64 "test"
            }
        }]
    }

    # Bypass __init__ logic to call _load_gke_credentials directly
    with mock.patch.object(
        service.KubernetesService, '__init__', return_value=None):
      kube_service = service.KubernetesService()

    # pylint: disable=protected-access
    kube_service._load_gke_credentials()

    self.assertEqual(self.mock_config_instance.host, 'https://1.2.3.4')
    self.assertIsNotNone(self.mock_config_instance.ssl_ca_cert)
    self.assertTrue(self.mock_config_instance.verify_ssl)

  def test_load_gke_credentials_hostname_endpoint(self):
    """Test loading credentials with a hostname endpoint (should skip ssl_ca_cert)."""
    self.mock_clusters.list.return_value.execute.return_value = {
        'clusters': [{
            'name': 'clusterfuzz-cronjobs-gke',
            'endpoint': 'example.com',
            'masterAuth': {
                'clusterCaCertificate': 'dGVzdA=='
            }
        }]
    }

    # Bypass __init__ logic to call _load_gke_credentials directly
    with mock.patch.object(
        service.KubernetesService, '__init__', return_value=None):
      kube_service = service.KubernetesService()

    # Reset mock to ensure we capture the specific call
    self.mock_config_instance.ssl_ca_cert = None

    # pylint: disable=protected-access
    kube_service._load_gke_credentials()

    self.assertEqual(self.mock_config_instance.host, 'https://example.com')
    self.assertIsNone(self.mock_config_instance.ssl_ca_cert)
    self.assertTrue(self.mock_config_instance.verify_ssl)

# Copyright 2024 Google LLC
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
"""Tests for credentials."""
import unittest
from unittest import mock

from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.tests.test_libs import helpers


class CredentialsTest(unittest.TestCase):
  """Tests for credentials."""

  def setUp(self):
    helpers.patch(self, [
        'google.auth.default',
        'google.auth.impersonated_credentials.Credentials',
        'google.auth.transport.requests.Request',
    ])

  def test_get_target_service_account_credentials(self):
    """Tests get_target_service_account_credentials."""
    source_creds = mock.Mock()
    self.mock.default.return_value = (source_creds, 'project-id')

    target_creds = self.mock.Credentials.return_value
    
    result = credentials.get_target_service_account_credentials(
        'target@example.com', ['scope1'])

    self.mock.Credentials.assert_called_with(
        source_credentials=source_creds,
        target_principal='target@example.com',
        target_scopes=['scope1'])
    
    self.assertTrue(target_creds.refresh.called)
    self.assertEqual(result, target_creds)

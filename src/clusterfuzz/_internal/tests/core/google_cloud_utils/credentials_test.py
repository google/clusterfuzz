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
"""Tests for credentials helpers."""

import unittest
from unittest import mock

from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class GetServiceAccountEmailTest(unittest.TestCase):
  """Tests for get_service_account_email."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.compute_metadata.get',
        'clusterfuzz._internal.google_cloud_utils.credentials.get_default',
    ])

  def test_resolves_default_metadata_and_strips_whitespace(self):
    """Test resolving 'default' via metadata strips trailing newlines."""
    creds = mock.Mock(service_account_email='default')
    self.mock.get_default.return_value = (creds, 'project-id')
    self.mock.get.return_value = '123-compute@developer.gserviceaccount.com\n'

    self.assertEqual(credentials.get_service_account_email(),
                     '123-compute@developer.gserviceaccount.com')
    self.mock.get.assert_called_once_with(
        'instance/service-accounts/default/email')

  def test_whitespace_only_metadata_returns_none(self):
    """Test whitespace-only metadata response returns None."""
    creds = mock.Mock(service_account_email='default')
    self.mock.get_default.return_value = (creds, 'project-id')
    self.mock.get.return_value = '  \n '

    self.assertIsNone(credentials.get_service_account_email())

  def test_uses_provided_creds_without_calling_get_default(self):
    """Test passing creds avoids calling get_default again."""
    creds = mock.Mock(
        service_account_email='  sa@project.iam.gserviceaccount.com  ')

    self.assertEqual(
        credentials.get_service_account_email(creds=creds),
        'sa@project.iam.gserviceaccount.com')
    self.mock.get_default.assert_not_called()
    self.mock.get.assert_not_called()

  def test_missing_service_account_email_returns_none(self):
    """Test credentials without a service_account_email return None."""
    creds = object()
    self.assertIsNone(credentials.get_service_account_email(creds=creds))

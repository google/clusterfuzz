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
"""auth tests."""

import threading
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from libs import auth


@test_utils.with_cloud_emulators('datastore')
class AuthTest(unittest.TestCase):
  """Test auth module."""

  def setUp(self):
    test_helpers.patch(self, [
        ('auth_config_get',
         'clusterfuzz._internal.config.local_config.AuthConfig.get'),
        ('project_config_get',
         'clusterfuzz._internal.config.local_config.ProjectConfig.get'),
        'clusterfuzz._internal.system.environment.is_local_development',
        'libs.auth.decode_claims',
        'libs.auth.get_email_from_bearer_token',
        'libs.auth.get_iap_email',
        'libs.auth.get_session_cookie',
        'libs.request_cache.get_cache_backing',
        'libs.request_cache.get_current_request',
    ])
    self.mock.is_local_development.return_value = False
    self.mock.auth_config_get.return_value = False
    self.mock.project_config_get.return_value = ['google.com', 'github.com']
    self.mock.get_iap_email.return_value = None
    self.mock.get_email_from_bearer_token.return_value = None
    self.mock.get_cache_backing.return_value = threading.local()
    self.mock.get_session_cookie.return_value = 'session-cookie'

  def test_get_current_user_rejects_unverified_github_email(self):
    """Ensure unverified GitHub Firebase claims are rejected."""
    self.mock.decode_claims.return_value = {
        'email': 'admin@example.com',
        'email_verified': False,
        'firebase': {
            'sign_in_provider': 'github.com',
        },
    }
    self.assertIsNone(auth.get_current_user())

  def test_get_current_user_accepts_verified_github_email(self):
    """Ensure verified GitHub Firebase claims are accepted."""
    self.mock.decode_claims.return_value = {
        'email': 'user@example.com',
        'email_verified': True,
        'firebase': {
            'sign_in_provider': 'github.com',
        },
    }
    user = auth.get_current_user()
    self.assertIsNotNone(user)
    self.assertEqual(user.email, 'user@example.com')
    self.assertTrue(user.email_verified)

  def test_get_current_user_rejects_service_account_in_session_cookie(self):
    """Ensure service account emails are rejected in Firebase session cookies."""
    self.mock.decode_claims.return_value = {
        'email': 'service-1234@gcp-sa-monitoring.iam.gserviceaccount.com',
        'email_verified': True,
        'firebase': {
            'sign_in_provider': 'github.com',
        },
    }
    self.assertIsNone(auth.get_current_user())

  def test_is_current_user_admin_rejects_unverified_user(self):
    """Ensure is_current_user_admin returns False if user email is unverified."""
    data_types.Admin(id='admin@example.com', email='admin@example.com').put()
    test_helpers.patch(self, ['libs.auth.get_current_user'])
    self.mock.get_current_user.return_value = auth.User(
        'admin@example.com', email_verified=False)
    self.assertFalse(auth.is_current_user_admin())

  def test_is_current_user_admin_accepts_verified_admin(self):
    """Ensure is_current_user_admin returns True for a verified Admin."""
    data_types.Admin(id='admin@example.com', email='admin@example.com').put()
    test_helpers.patch(self, ['libs.auth.get_current_user'])
    self.mock.get_current_user.return_value = auth.User(
        'admin@example.com', email_verified=True)
    self.assertTrue(auth.is_current_user_admin())

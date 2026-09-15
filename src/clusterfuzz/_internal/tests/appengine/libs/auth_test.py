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
"""Tests for get_email_from_bearer_token."""

import unittest
import unittest.mock

import flask

from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from libs import auth
from libs import helpers


class GetEmailFromBearerTokenTest(unittest.TestCase):
  """Tests for get_email_from_bearer_token."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.service_account_email',
        'google.oauth2.id_token.verify_oauth2_token',
    ])
    self.mock.service_account_email.return_value = (
        'test-clusterfuzz@appspot.gserviceaccount.com')
    self.mock.verify_oauth2_token.return_value = {
        'email_verified': True,
        'email': 'test-clusterfuzz@appspot.gserviceaccount.com',
    }

    self.app = flask.Flask('testflask')

  def _make_request(self, url='https://clusterfuzz.example.com/external-update'):
    with self.app.test_request_context(
        url, headers={'Authorization': 'Bearer sometoken'}):
      return auth.get_email_from_bearer_token(flask.request)

  def test_passes_request_url_as_audience(self):
    """verify_oauth2_token must be called with the request URL as the
    audience, not left unverified."""
    self._make_request(url='https://clusterfuzz.example.com/external-update')

    self.mock.verify_oauth2_token.assert_called_once_with(
        'sometoken', unittest.mock.ANY,
        audience='https://clusterfuzz.example.com/external-update')

  def test_rejects_token_for_wrong_audience(self):
    """A token minted for a different destination must be rejected, not
    just accepted because the email claim happens to match."""
    self.mock.verify_oauth2_token.side_effect = ValueError(
        'Token has wrong audience')

    with self.assertRaises(helpers.UnauthorizedError):
      self._make_request()


if __name__ == '__main__':
  unittest.main()

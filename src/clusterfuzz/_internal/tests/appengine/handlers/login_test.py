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
"""Tests for the session login handler."""

import time
import unittest

import flask
import webtest

from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from handlers import login
from libs import auth


class SessionLoginTests(unittest.TestCase):
  """Tests for SessionLoginHandler."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.auth.verify_id_token',
        'libs.auth.create_session_cookie',
    ])
    self.mock.create_session_cookie.return_value = 'session-cookie-value'

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/session-login',
        view_func=login.SessionLoginHandler.as_view('/session-login'))
    self.app = webtest.TestApp(flaskapp)

  def _recent_claims(self, age_seconds=0):
    return {'auth_time': time.time() - age_seconds}

  def test_recent_sign_in_sets_cookie(self):
    """A token from a sign-in that just happened is exchanged for a session."""
    self.mock.verify_id_token.return_value = self._recent_claims()

    resp = self.app.post_json('/session-login', {'idToken': 'token'})

    self.assertEqual(200, resp.status_int)
    self.assertEqual('success', resp.json['status'])
    self.assertEqual(1, self.mock.create_session_cookie.call_count)
    set_cookie = resp.headers['Set-Cookie']
    self.assertIn('session=session-cookie-value', set_cookie)
    self.assertIn('HttpOnly', set_cookie)
    self.assertIn('Secure', set_cookie)
    self.assertIn('SameSite=Lax', set_cookie)

  def test_stale_sign_in_is_rejected(self):
    """A token from an older sign-in does not produce a session."""
    self.mock.verify_id_token.return_value = self._recent_claims(
        age_seconds=login.MAX_SIGN_IN_AGE_SECONDS + 1)

    resp = self.app.post_json(
        '/session-login', {'idToken': 'token'}, expect_errors=True)

    self.assertEqual(401, resp.status_int)
    self.assertEqual(0, self.mock.create_session_cookie.call_count)
    self.assertNotIn('Set-Cookie', resp.headers)

  def test_claims_without_auth_time_are_rejected(self):
    """A token that carries no auth_time is treated as not recent."""
    self.mock.verify_id_token.return_value = {}

    resp = self.app.post_json(
        '/session-login', {'idToken': 'token'}, expect_errors=True)

    self.assertEqual(401, resp.status_int)
    self.assertEqual(0, self.mock.create_session_cookie.call_count)

  def test_invalid_id_token_is_rejected(self):
    """An ID token that does not verify does not produce a session."""
    self.mock.verify_id_token.side_effect = auth.AuthError('Invalid ID token.')

    resp = self.app.post_json(
        '/session-login', {'idToken': 'token'}, expect_errors=True)

    self.assertEqual(401, resp.status_int)
    self.assertEqual(0, self.mock.create_session_cookie.call_count)
    self.assertNotIn('Set-Cookie', resp.headers)

  def test_cross_site_text_plain_form_is_rejected(self):
    """A cross-site form body cannot reach the handler as a JSON request.

    An HTML form submitted from another origin can only use one of the
    CORS-safelisted media types. text/plain is the one that leaves the body
    bytes untouched, so it is the one that can carry valid JSON.
    """
    self.mock.verify_id_token.return_value = self._recent_claims()
    body = '{"idToken":"attacker-token","padding":"="}'

    resp = self.app.post(
        '/session-login',
        body,
        content_type='text/plain',
        expect_errors=True)

    self.assertEqual(400, resp.status_int)
    self.assertEqual(0, self.mock.create_session_cookie.call_count)
    self.assertNotIn('Set-Cookie', resp.headers)


if __name__ == '__main__':
  unittest.main()

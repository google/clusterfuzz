# Copyright 2019 Google LLC
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
"""Authentication helpers."""

import collections

from firebase_admin import auth
import webapp2

from datastore import data_types
from datastore import ndb
from metrics import logs

User = collections.namedtuple('User', ['email'])


class AuthError(Exception):
  """Auth error."""


def is_current_user_admin():
  """Returns whether or not the current logged in user is an admin."""
  user = get_current_user()
  if not user:
    return False

  key = ndb.Key(data_types.Admin, user.email)
  return bool(key.get())


def get_current_user():
  """Get the current logged in user, or None."""
  oauth_email = getattr(get_current_request(), '_oauth_email', None)
  if oauth_email:
    return User(oauth_email)

  session_cookie = get_session_cookie()
  if not session_cookie:
    return None

  try:
    decoded_claims = decode_claims(get_session_cookie())
  except AuthError:
    logs.log_error('Invalid session cookie.')
    return None

  if not decoded_claims.get('email_verified'):
    return None

  email = decoded_claims.get('email')
  if not email:
    return None

  return User(email)


def create_session_cookie(id_token, expires_in):
  """Create a new session cookie."""
  try:
    return auth.create_session_cookie(id_token, expires_in=expires_in)
  except auth.AuthError:
    raise AuthError('Failed to create session cookie.')


def get_current_request():
  """Get the current request."""
  return webapp2.get_request()


def get_session_cookie():
  """Get the current session cookie."""
  return get_current_request().cookies.get('session')


def revoke_session_cookie(session_cookie):
  """Revoke a session cookie."""
  decoded_claims = decode_claims(session_cookie)
  auth.revoke_refresh_tokens(decoded_claims['sub'])


def decode_claims(session_cookie):
  """Decode the claims for the current session cookie."""
  try:
    return auth.verify_session_cookie(session_cookie, check_revoked=True)
  except (ValueError, auth.AuthError):
    raise AuthError('Invalid session cookie.')

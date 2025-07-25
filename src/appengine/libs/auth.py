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
from google.auth.exceptions import MalformedError
from google.auth.transport import requests as google_requests
from google.cloud import ndb
from google.oauth2 import id_token
from googleapiclient.discovery import build
import jwt
import requests

from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from libs import helpers
from libs import request_cache

User = collections.namedtuple('User', ['email'])
BEARER_PREFIX = 'Bearer '


class AuthError(Exception):
  """Auth error."""


def auth_domain():
  """Get the auth domain."""
  domain = local_config.ProjectConfig().get('firebase.auth_domain')
  if not domain:
    raise AuthError('No auth domain.')

  return domain


def real_auth_domain():
  """Get the real auth domain"""
  real_domain = local_config.ProjectConfig().get('firebase.real_auth_domain')
  if real_domain:
    return real_domain

  return utils.get_application_id() + '.firebaseapp.com'


def is_current_user_admin():
  """Returns whether or not the current logged in user is an admin."""
  if environment.is_local_development():
    return True

  user = get_current_user()
  if not user:
    return False

  key = ndb.Key(data_types.Admin, user.email)
  return bool(key.get())


@memoize.wrap(memoize.FifoInMemory(1))
def _project_number_from_id(project_id):
  """Get the project number from project ID."""
  resource_manager = build('cloudresourcemanager', 'v1')
  # pylint: disable=no-member
  result = resource_manager.projects().get(projectId=project_id).execute()
  if 'projectNumber' not in result:
    raise AuthError('Failed to get project number.')

  return result['projectNumber']


@memoize.wrap(memoize.FifoInMemory(1))
def _get_iap_key(key_id):
  """Retrieves a public key from the list published by Identity-Aware Proxy,
  re-fetching the key file if necessary.
  """
  # pylint: disable=missing-timeout
  resp = requests.get('https://www.gstatic.com/iap/verify/public_key')
  if resp.status_code != 200:
    raise AuthError('Unable to fetch IAP keys: '
                    f'{resp.status_code} / {resp.headers} / {resp.text}')

  result = resp.json()
  key = result.get(key_id)
  if not key:
    raise AuthError(f'Key {repr(key_id)} not found')

  return key


def _validate_iap_jwt(iap_jwt):
  """Validate JWT assertion."""
  project_id = utils.get_application_id()
  expected_audience = f'/projects/{_project_number_from_id(project_id)}' \
                      f'/apps/{project_id}'

  try:
    key_id = jwt.get_unverified_header(iap_jwt).get('kid')
    if not key_id:
      raise AuthError('No key ID.')

    key = _get_iap_key(key_id)
    decoded_jwt = jwt.decode(
        iap_jwt,
        key,
        algorithms=['ES256'],
        issuer='https://cloud.google.com/iap',
        audience=expected_audience)
    return decoded_jwt['email']
  except (jwt.exceptions.InvalidTokenError,
          requests.exceptions.RequestException) as e:
    raise AuthError('JWT assertion decode error: ' + str(e))


def get_iap_email(current_request):
  """Get Cloud IAP email."""
  jwt_assertion = current_request.headers.get('X-Goog-IAP-JWT-Assertion')
  if not jwt_assertion:
    return None

  return _validate_iap_jwt(jwt_assertion)


def get_email_from_bearer_token(request):
  """Gets the email corresponding to a bearer token in an http request."""
  bearer_token = request.headers.get('Authorization', '')
  if not bearer_token.startswith(BEARER_PREFIX):
    raise helpers.UnauthorizedError('Missing or invalid bearer token.')

  token = bearer_token.split(' ')[1]
  try:
    claim = id_token.verify_oauth2_token(token, google_requests.Request())
  except MalformedError:
    raise helpers.UnauthorizedError('Malformed bearer token')
  if (not claim.get('email_verified') or
      claim.get('email') != utils.service_account_email()):
    raise helpers.UnauthorizedError('Invalid ID token.')

  if not claim.get('email_verified'):
    return None
  return claim.get('email')


def get_current_user():
  """Get the current logged in user, or None."""
  if environment.is_local_development():
    return User('user@localhost')

  current_request = request_cache.get_current_request()
  if local_config.AuthConfig().get('enable_loas'):
    loas_user = current_request.headers.get('X-AppEngine-LOAS-Peer-Username')
    if loas_user:
      return User(loas_user + '@google.com')

  iap_email = get_iap_email(current_request)
  if iap_email:
    return User(iap_email)

  try:
    bearer_token_email = get_email_from_bearer_token(current_request)
    if bearer_token_email:
      logs.info(f'bearer token email = {bearer_token_email}')
      return User(bearer_token_email)
  except helpers.UnauthorizedError as e:
    logs.warning(f'Exception while trying to get email from auth token: {e}')

  cache_backing = request_cache.get_cache_backing()
  oauth_email = getattr(cache_backing, '_oauth_email', None)
  if oauth_email:
    return User(oauth_email)

  cached_email = getattr(cache_backing, '_cached_email', None)
  if cached_email:
    return User(cached_email)

  session_cookie = get_session_cookie()
  if not session_cookie:
    return None

  try:
    decoded_claims = decode_claims(get_session_cookie())
  except AuthError:
    logs.warning('Invalid session cookie.')
    return None

  allowed_firebase_providers = local_config.ProjectConfig().get(
      'firebase.auth_providers', ['google.com'])
  firebase_info = decoded_claims.get('firebase', {})
  sign_in_provider = firebase_info.get('sign_in_provider')

  if sign_in_provider not in allowed_firebase_providers:
    logs.error(f'Firebase provider {sign_in_provider} is not enabled.')
    return None

  # Per https://docs.github.com/en/authentication/
  #       keeping-your-account-and-data-secure/authorizing-oauth-apps
  # GitHub requires emails to be verified before an OAuth app can be
  # authorized, so we make an exception.
  if (not decoded_claims.get('email_verified') and
      sign_in_provider != 'github.com'):
    return None

  email = decoded_claims.get('email')
  if not email:
    return None

  # We cache the email for this request if we've validated the user to make
  # subsequent get_current_user() calls fast.
  setattr(cache_backing, '_cached_email', email)
  return User(email)


def create_session_cookie(token, expires_in):
  """Create a new session cookie."""
  try:
    return auth.create_session_cookie(token, expires_in=expires_in)
  except auth.AuthError:
    raise AuthError('Failed to create session cookie.')


def get_session_cookie():
  """Get the current session cookie."""
  return request_cache.get_current_request().cookies.get('session')


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

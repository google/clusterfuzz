# Copyright 2020 Google LLC
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
"""handler.py provides decorators for POST and GET handlers."""

import datetime
import functools
import json
import re

from flask import g
from flask import make_response
from flask import request
import google.auth
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
import requests

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.system import environment
from libs import access
from libs import auth
from libs import csp
from libs import helpers

JSON = 'json'
FORM = 'form'
HTML = 'html'
TEXT = 'text'

CLUSTERFUZZ_AUTHORIZATION_HEADER = 'x-clusterfuzz-authorization'
CLUSTERFUZZ_AUTHORIZATION_IDENTITY = 'x-clusterfuzz-identity'
VERIFICATION_CODE_PREFIX = 'VerificationCode '
BEARER_PREFIX = 'Bearer '

_auth_config_obj = None


def _auth_config():
  """Return a config with auth root."""
  global _auth_config_obj
  if not _auth_config_obj:
    _auth_config_obj = local_config.AuthConfig()

  return _auth_config_obj


def extend_request(req, params):
  """Extends a request."""

  def _iterparams():
    for k, v in params.items():
      yield k, v

  def _get(key, default_value=None):
    """Return the value of the key or the default value."""
    return params.get(key, default_value)

  req.get = _get
  req.iterparams = _iterparams


def extend_json_request(req):
  """Extends a request to support JSON."""
  try:
    params = json.loads(req.data)
  except ValueError as e:
    raise helpers.EarlyExitException(
        'Parsing the JSON request body failed: %s' % req.data, 400) from e

  extend_request(req, params)


def cron():
  """Wrap a handler with cron."""

  def decorator(func):
    """Decorator."""

    @functools.wraps(func)
    def wrapper(self):
      """Wrapper."""
      if not self.is_cron():
        raise helpers.AccessDeniedException('You are not a cron.')

      result = func(self)
      if result is None:
        return 'OK'

      return result

    return wrapper

  return decorator


def check_admin_access(func):
  """Wrap a handler with admin checking.

  This decorator must be below post(..) and get(..) when used.
  """

  @functools.wraps(func)
  def wrapper(self):
    """Wrapper."""
    if not auth.is_current_user_admin():
      raise helpers.AccessDeniedException('Admin access is required.')

    return func(self)

  return wrapper


def check_admin_access_if_oss_fuzz(func):
  """Wrap a handler with an admin check if this is OSS-Fuzz.

  This decorator must be below post(..) and get(..) when used.
  """

  @functools.wraps(func)
  def wrapper(self):
    """Wrapper."""
    if utils.is_oss_fuzz():
      return check_admin_access(func)(self)

    return func(self)

  return wrapper


def unsupported_on_local_server(func):
  """Wrap a handler to raise error when running in local App Engine
  development environment.

  This decorator must be below post(..) and get(..) when used.
  """

  @functools.wraps(func)
  def wrapper(self, *args, **kwargs):
    """Wrapper."""
    if environment.is_running_on_app_engine_development():
      raise helpers.EarlyExitException(
          'This feature is not available in local App Engine Development '
          'environment.', 400)

    return func(self, *args, **kwargs)

  return wrapper


def get_access_token(verification_code):
  """Get the access token from verification code.

    See: https://developers.google.com/identity/protocols/OAuth2InstalledApp
  """
  client_id = db_config.get_value('reproduce_tool_client_id')
  if not client_id:
    raise helpers.UnauthorizedException('Client id not configured.')

  client_secret = db_config.get_value('reproduce_tool_client_secret')
  if not client_secret:
    raise helpers.UnauthorizedException('Client secret not configured.')

  response = requests.post(
      'https://www.googleapis.com/oauth2/v4/token',
      headers={'Content-Type': 'application/x-www-form-urlencoded'},
      data={
          'code': verification_code,
          'client_id': client_id,
          'client_secret': client_secret,
          'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
          'grant_type': 'authorization_code'
      })

  if response.status_code != 200:
    raise helpers.UnauthorizedException('Invalid verification code (%s): %s' %
                                        (verification_code, response.text))

  try:
    data = json.loads(response.text)
    return data['access_token']
  except (KeyError, ValueError) as e:
    raise helpers.EarlyExitException(
        'Parsing the JSON response body failed: %s' % response.text, 500) from e


def get_email_and_access_token(authorization):
  """Get user email from the request.

    See: https://developers.google.com/identity/protocols/OAuth2InstalledApp
  """
  if authorization.startswith(VERIFICATION_CODE_PREFIX):
    verification_code = authorization.split(' ')[1]
    access_token = get_access_token(verification_code)
    authorization = BEARER_PREFIX + access_token

  if not authorization.startswith(BEARER_PREFIX):
    raise helpers.UnauthorizedException(
        'The Authorization header is invalid. It should have been started with'
        " '%s'." % BEARER_PREFIX)

  access_token = authorization.split(' ')[1]

  response = requests.get(
      'https://www.googleapis.com/oauth2/v3/tokeninfo',
      params={'access_token': access_token})
  if response.status_code != 200:
    raise helpers.UnauthorizedException(
        'Failed to authorize. The Authorization header (%s) might be invalid.' %
        authorization)

  try:
    data = json.loads(response.text)

    # Whitelist service accounts. They have different client IDs (or aud).
    # Therefore, we check against their email directly.
    if data.get('email_verified') and data.get('email') in _auth_config().get(
        'whitelisted_oauth_emails', default=[]):
      return data['email'], authorization

    # Validate that this is an explicitly whitelisted client ID, or the client
    # ID for the reproduce tool.
    whitelisted_client_ids = _auth_config().get(
        'whitelisted_oauth_client_ids', default=[])
    reproduce_tool_client_id = db_config.get_value('reproduce_tool_client_id')
    if reproduce_tool_client_id:
      whitelisted_client_ids += [reproduce_tool_client_id]
    if data.get('aud') not in whitelisted_client_ids:
      raise helpers.UnauthorizedException(
          "The access token doesn't belong to one of the allowed OAuth clients"
          ': %s.' % response.text)

    if not data.get('email_verified'):
      raise helpers.UnauthorizedException('The email (%s) is not verified: %s.'
                                          % (data.get('email'), response.text))

    return data['email'], authorization
  except (KeyError, ValueError) as e:
    raise helpers.EarlyExitException(
        'Parsing the JSON response body failed: %s' % response.text, 500) from e


def oauth(func):
  """Wrap a handler with OAuth authentication by reading the Authorization
    header and getting user email.
  """

  @functools.wraps(func)
  def wrapper(self):
    """Wrapper."""
    auth_header = request.headers.get('Authorization')
    if auth_header:
      email, returned_auth_header = get_email_and_access_token(auth_header)
      setattr(g, '_oauth_email', email)

      response = make_response(func(self))
      response.headers[CLUSTERFUZZ_AUTHORIZATION_HEADER] = str(
          returned_auth_header)
      response.headers[CLUSTERFUZZ_AUTHORIZATION_IDENTITY] = str(email)
      return response

    return func(self)

  return wrapper


def pubsub_push(func):
  """Wrap a handler with pubsub push authentication."""

  @functools.wraps(func)
  def wrapper(self):
    """Wrapper."""
    try:
      bearer_token = request.headers.get('Authorization', '')
      if not bearer_token.startswith(BEARER_PREFIX):
        raise helpers.UnauthorizedException('Missing or invalid bearer token.')

      token = bearer_token.split(' ')[1]
      claim = id_token.verify_oauth2_token(token, google_requests.Request())
    except google.auth.exceptions.GoogleAuthError as e:
      raise helpers.UnauthorizedException('Invalid ID token.') from e

    if (not claim.get('email_verified') or
        claim.get('email') != utils.service_account_email()):
      raise helpers.UnauthorizedException('Invalid ID token.')

    message = pubsub.raw_message_to_message(json.loads(request.data.decode()))
    return func(self, message)

  return wrapper


def check_user_access(need_privileged_access):
  """Wrap a handler with check_user_access.

  This decorator must be below post(..) and get(..) when used.
  """

  def decorator(func):
    """Decorator."""

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
      """Wrapper."""
      if not access.has_access(need_privileged_access=need_privileged_access):
        raise helpers.AccessDeniedException()

      return func(self, *args, **kwargs)

    return wrapper

  return decorator


def check_testcase_access(func):
  """Wrap a handler with check_testcase_access.

  It expects the param
    `testcaseId`. And it expects func to have testcase as its first argument.

  This decorator must be below post(..) and get(..) when used.
  """

  @functools.wraps(func)
  def wrapper(self):
    """Wrapper."""
    testcase_id = helpers.cast(
        request.get('testcaseId'), int,
        "The param 'testcaseId' is not a number.")

    testcase = access.check_access_and_get_testcase(testcase_id)
    return func(self, testcase)

  return wrapper


def allowed_cors(func):
  """Wrap a handler with 'Access-Control-Allow-Origin to allow cross-domain
  AJAX calls."""

  @functools.wraps(func)
  def wrapper(self):
    """Wrapper."""
    origin = request.headers.get('Origin')
    whitelisted_cors_urls = _auth_config().get('whitelisted_cors_urls')
    response = make_response(func(self))

    if origin and whitelisted_cors_urls:
      for domain_regex in whitelisted_cors_urls:
        if re.match(domain_regex, origin):
          response.headers['Access-Control-Allow-Origin'] = origin
          response.headers['Vary'] = 'Origin'
          response.headers['Access-Control-Allow-Credentials'] = 'true'
          response.headers['Access-Control-Allow-Methods'] = (
              'GET,OPTIONS,POST')
          response.headers['Access-Control-Allow-Headers'] = (
              'Accept,Authorization,Content-Type')
          response.headers['Access-Control-Max-Age'] = '3600'
          break

    return response

  return wrapper


def post(request_content_type, response_content_type):
  """Wrap a POST handler, parse request, and set response's content type."""

  def decorator(func):
    """Decorator."""

    @functools.wraps(func)
    def wrapper(self):
      """Wrapper."""
      if response_content_type == JSON:
        self.is_json = True

      if request_content_type == JSON:
        extend_json_request(request)
      elif request_content_type == FORM:
        extend_request(request, request.form)
      else:
        extend_request(request, request.args)

      response = make_response(func(self))
      if response_content_type == JSON:
        response.headers['Content-Type'] = 'application/json'
      elif response_content_type == TEXT:
        response.headers['Content-Type'] = 'text/plain'
      elif response_content_type == HTML:
        # Don't enforce content security policies in local development mode.
        if not environment.is_running_on_app_engine_development():
          response.headers['Content-Security-Policy'] = csp.get_default()

      return response

    return wrapper

  return decorator


def get(response_content_type):
  """Wrap a GET handler and set response's content type."""

  def decorator(func):
    """Decorator."""

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
      """Wrapper."""
      if response_content_type == JSON:
        self.is_json = True

      extend_request(request, request.args)
      response = make_response(func(self, *args, **kwargs))
      if response_content_type == JSON:
        response.headers['Content-Type'] = 'application/json'
      elif response_content_type == TEXT:
        response.headers['Content-Type'] = 'text/plain'
      elif response_content_type == HTML:
        # Don't enforce content security policies in local development mode.
        if not environment.is_running_on_app_engine_development():
          response.headers['Content-Security-Policy'] = csp.get_default()

      return response

    return wrapper

  return decorator


def require_csrf_token(func):
  """Wrap a handler to require a valid CSRF token."""

  def wrapper(self, *args, **kwargs):
    """Check to see if this handler has a valid CSRF token provided to it."""
    token_value = request.get('csrf_token')
    user = auth.get_current_user()
    if not user:
      raise helpers.AccessDeniedException('Not logged in.')

    query = data_types.CSRFToken.query(
        data_types.CSRFToken.value == token_value,
        data_types.CSRFToken.user_email == user.email)
    token = query.get()
    if not token:
      raise helpers.AccessDeniedException('Invalid CSRF token.')

    # Make sure that the token is not expired.
    if token.expiration_time < datetime.datetime.utcnow():
      token.key.delete()
      raise helpers.AccessDeniedException('Expired CSRF token.')

    return func(self, *args, **kwargs)

  return wrapper

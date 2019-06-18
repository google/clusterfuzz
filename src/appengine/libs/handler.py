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
"""handler.py provides decorators for POST and GET handlers."""
import datetime
import functools
import json
import re
import requests
import six

from base import utils
from config import db_config
from config import local_config
from datastore import data_types
from libs import access
from libs import auth
from libs import csp
from libs import helpers
from system import environment

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
    for k, v in six.iteritems(params):
      yield k, v

  req.iterparams = _iterparams


def extend_json_request(req):
  """Extends a request to support JSON."""
  try:
    params = json.loads(req.body)
  except ValueError:
    raise helpers.EarlyExitException(
        'Parsing the JSON request body failed: %s' % req.body, 400)

  def _get(key, default_value=None):
    """Return the value of the key or the default value."""
    return params.get(key, default_value)

  req.get = _get

  # We need the below method because setting req.params raises "can't set
  # attribute" error. It would have been cleaner to replace req.params.
  extend_request(req, params)


def check_cron():
  """Wrap a handler with check_cron."""

  def decorator(func):
    """Decorator."""

    @functools.wraps(func)
    def wrapper(self):
      """Wrapper."""
      if not self.is_cron():
        raise helpers.AccessDeniedException('You are not a cron.')

      return func(self)

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
  def wrapper(self):
    """Wrapper."""
    if environment.is_running_on_app_engine_development():
      raise helpers.EarlyExitException(
          'This feature is not available in local App Engine Development '
          'environment.', 400)

    return func(self)

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
  except (KeyError, ValueError):
    raise helpers.EarlyExitException(
        'Parsing the JSON response body failed: %s' % response.text, 500)


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
  except (KeyError, ValueError):
    raise helpers.EarlyExitException(
        'Parsing the JSON response body failed: %s' % response.text, 500)


def oauth(func):
  """Wrap a handler with OAuth authentication by reading the Authorization

    header and getting user email.
  """

  @functools.wraps(func)
  def wrapper(self):
    """Wrapper."""
    auth_header = self.request.headers.get('Authorization')
    if auth_header:
      email, returned_auth_header = get_email_and_access_token(auth_header)

      setattr(self.request, '_oauth_email', email)
      self.response.headers[CLUSTERFUZZ_AUTHORIZATION_HEADER] = str(
          returned_auth_header)
      self.response.headers[CLUSTERFUZZ_AUTHORIZATION_IDENTITY] = str(email)

    return func(self)

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
        self.request.get('testcaseId'), int,
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
    origin = self.request.headers.get('Origin')
    whitelisted_cors_urls = _auth_config().get('whitelisted_cors_urls')

    if origin and whitelisted_cors_urls:
      for domain_regex in whitelisted_cors_urls:
        if re.match(domain_regex, origin):
          self.response.headers['Access-Control-Allow-Origin'] = origin
          self.response.headers['Vary'] = 'Origin'
          self.response.headers['Access-Control-Allow-Credentials'] = 'true'
          self.response.headers['Access-Control-Allow-Methods'] = (
              'GET,OPTIONS,POST')
          self.response.headers['Access-Control-Allow-Headers'] = (
              'Accept,Authorization,Content-Type')
          self.response.headers['Access-Control-Max-Age'] = '3600'
          break

    return func(self)

  return wrapper


def post(request_content_type, response_content_type):
  """Wrap a POST handler, parse request, and set response's content type."""

  def decorator(func):
    """Decorator."""

    @functools.wraps(func)
    def wrapper(self):
      """Wrapper."""
      if response_content_type == JSON:
        self.response.headers['Content-Type'] = 'application/json'
      elif response_content_type == TEXT:
        self.response.headers['Content-Type'] = 'text/plain'
      elif response_content_type == HTML:
        # Don't enforce content security policies in local development mode.
        if not environment.is_running_on_app_engine_development():
          self.response.headers['Content-Security-Policy'] = csp.get_default()

      if request_content_type == JSON:
        extend_json_request(self.request)
      else:
        extend_request(self.request, self.request.params)

      return func(self)

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
        self.response.headers['Content-Type'] = 'application/json'
      elif response_content_type == TEXT:
        self.response.headers['Content-Type'] = 'text/plain'
      elif response_content_type == HTML:
        # Don't enforce content security policies in local development mode.
        if not environment.is_running_on_app_engine_development():
          self.response.headers['Content-Security-Policy'] = csp.get_default()

      extend_request(self.request, self.request.params)
      return func(self, *args, **kwargs)

    return wrapper

  return decorator


def require_csrf_token(func):
  """Wrap a handler to require a valid CSRF token."""

  def wrapper(self, *args, **kwargs):
    """Check to see if this handler has a valid CSRF token provided to it."""
    token_value = self.request.get('csrf_token')
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
    elif token.expiration_time < datetime.datetime.utcnow():
      token.key.delete()
      raise helpers.AccessDeniedException('Expired CSRF token.')

    return func(self, *args, **kwargs)

  return wrapper

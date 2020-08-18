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
"""Login page."""

import datetime

from config import local_config
from flask import request
from handlers import base_handler_flask
from libs import auth
from libs import handler_flask
from libs import helpers
from metrics import logs

DEFAULT_REDIRECT = '/'
SESSION_EXPIRY_DAYS = 14


class Handler(base_handler_flask.Handler):
  """Login page."""

  @handler_flask.get(handler_flask.HTML)
  @handler_flask.unsupported_on_local_server
  def get(self):
    """Handle a get request."""
    dest = request.get('dest', DEFAULT_REDIRECT)
    base_handler_flask.check_redirect_url(dest)

    return self.render(
        'login.html', {
            'apiKey': local_config.ProjectConfig().get('firebase.api_key'),
            'authDomain': auth.auth_domain(),
            'dest': dest,
        })


class SessionLoginHandler(base_handler_flask.Handler):
  """Session login handler_flask."""

  @handler_flask.post(handler_flask.JSON, handler_flask.JSON)
  def post(self):
    """Handle a post request."""
    id_token = request.get('idToken')
    expires_in = datetime.timedelta(days=SESSION_EXPIRY_DAYS)
    try:
      session_cookie = auth.create_session_cookie(id_token, expires_in)
    except auth.AuthError:
      raise helpers.EarlyExitException('Failed to create session cookie.', 401)

    expires = datetime.datetime.now() + expires_in
    response = self.render_json({'status': 'success'})
    response.set_cookie(
        'session', session_cookie, expires=expires, httponly=True, secure=True)
    return response


class LogoutHandler(base_handler_flask.Handler):
  """Log out handler_flask."""

  @handler_flask.get(handler_flask.HTML)
  @handler_flask.unsupported_on_local_server
  @handler_flask.require_csrf_token
  def get(self):
    """Handle a get request."""
    try:
      auth.revoke_session_cookie(auth.get_session_cookie())
    except auth.AuthError:
      # Even if the revoke failed, remove the cookie.
      logs.log_error('Failed to revoke session cookie.')

    response = self.redirect(request.get('dest', DEFAULT_REDIRECT))
    response.delete_cookie('session')
    return response

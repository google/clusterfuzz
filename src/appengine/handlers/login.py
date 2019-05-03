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
from handlers import base_handler
from libs import auth
from libs import handler
from libs import helpers
from metrics import logs

SESSION_EXPIRY_DAYS = 14


class Handler(base_handler.Handler):
  """Login page."""

  @handler.unsupported_on_local_server
  @handler.get(handler.HTML)
  def get(self):
    """Handle a get request."""
    self.render(
        'login.html', {
            'apiKey': local_config.ProjectConfig().get('firebase.api_key'),
            'authDomain': auth.auth_domain(),
            'dest': self.request.get('dest'),
        })


class SessionLoginHandler(base_handler.Handler):
  """Session login handler."""

  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    """Handle a post request."""
    id_token = self.request.get('idToken')
    expires_in = datetime.timedelta(days=SESSION_EXPIRY_DAYS)
    try:
      session_cookie = auth.create_session_cookie(id_token, expires_in)
    except auth.AuthError:
      raise helpers.EarlyExitException('Failed to create session cookie.', 401)

    expires = datetime.datetime.now() + expires_in
    self.response.set_cookie(
        'session',
        session_cookie,
        expires=expires,
        httponly=True,
        secure=True,
        overwrite=True)
    self.render_json({'status': 'success'})


class LogoutHandler(base_handler.Handler):
  """Log out handler."""

  @handler.unsupported_on_local_server
  @handler.require_csrf_token
  @handler.get(handler.HTML)
  def get(self):
    """Handle a get request."""
    try:
      auth.revoke_session_cookie(auth.get_session_cookie())
    except auth.AuthError:
      # Even if the revoke failed, remove the cookie.
      logs.log_error('Failed to revoke session cookie.')

    self.response.delete_cookie('session')
    self.redirect(self.request.get('dest'))

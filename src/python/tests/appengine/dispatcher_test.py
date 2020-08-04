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
"""Tests for custom_dispatcher module."""
# TODO(singharshdeep): Remove this after flask migration.
import flask
import unittest
import webapp2

from main import Middleware
from handlers import base_handler, base_handler_flask
from tests.test_libs import helpers as test_helpers
from werkzeug.test import create_environ
from werkzeug.test import run_wsgi_app


class FlaskHandler(base_handler_flask.Handler):
  """Render JSON response for testing."""

  def get(self):
    return 'flask', 200


class WebappHandler(base_handler.Handler):
  """Render JSON response for testing."""

  def get(self):
    self.response.set_status(201)


class CustomDispatcherTest(unittest.TestCase):
  """Test custom_dispatcher module is loaded."""

  def setUp(self):
    test_helpers.patch(self, [
        'config.db_config.get_value', 'libs.form.generate_csrf_token',
        'libs.helpers.get_user_email', 'main.routes', 'server.app'
    ])
    self.mock.get_value.return_value = 'contact_string'
    self.mock.generate_csrf_token.return_value = 'csrf_token'
    self.mock.get_user_email.return_value = 'test@test.com'

  def test_mounts(self):
    """Test if Middleware dispatches correctly for given mounts."""
    flask_app = flask.Flask('testflask')
    flask_app.add_url_rule('/test_a', view_func=FlaskHandler.as_view('/test_a'))
    webapp_app = webapp2.WSGIApplication([('/test_b', WebappHandler)])
    app = Middleware(webapp_app, {'/test_a': flask_app})
    environ = create_environ('/test_b')
    _, status, _ = run_wsgi_app(app, environ)
    self.assertEqual(status, "201 Created")

    environ = create_environ('/test_a')
    _, status, _ = run_wsgi_app(app, environ)
    self.assertEqual(status, "200 OK")

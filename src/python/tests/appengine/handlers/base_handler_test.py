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
"""Tests for the base handler class."""

import flask
import unittest
import webapp2
import webtest

from handlers import base_handler
from libs import helpers
from tests.test_libs import helpers as test_helpers


class JsonHandler(base_handler.Handler):
  """Render JSON response for testing."""

  def get(self):
    self.render_json({'test': 'value'})


class HtmlHandler(base_handler.Handler):
  """Render HTML response for testing."""

  def get(self):
    self.render('test.html', {'test': 'value'})


class ExceptionJsonHandler(base_handler.Handler):
  """Render exception in JSON response for testing."""

  def get(self):
    self.response.headers['Content-Type'] = 'application/json'
    raise Exception('message')


class ExceptionHtmlHandler(base_handler.Handler):
  """Render exception in HTML response for testing."""

  def get(self):
    raise Exception('unique_message')


class EarlyExceptionHandler(base_handler.Handler):
  """Render EarlyException in JSON for testing."""

  def get(self):
    self.response.headers['Content-Type'] = 'application/json'
    raise helpers.EarlyExitException('message', 500, [])


class AccessDeniedExceptionHandler(base_handler.Handler):
  """Render forbidden in HTML response for testing."""

  def get(self):
    raise helpers.AccessDeniedException('this_random_message')


class RedirectHandler(base_handler.Handler):
  """Redirect handler."""

  def get(self):
    redirect = self.request.get('redirect')
    self.redirect(redirect)


class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'config.db_config.get_value',
        'libs.form.generate_csrf_token',
        'libs.helpers.get_user_email',
    ])
    self.mock.get_value.return_value = 'contact_string'
    self.mock.generate_csrf_token.return_value = 'csrf_token'
    self.mock.get_user_email.return_value = 'test@test.com'

  def test_render_json(self):
    """Ensure it renders JSON correctly."""
    app = webtest.TestApp(webapp2.WSGIApplication([('/', JsonHandler)]))
    response = app.get('/')
    self.assertEqual(response.status_int, 200)
    self.assertDictEqual(response.json, {'test': 'value'})

  def test_render_early_exception(self):
    """Ensure it renders JSON response for EarlyExitException properly."""
    app = webtest.TestApp(
        webapp2.WSGIApplication([('/', EarlyExceptionHandler)]))
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 500)
    self.assertEqual(response.json['message'], 'message')
    self.assertEqual(response.json['email'], 'test@test.com')

  def test_render_json_exception(self):
    """Ensure it renders JSON exception correctly."""
    app = webtest.TestApp(
        webapp2.WSGIApplication([('/', ExceptionJsonHandler)]))
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 500)
    self.assertEqual(response.json['message'], 'message')
    self.assertEqual(response.json['email'], 'test@test.com')

  def test_render(self):
    """Ensure it gets template and render HTML correctly."""
    app = webtest.TestApp(webapp2.WSGIApplication([('/', HtmlHandler)]))
    response = app.get('/')
    self.assertEqual(response.status_int, 200)
    self.assertEqual(response.body, b'<html><body>value\n</body></html>')

  def test_render_html_exception(self):
    """Ensure it renders HTML exception correctly."""
    app = webtest.TestApp(
        webapp2.WSGIApplication([('/', ExceptionHtmlHandler)]))
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 500)
    self.assertRegex(response.body, b'.*unique_message.*')
    self.assertRegex(response.body, b'.*test@test.com.*')

  def test_forbidden_not_logged_in(self):
    """Ensure it renders forbidden response correctly (when not logged in)."""
    self.mock.get_user_email.return_value = None

    app = webtest.TestApp(
        webapp2.WSGIApplication([('/', AccessDeniedExceptionHandler)]))
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 302)
    self.assertEqual('http://localhost/login?dest=http%3A%2F%2Flocalhost%2F',
                     response.headers['Location'])

  def test_forbidden_logged_in(self):
    """Ensure it renders forbidden response correctly (when logged in)."""
    app = webtest.TestApp(
        webapp2.WSGIApplication([('/', AccessDeniedExceptionHandler)]))
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 403)
    self.assertRegex(response.body, b'.*Access Denied.*')
    self.assertRegex(response.body, b'.*this_random_message.*')

  def test_redirect_another_page(self):
    """Test redirect to another page."""
    app = webtest.TestApp(webapp2.WSGIApplication([('/', RedirectHandler)]))
    response = app.get('/?redirect=%2Fanother-page')
    self.assertEqual('http://localhost/another-page',
                     response.headers['Location'])

  def test_redirect_another_domain(self):
    """Test redirect to another domain."""
    app = webtest.TestApp(webapp2.WSGIApplication([('/', RedirectHandler)]))
    response = app.get('/?redirect=https%3A%2F%2Fblah.com%2Ftest')
    self.assertEqual('https://blah.com/test', response.headers['Location'])

  def test_redirect_javascript(self):
    """Test redirect to a javascript url."""
    app = webtest.TestApp(webapp2.WSGIApplication([('/', RedirectHandler)]))
    response = app.get(
        '/?redirect=javascript%3Aalert%281%29', expect_errors=True)
    self.assertEqual(response.status_int, 403)


class FlaskJsonHandler(base_handler.FlaskHandler):
  """Render JSON response for testing."""

  def get(self):
    return self.render_json({'test': 'value'})


class FlaskHtmlHandler(base_handler.FlaskHandler):
  """Render HTML response for testing."""

  def get(self):
    return self.render('test.html', {'test': 'value'})


class FlaskExceptionJsonHandler(base_handler.FlaskHandler):
  """Render exception in JSON response for testing."""

  def get(self):
    self.response.headers['Content-Type'] = 'application/json'
    raise Exception('message')


class FlaskExceptionHtmlHandler(base_handler.FlaskHandler):
  """Render exception in HTML response for testing."""

  def get(self):
    raise Exception('unique_message')


class FlaskEarlyExceptionHandler(base_handler.FlaskHandler):
  """Render EarlyException in JSON for testing."""

  def get(self):
    self.response.headers['Content-Type'] = 'application/json'
    raise helpers.EarlyExitException('message', 500, [])


class FlaskAccessDeniedExceptionHandler(base_handler.FlaskHandler):
  """Render forbidden in HTML response for testing."""

  def get(self):
    raise helpers.AccessDeniedException('this_random_message')


class FlaskRedirectHandler(base_handler.FlaskHandler):
  """Redirect handler."""

  def get(self):
    redirect = self.request.args.get('redirect')
    return self.redirect(redirect)


class FlaskHandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'config.db_config.get_value',
        'libs.form.generate_csrf_token',
        'libs.helpers.get_user_email',
    ])
    self.mock.get_value.return_value = 'contact_string'
    self.mock.generate_csrf_token.return_value = 'csrf_token'
    self.mock.get_user_email.return_value = 'test@test.com'

  def test_render_json(self):
    """Ensure it renders JSON correctly."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=FlaskJsonHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get('/')
    print(response)
    self.assertEqual(response.status_int, 200)
    self.assertDictEqual(response.json, {'test': 'value'})

  def test_render_early_exception(self):
    """Ensure it renders JSON response for EarlyExitException properly."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=FlaskEarlyExceptionHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get('/', expect_errors=True)
    print(response)
    self.assertEqual(response.status_int, 500)
    self.assertEqual(response.json['message'], 'message')
    self.assertEqual(response.json['email'], 'test@test.com')

  def test_render_json_exception(self):
    """Ensure it renders JSON exception correctly."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=FlaskExceptionJsonHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 500)
    self.assertEqual(response.json['message'], 'message')
    self.assertEqual(response.json['email'], 'test@test.com')

  def test_render(self):
    """Ensure it gets template and render HTML correctly."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=FlaskHtmlHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get('/')
    self.assertEqual(response.status_int, 200)
    self.assertEqual(response.body, b'<html><body>value\n</body></html>')

  def test_render_html_exception(self):
    """Ensure it renders HTML exception correctly."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=FlaskExceptionHtmlHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 500)
    self.assertRegex(response.body, b'.*unique_message.*')
    self.assertRegex(response.body, b'.*test@test.com.*')

  def test_forbidden_not_logged_in(self):
    """Ensure it renders forbidden response correctly (when not logged in)."""
    self.mock.get_user_email.return_value = None

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=FlaskAccessDeniedExceptionHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 302)
    self.assertEqual('http://localhost/login?dest=http%3A%2F%2Flocalhost%2F',
                     response.headers['Location'])

  def test_forbidden_logged_in(self):
    """Ensure it renders forbidden response correctly (when logged in)."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=FlaskAccessDeniedExceptionHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 403)
    self.assertRegex(response.body, b'.*Access Denied.*')
    self.assertRegex(response.body, b'.*this_random_message.*')

  def test_redirect_another_page(self):
    """Test redirect to another page."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=FlaskRedirectHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get('/?redirect=%2Fanother-page')
    self.assertEqual('http://localhost/another-page',
                     response.headers['Location'])

  def test_redirect_another_domain(self):
    """Test redirect to another domain."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=FlaskRedirectHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get('/?redirect=https%3A%2F%2Fblah.com%2Ftest')
    self.assertEqual('https://blah.com/test', response.headers['Location'])

  def test_redirect_javascript(self):
    """Test redirect to a javascript url."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=FlaskRedirectHandler.as_view('/'))
    app = webtest.TestApp(flaskapp)
    response = app.get(
        '/?redirect=javascript%3Aalert%281%29', expect_errors=True)
    self.assertEqual(response.status_int, 403)

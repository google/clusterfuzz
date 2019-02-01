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

import unittest
import webapp2
import webtest

from google.appengine.ext import testbed

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


class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'config.db_config.get_value',
        'google.appengine.api.users.create_login_url',
        'google.appengine.api.users.create_logout_url',
        'libs.helpers.get_user_email',
    ])
    self.mock.get_value.return_value = 'contact_string'
    self.mock.create_login_url.return_value = 'login_url'
    self.mock.create_logout_url.return_value = 'logout_url'
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
    self.assertEqual(response.body, '<html><body>value\n</body></html>')

  def test_render_html_exception(self):
    """Ensure it renders HTML exception correctly."""
    app = webtest.TestApp(
        webapp2.WSGIApplication([('/', ExceptionHtmlHandler)]))
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 500)
    self.assertRegexpMatches(response.body, '.*unique_message.*')
    self.assertRegexpMatches(response.body, '.*test@test.com.*')

  def test_forbidden_not_logged_in(self):
    """Ensure it renders forbidden response correctly (when not logged in)."""
    self.mock.get_user_email.return_value = None

    app = webtest.TestApp(
        webapp2.WSGIApplication([('/', AccessDeniedExceptionHandler)]))
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 403)
    self.assertRegexpMatches(response.body, '.*login.*')
    self.assertRegexpMatches(response.body, '.*see this page.*')
    self.assertRegexpMatches(response.body, '.*Access Denied.*')
    self.assertNotRegexpMatches(response.body, '.*this_random_message.*')

  def test_forbidden_logged_in(self):
    """Ensure it renders forbidden response correctly (when logged in)."""
    app = webtest.TestApp(
        webapp2.WSGIApplication([('/', AccessDeniedExceptionHandler)]))
    response = app.get('/', expect_errors=True)
    self.assertEqual(response.status_int, 403)
    self.assertRegexpMatches(response.body, '.*Access Denied.*')
    self.assertRegexpMatches(response.body, '.*this_random_message.*')


def _mock_create_login_url(dest_url):
  """Return a fake login URL in the format for authenticated users."""
  return 'https://site/ServiceLogin?continue=%s' % dest_url


class MakeSwitchAccountUrlTest(unittest.TestCase):
  """Test make_switch_account_url."""

  def setUp(self):
    test_helpers.patch(self, [
        'google.appengine.api.users.create_login_url',
        'libs.helpers.get_user_email',
    ])
    self.testbed = testbed.Testbed()
    self.testbed.activate()
    self.testbed.init_user_stub()

  def tearDown(self):
    self.testbed.deactivate()

  def test_make(self):
    """Test make_url."""
    self.mock.create_login_url.side_effect = _mock_create_login_url
    self.mock.get_user_email.return_value = 'test@test.com'
    self.assertEqual('https://site/AccountChooser?continue=/testcase/12354',
                     base_handler.make_switch_account_url('/testcase/12354'))

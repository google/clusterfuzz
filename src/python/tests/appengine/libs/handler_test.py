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
"""Tests for Handler."""

from __future__ import print_function

import json
import mock
import os
import unittest
import urllib
import webapp2
import webtest
import yaml

from google.appengine.api import urlfetch
from google.appengine.api import users
from google.appengine.ext import testbed

from config import local_config
from datastore import data_types
from handlers import base_handler
from libs import handler
from libs import helpers
from tests.test_libs import helpers as test_helpers


def mocked_db_config_get_value(key):
  """Return mocked values from db_config's get_value function."""
  if key == 'clusterfuzz_tools_client_secret':
    return 'Secret'
  return None


def mocked_load_yaml_file(yaml_file_path):
  """Return mocked version of local_config._load_yaml_file. Uses custom version
  of auth.yaml for tests in this file."""
  if os.path.basename(yaml_file_path) == 'auth.yaml':
    yaml_file_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), 'handler_data', 'auth.yaml'))

  return yaml.safe_load(open(yaml_file_path).read())


class JsonJsonPostHandler(base_handler.Handler):

  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    test = self.request.get('test')
    self.response.out.write(json.dumps({'data': test}))
    self.response.set_status(200)


class FormHtmlPostHandler(base_handler.Handler):

  @handler.post(handler.FORM, handler.HTML)
  def post(self):
    test = self.request.get('test')
    self.response.out.write(str(test))
    self.response.set_status(200)


class JsonGetHandler(webapp2.RequestHandler):

  @handler.get(handler.JSON)
  def get(self):
    test = self.request.get('test')
    self.response.out.write(json.dumps({'data': test}))
    self.response.set_status(200)


class HtmlGetHandler(webapp2.RequestHandler):

  @handler.get(handler.HTML)
  def get(self):
    test = self.request.get('test')
    self.response.out.write(str(test))
    self.response.set_status(200)


class NeedsPrivilegeAccessHandler(base_handler.Handler):

  @handler.get(handler.JSON)
  @handler.check_user_access(True)
  def get(self):
    self.render_json({'data': 'with'})


class WithoutNeedsPrivilegeAccessHandler(base_handler.Handler):

  @handler.get(handler.JSON)
  @handler.check_user_access(False)
  def get(self):
    self.render_json({'data': 'without'})


class CronHandler(base_handler.Handler):

  @handler.check_cron()
  def get(self):
    self.render_json({})


class CheckTestcaseAccessHandler(base_handler.Handler):

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_testcase_access
  def post(self, testcase):
    self.render_json({'state': testcase.crash_state})


class CheckAdminAccessHandler(base_handler.Handler):

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_admin_access
  def post(self):
    self.render_json({'data': 'admin'})


class CheckAdminAccessIfOssFuzzHandler(base_handler.Handler):

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_admin_access_if_oss_fuzz
  def post(self):
    self.render_json({})


class OAuthHandler(base_handler.Handler):

  @handler.post(handler.JSON, handler.JSON)
  @handler.oauth
  def post(self):
    email = ''
    if users.get_current_user():
      email = users.get_current_user().email()
    self.render_json({'data': email})


class AllowedCorsHandler(base_handler.Handler):

  @handler.allowed_cors
  def post(self):
    self.render_json({'data': 'yes'})


class CronTest(unittest.TestCase):
  """Test check_cron."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.helpers.get_user_email', 'config.db_config.get_value',
        'google.appengine.api.users.is_current_user_admin'
    ])
    self.mock.is_current_user_admin.return_value = False
    self.mock.get_user_email.return_value = 'test@test.com'

    self.testbed = testbed.Testbed()
    self.testbed.activate()
    self.testbed.init_user_stub()
    self.app = webtest.TestApp(webapp2.WSGIApplication([('/', CronHandler)]))

  def tearDown(self):
    self.testbed.deactivate()

  def test_succeed(self):
    """Test request from cron."""
    response = self.app.get('/', headers={'X-Appengine-Cron': 'True'})
    self.assertEqual(200, response.status_int)

  def test_fail(self):
    """Test request from non-cron."""
    response = self.app.get('/', expect_errors=True)
    self.assertEqual(403, response.status_int)


class PostTest(unittest.TestCase):
  """Test post wrapper"""

  def test_post_json_json(self):
    """Post JSON and receive JSON."""
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', JsonJsonPostHandler)]))

    resp = self.app.post_json('/', {'test': 123})
    self.assertEqual('application/json', resp.headers['Content-Type'])
    self.assertEqual(123, resp.json['data'])

  def test_post_json_json_failure(self):
    """Fail to post JSON."""
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', JsonJsonPostHandler)]))

    resp = self.app.post('/', {'test': 123}, expect_errors=True)
    self.assertEqual('application/json', resp.headers['Content-Type'])
    self.assertEqual(400, resp.status_int)

  def test_post_form_html(self):
    """Post Form-data and receive Html."""
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', FormHtmlPostHandler)]))

    resp = self.app.post('/', {'test': 123})
    self.assertNotEqual('application/json', resp.headers['Content-Type'])
    self.assertEqual('123', resp.body)


class GetTest(unittest.TestCase):
  """Test get wrapper."""

  def test_get_json(self):
    """Get and receive JSON."""
    self.app = webtest.TestApp(webapp2.WSGIApplication([('/', JsonGetHandler)]))

    resp = self.app.get('/', {'test': 123})
    self.assertEqual('application/json', resp.headers['Content-Type'])
    self.assertEqual('123', resp.json['data'])

  def test_get_html(self):
    """Get and receive Html."""
    self.app = webtest.TestApp(webapp2.WSGIApplication([('/', HtmlGetHandler)]))

    resp = self.app.get('/', {'test': 123})
    self.assertNotEqual('application/json', resp.headers['Content-Type'])
    self.assertEqual('123', resp.body)


class CheckUserAccessTest(unittest.TestCase):
  """Test check_user_access."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.has_access',
        'libs.helpers.get_user_email',
    ])

  def test_with_needs_privilege_access(self):
    """Test with needs_previlege_access."""
    self.mock.has_access.return_value = True
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', NeedsPrivilegeAccessHandler)]))

    resp = self.app.get('/')
    self.assertEqual(200, resp.status_int)
    self.assertEqual('with', resp.json['data'])
    self.mock.has_access.assert_called_once_with(need_privileged_access=True)

  def test_without_needs_privilege(self):
    """Test without needs_previlege_access."""
    self.mock.has_access.return_value = True
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', WithoutNeedsPrivilegeAccessHandler)]))

    resp = self.app.get('/')
    self.assertEqual(200, resp.status_int)
    self.assertEqual('without', resp.json['data'])
    self.mock.has_access.assert_called_once_with(need_privileged_access=False)

  def test_deny(self):
    """Test deny access."""
    self.mock.has_access.return_value = False
    self.mock.get_user_email.return_value = 'test@test.com'
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', WithoutNeedsPrivilegeAccessHandler)]))

    resp = self.app.get('/', expect_errors=True)
    self.assertEqual(403, resp.status_int)
    self.assertEqual('', resp.json['message'])
    self.assertEqual('test@test.com', resp.json['email'])
    self.mock.has_access.assert_called_once_with(need_privileged_access=False)


class CheckTestcaseAccessTest(unittest.TestCase):
  """Test check_testcase_access."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.check_access_and_get_testcase',
    ])

  def test_no_testcase_id(self):
    """Test no testcase id."""
    self.mock.check_access_and_get_testcase.side_effect = (
        helpers.AccessDeniedException())
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', CheckTestcaseAccessHandler)]))

    resp = self.app.post_json('/', {}, expect_errors=True)
    self.assertEqual(400, resp.status_int)
    self.assertRegexpMatches(resp.json['message'], '.*not a number.*')

  def test_invalid_testcase_id(self):
    """Test invalid testcase id."""
    self.mock.check_access_and_get_testcase.side_effect = (
        helpers.AccessDeniedException())
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', CheckTestcaseAccessHandler)]))

    resp = self.app.post_json('/', {'testcaseId': 'aaa'}, expect_errors=True)
    self.assertEqual(400, resp.status_int)
    self.assertRegexpMatches(resp.json['message'], '.*not a number.*')

  def test_forbidden(self):
    """Test forbidden."""
    self.mock.check_access_and_get_testcase.side_effect = (
        helpers.AccessDeniedException())
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', CheckTestcaseAccessHandler)]))

    resp = self.app.post_json('/', {'testcaseId': '123'}, expect_errors=True)
    self.assertEqual(403, resp.status_int)

  def test_allow(self):
    """Test allow."""
    testcase = data_types.Testcase()
    testcase.crash_state = 'state_value'
    self.mock.check_access_and_get_testcase.return_value = testcase
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', CheckTestcaseAccessHandler)]))

    resp = self.app.post_json('/', {'testcaseId': '123'}, expect_errors=True)
    self.assertEqual(200, resp.status_int)
    self.assertEqual('state_value', resp.json['state'])


class CheckAdminAccessTest(unittest.TestCase):
  """Test check_testcase_access."""

  def setUp(self):
    test_helpers.patch(self, [
        'google.appengine.api.users.is_current_user_admin',
    ])

  def test_allowed(self):
    """Test allowing admin."""
    self.mock.is_current_user_admin.return_value = True
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', CheckAdminAccessHandler)]))

    resp = self.app.post_json('/', {})
    self.assertEqual(200, resp.status_int)
    self.assertEqual('admin', resp.json['data'])

  def test_forbidden(self):
    """Test allowing admin."""
    self.mock.is_current_user_admin.return_value = False
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', CheckAdminAccessHandler)]))

    resp = self.app.post_json('/', {}, expect_errors=True)
    self.assertEqual(403, resp.status_int)


class CheckAdminAccessIfOssFuzzTest(unittest.TestCase):
  """Test check_testcase_access_if_oss_fuzz."""

  def setUp(self):
    test_helpers.patch(self, [
        'base.utils.is_oss_fuzz',
        'google.appengine.api.users.is_current_user_admin',
    ])
    test_helpers.patch_environ(self)
    self.mock.is_oss_fuzz.return_value = False

  def test_allowed_internal(self):
    """Test allowing non-admin and admin in internal."""
    self.mock.is_current_user_admin.return_value = False
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', CheckAdminAccessIfOssFuzzHandler)]))

    resp = self.app.post_json('/', {})
    self.assertEqual(200, resp.status_int)

    self.mock.is_current_user_admin.return_value = True
    resp = self.app.post_json('/', {})
    self.assertEqual(200, resp.status_int)

  def test_allowed_oss_fuzz(self):
    """Test allowing admin in OSS-Fuzz."""
    self.mock.is_oss_fuzz.return_value = True
    self.mock.is_current_user_admin.return_value = True
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', CheckAdminAccessIfOssFuzzHandler)]))

    resp = self.app.post_json('/', {})
    self.assertEqual(200, resp.status_int)

  def test_forbidden_oss_fuzz(self):
    """Test that non-admin in OSS-Fuzz are forbidden."""
    self.mock.is_oss_fuzz.return_value = True
    self.mock.is_current_user_admin.return_value = False
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', CheckAdminAccessIfOssFuzzHandler)]))

    resp = self.app.post_json('/', {}, expect_errors=True)
    self.assertEqual(403, resp.status_int)


class AllowOAuthTest(unittest.TestCase):
  """Test oauth."""

  def setUp(self):
    test_helpers.patch(self, ['libs.handler.get_email_and_access_token'])
    self.app = webtest.TestApp(webapp2.WSGIApplication([('/', OAuthHandler)]))
    test_helpers.patch_environ(self)
    os.environ['AUTH_DOMAIN'] = 'localhost'

  def test_success(self):
    """Test setting environ and header properly."""
    self.mock.get_email_and_access_token.return_value = ('email', 'auth')

    resp = self.app.post_json(
        '/', {}, headers={'Authorization': 'Bearer AccessToken'})
    self.assertEqual(200, resp.status_int)
    self.assertEqual('email', resp.json['data'])
    self.assertEqual('auth',
                     resp.headers[handler.CLUSTERFUZZ_AUTHORIZATION_HEADER])
    self.assertEqual('email',
                     resp.headers[handler.CLUSTERFUZZ_AUTHORIZATION_IDENTITY])
    self.assertEqual(1, self.mock.get_email_and_access_token.call_count)
    self.mock.get_email_and_access_token.assert_has_calls(
        [mock.call('Bearer AccessToken')])

  def test_no_header(self):
    self.mock.get_email_and_access_token.return_value = ('email', 'auth')

    resp = self.app.post_json('/', {}, headers={})
    self.assertEqual(200, resp.status_int)
    self.assertEqual('', resp.json['data'])
    self.assertNotIn(handler.CLUSTERFUZZ_AUTHORIZATION_HEADER, resp.headers)
    self.assertEqual(0, self.mock.get_email_and_access_token.call_count)


class TestGetEmailAndAccessToken(unittest.TestCase):
  """Test get_email_and_access_token."""

  def setUp(self):
    test_helpers.patch(self, [
        'config.db_config.get_value',
        'config.local_config._load_yaml_file',
        'google.appengine.api.urlfetch.fetch',
        'libs.handler.get_access_token',
    ])

    self.mock.get_value.side_effect = mocked_db_config_get_value
    self.mock._load_yaml_file.side_effect = mocked_load_yaml_file  # pylint: disable=protected-access

    config = local_config.AuthConfig()
    self.test_clusterfuzz_tools_oauth_client_id = config.get(
        'clusterfuzz_tools_oauth_client_id')
    self.test_whitelisted_oauth_client_ids = config.get(
        'whitelisted_oauth_client_ids')
    self.test_whitelisted_oauth_emails = config.get('whitelisted_oauth_emails')

  def _assert_fetch_call(self):
    self.assertEqual(1, self.mock.fetch.call_count)
    self.mock.fetch.assert_has_calls([
        mock.call(
            url=('https://www.googleapis.com/oauth2/v3/tokeninfo'
                 '?access_token=AccessToken'),
            validate_certificate=True)
    ])
    self.mock.fetch.reset_mock()

  def test_allowed_bearer(self):
    """Test allowing Bearer."""
    for aud in self.test_whitelisted_oauth_client_ids:
      self.mock.fetch.return_value = mock.Mock(
          status_code=200,
          content=json.dumps({
              'aud': aud,
              'email': 'test@test.com',
              'email_verified': True
          }))

      email, auth = handler.get_email_and_access_token('Bearer AccessToken')
      self.assertEqual('test@test.com', email)
      self.assertEqual('Bearer AccessToken', auth)
      self._assert_fetch_call()

  def test_allow_whitelised_accounts(self):
    """Test allow compute engine service account."""
    for email in self.test_whitelisted_oauth_emails:
      self.mock.fetch.reset_mock()
      self.mock.fetch.return_value = mock.Mock(
          status_code=200,
          content=json.dumps({
              'email_verified': True,
              'email': email
          }))

      returned_email, auth = handler.get_email_and_access_token(
          'Bearer AccessToken')
      self.assertEqual(email, returned_email)
      self.assertEqual('Bearer AccessToken', auth)
      self._assert_fetch_call()

  def test_allowed_verification_code(self):
    """Test allowing VerificationCode."""
    self.mock.fetch.return_value = mock.Mock(
        status_code=200,
        content=json.dumps({
            'aud': self.test_clusterfuzz_tools_oauth_client_id,
            'email': 'test@test.com',
            'email_verified': True
        }))
    self.mock.get_access_token.return_value = 'AccessToken'

    email, auth = handler.get_email_and_access_token('VerificationCode Verify')
    self.assertEqual('test@test.com', email)
    self.assertEqual('Bearer AccessToken', auth)
    self.assertEqual(1, self.mock.get_access_token.call_count)
    self.mock.get_access_token.assert_has_calls(
        [mock.call(verification_code='Verify')])
    self._assert_fetch_call()

  def test_invalid_authorization_header(self):
    """Test invalid authorization header."""
    with self.assertRaises(helpers.UnauthorizedException) as cm:
      handler.get_email_and_access_token('ReceiverAccessToken')

    self.assertEqual(401, cm.exception.status)
    self.assertEqual(
        'The Authorization header is invalid. It should have been started with'
        " 'Bearer '.", cm.exception.message)
    self.assertEqual(0, self.mock.fetch.call_count)

  def test_bad_status(self):
    """Test bad status."""
    self.mock.fetch.return_value = mock.Mock(status_code=403)

    with self.assertRaises(helpers.UnauthorizedException) as cm:
      handler.get_email_and_access_token('Bearer AccessToken')
    self.assertEqual(401, cm.exception.status)
    self.assertEqual(
        ('Failed to authorize. The Authorization header (Bearer AccessToken)'
         ' might be invalid.'), cm.exception.message)
    self._assert_fetch_call()

  def test_invalid_json(self):
    """Test invalid json."""
    self.mock.fetch.return_value = mock.Mock(status_code=200, content='test')

    with self.assertRaises(helpers.EarlyExitException) as cm:
      handler.get_email_and_access_token('Bearer AccessToken')
    self.assertEqual(500, cm.exception.status)
    self.assertEqual('Parsing the JSON response body failed: test',
                     cm.exception.message)
    self._assert_fetch_call()

  def test_invalid_client_id(self):
    """Test the invalid client id."""
    self.mock.fetch.return_value = mock.Mock(
        status_code=200,
        content=json.dumps({
            'aud': 'InvalidClientId',
            'email': 'test@test.com',
            'email_verified': False
        }))

    with self.assertRaises(helpers.EarlyExitException) as cm:
      handler.get_email_and_access_token('Bearer AccessToken')
    self.assertEqual(401, cm.exception.status)
    self.assertIn(
        "The access token doesn't belong to one of the allowed OAuth clients",
        cm.exception.message)
    self._assert_fetch_call()

  def test_unverified_email(self):
    """Test unverified email."""
    self.mock.fetch.return_value = mock.Mock(
        status_code=200,
        content=json.dumps({
            'aud': self.test_clusterfuzz_tools_oauth_client_id,
            'email': 'test@test.com',
            'email_verified': False
        }))

    with self.assertRaises(helpers.EarlyExitException) as cm:
      handler.get_email_and_access_token('Bearer AccessToken')
    self.assertEqual(401, cm.exception.status)
    self.assertIn('The email (test@test.com) is not verified',
                  cm.exception.message)
    self._assert_fetch_call()


class TestGetAccessToken(unittest.TestCase):
  """Test get_access_token."""

  def setUp(self):
    test_helpers.patch(self, [
        'config.db_config.get_value',
        'config.local_config._load_yaml_file',
        'google.appengine.api.urlfetch.fetch',
    ])

    self.mock.get_value.side_effect = mocked_db_config_get_value
    self.mock._load_yaml_file.side_effect = mocked_load_yaml_file  # pylint: disable=protected-access

    config = local_config.AuthConfig()
    self.test_clusterfuzz_tools_oauth_client_id = config.get(
        'clusterfuzz_tools_oauth_client_id')

  def _assert_fetch_call(self):
    self.assertEqual(1, self.mock.fetch.call_count)
    self.mock.fetch.assert_has_calls([
        mock.call(
            url='https://www.googleapis.com/oauth2/v4/token',
            method=urlfetch.POST,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            payload=urllib.urlencode({
                'code': 'verify',
                'client_id': self.test_clusterfuzz_tools_oauth_client_id,
                'client_secret': 'Secret',
                'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
                'grant_type': 'authorization_code'
            }),
            validate_certificate=True)
    ])

  def test_succeed(self):
    """Test succeed."""
    self.mock.fetch.return_value = mock.Mock(
        status_code=200, content=json.dumps({
            'access_token': 'token'
        }))

    token = handler.get_access_token('verify')
    self.assertEqual('token', token)
    self._assert_fetch_call()

  def test_bad_status(self):
    """Test invalid_json."""
    self.mock.fetch.return_value = mock.Mock(status_code=403, content='test')

    with self.assertRaises(helpers.UnauthorizedException) as cm:
      handler.get_access_token('verify')
    self.assertEqual(401, cm.exception.status)
    self.assertEqual('Invalid verification code (verify): test',
                     cm.exception.message)
    self.assertEqual(1, self.mock.fetch.call_count)
    self._assert_fetch_call()

  def test_invalid_json(self):
    """Test invalid_json."""
    self.mock.fetch.return_value = mock.Mock(status_code=200, content='test')

    with self.assertRaises(helpers.EarlyExitException) as cm:
      handler.get_access_token('verify')
    self.assertEqual(500, cm.exception.status)
    self.assertEqual('Parsing the JSON response body failed: test',
                     cm.exception.message)
    self.assertEqual(1, self.mock.fetch.call_count)
    self._assert_fetch_call()


class AllowedCorsHandlerTest(unittest.TestCase):
  """Test allowed_cors."""

  def setUp(self):
    test_helpers.patch(self, [
        'config.local_config._load_yaml_file',
    ])

    self.mock._load_yaml_file.side_effect = mocked_load_yaml_file  # pylint: disable=protected-access

    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', AllowedCorsHandler)]))

  def test_allow_cors(self):
    """Tests valid origins."""
    origins = [
        'http://test-client-site.appspot.com',
        'https://test-client-site-staging.appspot.com',
        'https://suborigin-dot-test-client-site.appspot.com',
        'http://suborigin-dot-test-client-site-staging.appspot.com',
    ]
    for origin in origins:
      resp = self.app.post_json('/', {}, headers={'Origin': origin})
      self.assertEqual(200, resp.status_int)
      self.assertEqual('yes', resp.json['data'])
      self.assertEqual(origin, resp.headers['Access-Control-Allow-Origin'])
      self.assertEqual('Origin', resp.headers['Vary'])
      self.assertEqual('true', resp.headers['Access-Control-Allow-Credentials'])
      self.assertEqual('GET,OPTIONS,POST',
                       resp.headers['Access-Control-Allow-Methods'])
      self.assertEqual('Accept,Authorization,Content-Type',
                       resp.headers['Access-Control-Allow-Headers'])
      self.assertEqual('3600', resp.headers['Access-Control-Max-Age'])

  def test_no_origin(self):
    """Tests no origin."""
    resp = self.app.post_json('/', {})
    self.assertEqual(200, resp.status_int)
    self.assertEqual('yes', resp.json['data'])
    self.assertIsNone(resp.headers.get('Access-Control-Allow-Origin'))

  def test_invalid_origin(self):
    """Tests no origin."""
    origins = [
        'http://bad-test-client-site.appspot.com',
        'https://bad-test-client-site-staging.appspot.com',
        'https://bad-test-client-site.appspot.com',
        'http://bad-test-client-site-staging.appspot.com',
    ]
    for origin in origins:
      resp = self.app.post_json('/', {'Origin': origin})
      self.assertEqual(200, resp.status_int)
      self.assertEqual('yes', resp.json['data'])
      self.assertIsNone(resp.headers.get('Access-Control-Allow-Origin'))

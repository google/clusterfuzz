# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for Handler."""

import json
import os
import unittest

import flask
from flask import request
from flask import Response
import mock
import webtest
import yaml

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from handlers import base_handler
from libs import auth
from libs import handler
from libs import helpers

_JSON_CONTENT_TYPE = 'application/json'


def mocked_db_config_get_value(key):
  """Return mocked values from db_config's get_value function."""
  if key == 'reproduce_tool_client_id':
    return 'ClientId'
  if key == 'reproduce_tool_client_secret':
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
  """Handler for json json post requests."""

  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    test = request.get('test')
    response = Response()
    response.data = json.dumps({'data': test})
    response.status_code = 200
    return response


class FormHtmlPostHandler(base_handler.Handler):
  """Handler for form html post requests."""

  @handler.post(handler.FORM, handler.HTML)
  def post(self):
    test = request.form.get('test')
    response = Response()
    response.data = str(test)
    response.status_code = 200
    return response


class JsonGetHandler(base_handler.Handler):
  """Handler for json get requests."""

  @handler.get(handler.JSON)
  def get(self):
    test = request.get('test')
    response = Response()
    response.data = json.dumps({'data': test})
    response.status_code = 200
    return response


class HtmlGetHandler(base_handler.Handler):
  """Handler for html get requests."""

  @handler.get(handler.HTML)
  def get(self):
    test = request.get('test')
    response = Response()
    response.data = str(test)
    response.status_code = 200
    return response


class NeedsPrivilegeAccessHandler(base_handler.Handler):
  """Handler for needs privilege access requests."""

  @handler.get(handler.JSON)
  @handler.check_user_access(True)
  def get(self):
    return self.render_json({'data': 'with'})


class WithoutNeedsPrivilegeAccessHandler(base_handler.Handler):
  """Handler for without needs privilege access requests."""

  @handler.get(handler.JSON)
  @handler.check_user_access(False)
  def get(self):
    return self.render_json({'data': 'without'})


class CronHandler(base_handler.Handler):
  """Handler for crons."""

  @handler.cron()
  def get(self):
    return self.render_json({})


class CheckTestcaseAccessHandler(base_handler.Handler):
  """Handler for check testcase access requests."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_testcase_access
  def post(self, testcase):
    print("returning render_json")
    return self.render_json({'state': testcase.crash_state})


class CheckAdminAccessHandler(base_handler.Handler):
  """Handler for check admin access requests."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_admin_access
  def post(self):
    return self.render_json({'data': 'admin'})


class CheckAdminAccessIfOssFuzzHandler(base_handler.Handler):
  """Handler for check admin access if oss fuzz requests."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_admin_access_if_oss_fuzz
  def post(self):
    return self.render_json({})


class OAuthHandler(base_handler.Handler):
  """Handler for oauth requests."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.oauth
  def post(self):
    email = ''
    if auth.get_current_user():
      email = auth.get_current_user().email
    return self.render_json({'data': email})


class AllowedCorsHandler(base_handler.Handler):
  """Handler for allowed cors requests."""

  @handler.allowed_cors
  def post(self):
    return self.render_json({'data': 'yes'})


class CronTest(unittest.TestCase):
  """Test cron."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.config.db_config.get_value',
        'libs.form.generate_csrf_token',
        'libs.auth.is_current_user_admin',
        'libs.auth.get_current_user',
    ])
    self.mock.generate_csrf_token.return_value = 'csrf_token'
    self.mock.is_current_user_admin.return_value = False
    self.mock.get_current_user.return_value = auth.User('test@test.com')

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=CronHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

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
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=JsonJsonPostHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {'test': 123})
    self.assertEqual(_JSON_CONTENT_TYPE, resp.headers['Content-Type'])
    self.assertEqual(123, resp.json['data'])

  def test_post_json_json_failure(self):
    """Fail to post JSON."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=JsonJsonPostHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post('/', {'test': 123}, expect_errors=True)
    self.assertEqual(_JSON_CONTENT_TYPE, resp.headers['Content-Type'])
    self.assertEqual(400, resp.status_int)

  def test_post_form_html(self):
    """Post Form-data and receive Html."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=FormHtmlPostHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post('/', {'test': 123})
    self.assertNotEqual('application/json', resp.headers['Content-Type'])
    self.assertEqual(b'123', resp.body)


class GetTest(unittest.TestCase):
  """Test get wrapper."""

  def test_get_json(self):
    """Get and receive JSON."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=JsonGetHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.get('/', {'test': 123})
    self.assertEqual(_JSON_CONTENT_TYPE, resp.headers['Content-Type'])
    self.assertEqual('123', resp.json['data'])

  def test_get_html(self):
    """Get and receive Html."""
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=HtmlGetHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.get('/', {'test': 123})
    self.assertNotEqual('application/json', resp.headers['Content-Type'])
    self.assertEqual(b'123', resp.body)


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
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=NeedsPrivilegeAccessHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.get('/')
    self.assertEqual(200, resp.status_int)
    self.assertEqual('with', resp.json['data'])
    self.mock.has_access.assert_called_once_with(need_privileged_access=True)

  def test_without_needs_privilege(self):
    """Test without needs_previlege_access."""
    self.mock.has_access.return_value = True
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=WithoutNeedsPrivilegeAccessHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.get('/')
    self.assertEqual(200, resp.status_int)
    self.assertEqual('without', resp.json['data'])
    self.mock.has_access.assert_called_once_with(need_privileged_access=False)

  def test_deny(self):
    """Test deny access."""
    self.mock.has_access.return_value = False
    self.mock.get_user_email.return_value = 'test@test.com'
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=WithoutNeedsPrivilegeAccessHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

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
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=CheckTestcaseAccessHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {}, expect_errors=True)
    #print(resp)
    self.assertEqual(400, resp.status_int)
    self.assertRegex(resp.json['message'], '.*not a number.*')

  def test_invalid_testcase_id(self):
    """Test invalid testcase id."""
    self.mock.check_access_and_get_testcase.side_effect = (
        helpers.AccessDeniedException())
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=CheckTestcaseAccessHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {'testcaseId': 'aaa'}, expect_errors=True)
    self.assertEqual(400, resp.status_int)
    self.assertRegex(resp.json['message'], '.*not a number.*')

  def test_forbidden(self):
    """Test forbidden."""
    self.mock.check_access_and_get_testcase.side_effect = (
        helpers.AccessDeniedException())
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=CheckTestcaseAccessHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {'testcaseId': '123'}, expect_errors=True)
    self.assertEqual(403, resp.status_int)

  def test_allow(self):
    """Test allow."""
    testcase = data_types.Testcase()
    testcase.crash_state = 'state_value'
    self.mock.check_access_and_get_testcase.return_value = testcase
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=CheckTestcaseAccessHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {'testcaseId': '123'}, expect_errors=True)
    self.assertEqual(200, resp.status_int)
    self.assertEqual('state_value', resp.json['state'])


class CheckAdminAccessTest(unittest.TestCase):
  """Test check_testcase_access."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.auth.is_current_user_admin',
    ])

  def test_allowed(self):
    """Test allowing admin."""
    self.mock.is_current_user_admin.return_value = True
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=CheckAdminAccessHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {})
    self.assertEqual(200, resp.status_int)
    self.assertEqual('admin', resp.json['data'])

  def test_forbidden(self):
    """Test allowing admin."""
    self.mock.is_current_user_admin.return_value = False
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=CheckAdminAccessHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {}, expect_errors=True)
    self.assertEqual(403, resp.status_int)


class CheckAdminAccessIfOssFuzzTest(unittest.TestCase):
  """Test check_testcase_access_if_oss_fuzz."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.is_oss_fuzz',
        'libs.auth.is_current_user_admin',
    ])
    test_helpers.patch_environ(self)
    self.mock.is_oss_fuzz.return_value = False

  def test_allowed_internal(self):
    """Test allowing non-admin and admin in internal."""
    self.mock.is_current_user_admin.return_value = False
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=CheckAdminAccessIfOssFuzzHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {})
    self.assertEqual(200, resp.status_int)

    self.mock.is_current_user_admin.return_value = True
    resp = self.app.post_json('/', {})
    self.assertEqual(200, resp.status_int)

  def test_allowed_oss_fuzz(self):
    """Test allowing admin in OSS-Fuzz."""
    self.mock.is_oss_fuzz.return_value = True
    self.mock.is_current_user_admin.return_value = True
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=CheckAdminAccessIfOssFuzzHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {})
    self.assertEqual(200, resp.status_int)

  def test_forbidden_oss_fuzz(self):
    """Test that non-admin in OSS-Fuzz are forbidden."""
    self.mock.is_oss_fuzz.return_value = True
    self.mock.is_current_user_admin.return_value = False
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/', view_func=CheckAdminAccessIfOssFuzzHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    resp = self.app.post_json('/', {}, expect_errors=True)
    self.assertEqual(403, resp.status_int)


class AllowOAuthTest(unittest.TestCase):
  """Test oauth."""

  def setUp(self):
    test_helpers.patch(self, ['libs.handler.get_email_and_access_token'])
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=OAuthHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)
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
        'clusterfuzz._internal.config.db_config.get_value',
        'clusterfuzz._internal.config.local_config._load_yaml_file',
        'libs.handler.get_access_token',
        'requests.get',
    ])

    self.mock.get_value.side_effect = mocked_db_config_get_value
    self.mock._load_yaml_file.side_effect = mocked_load_yaml_file  # pylint: disable=protected-access

    config = local_config.AuthConfig()
    self.test_whitelisted_oauth_client_ids = config.get(
        'whitelisted_oauth_client_ids')
    self.test_whitelisted_oauth_emails = config.get('whitelisted_oauth_emails')

  def _assert_requests_get_call(self):
    self.assertEqual(1, self.mock.get.call_count)
    self.mock.get.assert_has_calls([
        mock.call(
            'https://www.googleapis.com/oauth2/v3/tokeninfo',
            params={'access_token': 'AccessToken'})
    ])
    self.mock.get.reset_mock()

  def test_allowed_bearer(self):
    """Test allowing Bearer."""
    for aud in self.test_whitelisted_oauth_client_ids:
      self.mock.get.return_value = mock.Mock(
          status_code=200,
          text=json.dumps({
              'aud': aud,
              'email': 'test@test.com',
              'email_verified': True
          }))

      email, token = handler.get_email_and_access_token('Bearer AccessToken')
      self.assertEqual('test@test.com', email)
      self.assertEqual('Bearer AccessToken', token)
      self._assert_requests_get_call()

  def test_allow_whitelised_accounts(self):
    """Test allow compute engine service account."""
    for email in self.test_whitelisted_oauth_emails:
      self.mock.get.reset_mock()
      self.mock.get.return_value = mock.Mock(
          status_code=200,
          text=json.dumps({
              'email_verified': True,
              'email': email
          }))

      returned_email, token = handler.get_email_and_access_token(
          'Bearer AccessToken')
      self.assertEqual(email, returned_email)
      self.assertEqual('Bearer AccessToken', token)
      self._assert_requests_get_call()

  def test_allowed_verification_code(self):
    """Test allowing VerificationCode."""
    self.mock.get.return_value = mock.Mock(
        status_code=200,
        text=json.dumps({
            'aud': 'ClientId',
            'email': 'test@test.com',
            'email_verified': True
        }))
    self.mock.get_access_token.return_value = 'AccessToken'

    email, token = handler.get_email_and_access_token('VerificationCode Verify')
    self.assertEqual('test@test.com', email)
    self.assertEqual('Bearer AccessToken', token)
    self.assertEqual(1, self.mock.get_access_token.call_count)
    self.mock.get_access_token.assert_has_calls([mock.call('Verify')])
    self._assert_requests_get_call()

  def test_invalid_authorization_header(self):
    """Test invalid authorization header."""
    with self.assertRaises(helpers.UnauthorizedException) as cm:
      handler.get_email_and_access_token('ReceiverAccessToken')

    self.assertEqual(401, cm.exception.status)
    self.assertEqual(
        'The Authorization header is invalid. It should have been started with'
        " 'Bearer '.", str(cm.exception))
    self.assertEqual(0, self.mock.get.call_count)

  def test_bad_status(self):
    """Test bad status."""
    self.mock.get.return_value = mock.Mock(status_code=403)

    with self.assertRaises(helpers.UnauthorizedException) as cm:
      handler.get_email_and_access_token('Bearer AccessToken')
    self.assertEqual(401, cm.exception.status)
    self.assertEqual(
        ('Failed to authorize. The Authorization header (Bearer AccessToken)'
         ' might be invalid.'), str(cm.exception))
    self._assert_requests_get_call()

  def test_invalid_json(self):
    """Test invalid json."""
    self.mock.get.return_value = mock.Mock(status_code=200, text='test')

    with self.assertRaises(helpers.EarlyExitException) as cm:
      handler.get_email_and_access_token('Bearer AccessToken')
    self.assertEqual(500, cm.exception.status)
    self.assertEqual('Parsing the JSON response body failed: test',
                     str(cm.exception))
    self._assert_requests_get_call()

  def test_invalid_client_id(self):
    """Test the invalid client id."""
    self.mock.get.return_value = mock.Mock(
        status_code=200,
        text=json.dumps({
            'aud': 'InvalidClientId',
            'email': 'test@test.com',
            'email_verified': False
        }))

    with self.assertRaises(helpers.EarlyExitException) as cm:
      handler.get_email_and_access_token('Bearer AccessToken')
    self.assertEqual(401, cm.exception.status)
    self.assertIn(
        "The access token doesn't belong to one of the allowed OAuth clients",
        str(cm.exception))
    self._assert_requests_get_call()

  def test_unverified_email(self):
    """Test unverified email."""
    self.mock.get.return_value = mock.Mock(
        status_code=200,
        text=json.dumps({
            'aud': 'ClientId',
            'email': 'test@test.com',
            'email_verified': False
        }))

    with self.assertRaises(helpers.EarlyExitException) as cm:
      handler.get_email_and_access_token('Bearer AccessToken')
    self.assertEqual(401, cm.exception.status)
    self.assertIn('The email (test@test.com) is not verified',
                  str(cm.exception))
    self._assert_requests_get_call()


class TestGetAccessToken(unittest.TestCase):
  """Test get_access_token."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.config.db_config.get_value',
        'clusterfuzz._internal.config.local_config._load_yaml_file',
        'requests.post',
    ])

    self.mock.get_value.side_effect = mocked_db_config_get_value
    self.mock._load_yaml_file.side_effect = mocked_load_yaml_file  # pylint: disable=protected-access

  def _assert_requests_post_call(self):
    self.assertEqual(1, self.mock.post.call_count)
    self.mock.post.assert_has_calls([
        mock.call(
            'https://www.googleapis.com/oauth2/v4/token',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data={
                'code': 'verify',
                'client_id': 'ClientId',
                'client_secret': 'Secret',
                'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
                'grant_type': 'authorization_code'
            })
    ])

  def test_succeed(self):
    """Test succeed."""
    self.mock.post.return_value = mock.Mock(
        status_code=200, text=json.dumps({
            'access_token': 'token'
        }))

    token = handler.get_access_token('verify')
    self.assertEqual('token', token)
    self._assert_requests_post_call()

  def test_bad_status(self):
    """Test invalid_json."""
    self.mock.post.return_value = mock.Mock(status_code=403, text='test')

    with self.assertRaises(helpers.UnauthorizedException) as cm:
      handler.get_access_token('verify')
    self.assertEqual(401, cm.exception.status)
    self.assertEqual('Invalid verification code (verify): test',
                     str(cm.exception))
    self._assert_requests_post_call()

  def test_invalid_json(self):
    """Test invalid_json."""
    self.mock.post.return_value = mock.Mock(status_code=200, text='test')

    with self.assertRaises(helpers.EarlyExitException) as cm:
      handler.get_access_token('verify')
    self.assertEqual(500, cm.exception.status)
    self.assertEqual('Parsing the JSON response body failed: test',
                     str(cm.exception))
    self._assert_requests_post_call()


class AllowedCorsHandlerTest(unittest.TestCase):
  """Test allowed_cors."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.config.local_config._load_yaml_file',
    ])

    self.mock._load_yaml_file.side_effect = mocked_load_yaml_file  # pylint: disable=protected-access

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=AllowedCorsHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

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

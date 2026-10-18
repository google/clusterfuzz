# Copyright 2026 Google LLC
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
"""Tests for corpora."""
import datetime
import unittest
from unittest import mock

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from handlers import corpora


class CorporaTest(unittest.TestCase):
  """Tests for the create and delete corpus handlers."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.is_oss_fuzz',
        'clusterfuzz._internal.config.db_config.get_value',
        'handlers.base_handler.Handler.render',
        'clusterfuzz._internal.datastore.data_handler.'
        'create_data_bundle_bucket_and_iams',
        'libs.access.has_access',
        'libs.auth.get_current_user',
        'libs.auth.is_current_user_admin',
        'libs.form.generate_csrf_token',
        'libs.helpers.get_user_email',
    ])
    self.mock.is_oss_fuzz.return_value = True
    self.mock.has_access.return_value = True
    self.mock.is_current_user_admin.return_value = False
    self.mock.get_user_email.return_value = 'user@example.com'
    self.mock.generate_csrf_token.return_value = 'csrf_token'
    self.mock.render.side_effect = self._render
    self.mock.get_current_user.return_value = mock.Mock(
        email='user@example.com')

    # These handlers query Datastore, which isn't available here. Replace the
    # `data_types` module as seen by the handler and the CSRF check.
    self.data_types = mock.Mock(wraps=data_types)
    self.data_types.DataBundle = mock.Mock()
    self.data_types.DataBundle.VALID_NAME_REGEX = (
        data_types.DataBundle.VALID_NAME_REGEX)
    self.data_types.DataBundle.query.return_value.get.return_value = None
    csrf_data_types = mock.Mock()
    csrf_data_types.CSRFToken.query.return_value.get.return_value = mock.Mock(
        expiration_time=datetime.datetime.utcnow() +
        datetime.timedelta(hours=1))
    self.data_types.Fuzzer.query.return_value = []
    self.ndb = mock.Mock()
    for target, replacement in (('handlers.corpora.data_types',
                                 self.data_types), ('handlers.corpora.ndb',
                                                    self.ndb),
                                ('libs.handler.data_types', csrf_data_types)):
      patcher = mock.patch(target, replacement)
      patcher.start()
      self.addCleanup(patcher.stop)

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/create', view_func=corpora.CreateHandler.as_view('/create'))
    flaskapp.add_url_rule(
        '/delete', view_func=corpora.DeleteHandler.as_view('/delete'))
    self.app = webtest.TestApp(flaskapp)

  @staticmethod
  def _render(_, path, values=None, status=200):
    """Stand-in for rendering, which needs built templates, keeping status."""
    del values
    response = flask.make_response(path)
    response.status_code = status
    return response

  def _create(self, name='corpus', **kwargs):
    return self.app.post('/create', {
        'name': name,
        'csrf_token': 'token'
    }, **kwargs)

  def test_create_requires_admin_on_oss_fuzz(self):
    """A privileged non-admin cannot create a corpus on OSS-Fuzz."""
    response = self._create(expect_errors=True)

    self.assertEqual(403, response.status_int)
    self.assertFalse(self.mock.create_data_bundle_bucket_and_iams.called)
    self.assertFalse(self.data_types.DataBundle.query.called)

  def test_delete_requires_admin_on_oss_fuzz(self):
    """A privileged non-admin cannot delete a corpus on OSS-Fuzz."""
    response = self.app.post(
        '/delete', {
            'key': '1',
            'csrf_token': 'token'
        }, expect_errors=True)

    self.assertEqual(403, response.status_int)
    self.assertFalse(self.ndb.Key.called)

  def test_delete_as_admin_on_oss_fuzz(self):
    """An admin can delete a corpus on OSS-Fuzz."""
    self.mock.is_current_user_admin.return_value = True

    response = self.app.post('/delete', {'key': '1', 'csrf_token': 'token'})

    self.assertEqual(200, response.status_int)
    data_bundle = self.ndb.Key.return_value.get.return_value
    data_bundle.key.delete.assert_called_once_with()

  def test_create_as_admin_on_oss_fuzz(self):
    """An admin can create a corpus on OSS-Fuzz."""
    self.mock.is_current_user_admin.return_value = True
    self.mock.create_data_bundle_bucket_and_iams.return_value = True

    response = self._create()

    self.assertEqual(200, response.status_int)
    self.mock.create_data_bundle_bucket_and_iams.assert_called_once_with(
        'corpus', ['user@example.com'])
    self.data_types.DataBundle.return_value.put.assert_called_once_with()

  def test_create_as_privileged_user_off_oss_fuzz(self):
    """A privileged non-admin can still create a corpus outside OSS-Fuzz."""
    self.mock.is_oss_fuzz.return_value = False
    self.mock.create_data_bundle_bucket_and_iams.return_value = True

    response = self._create()

    self.assertEqual(200, response.status_int)
    self.mock.create_data_bundle_bucket_and_iams.assert_called_once_with(
        'corpus', ['user@example.com'])

  def test_create_rejects_existing_corpus(self):
    """Creating an existing corpus fails and leaves its bucket IAM alone."""
    self.mock.is_current_user_admin.return_value = True
    self.data_types.DataBundle.query.return_value.get.return_value = (
        mock.Mock())

    response = self._create(expect_errors=True)

    self.assertEqual(400, response.status_int)
    self.assertFalse(self.mock.create_data_bundle_bucket_and_iams.called)
    self.assertFalse(self.data_types.DataBundle.return_value.put.called)


if __name__ == '__main__':
  unittest.main()

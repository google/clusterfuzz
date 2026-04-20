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
"""Tests for fuzzers handler."""
# pylint: disable=protected-access

import datetime
import unittest

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import fuzzers
from libs import form


class BaseEditHandlerTest(unittest.TestCase):
  """Test BaseEditHandler."""

  def setUp(self):
    self.handler = fuzzers.BaseEditHandler()

  def test_get_fuzzer_state_str(self):
    """Test that fuzzer state str excludes specific fields."""
    fuzzer = data_types.Fuzzer(
        name='test_fuzzer',
        revision=1,
        timeout=10,
        result='bad',
        console_output='some output',
        result_timestamp=datetime.datetime(2021, 1, 1),
        return_code=1,
        sample_testcase='testcase',
        stats_columns='cols',
        stats_column_descriptions='desc',
    )

    state_str = self.handler._get_fuzzer_state_str(fuzzer)

    self.assertIn('name: test_fuzzer', state_str)
    self.assertIn('revision: 1', state_str)
    self.assertIn('timeout: 10', state_str)

    # Explicitly excluded fields
    self.assertNotIn('result:', state_str)
    self.assertNotIn('result_timestamp', state_str)
    self.assertNotIn('console_output:', state_str)
    self.assertNotIn('return_code:', state_str)
    self.assertNotIn('sample_testcase:', state_str)
    self.assertNotIn('stats_columns:', state_str)
    self.assertNotIn('stats_column_descriptions:', state_str)


@test_utils.with_cloud_emulators('datastore')
class CreateHandlerTest(unittest.TestCase):
  """Tests CreateHandler creates a new Fuzzer"""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.has_access',
        'libs.auth.get_current_user',
        'libs.helpers.get_user_email',
        'handlers.fuzzers.datetime',
        'handlers.fuzzers.CreateHandler.get_upload',
        'handlers.fuzzers.CreateHandler.apply_fuzzer_changes',
    ])
    self.mock.has_access.return_value = True
    self.mock.get_current_user().email = 'test@user.com'
    self.mock.get_user_email.return_value = 'test@user.com'

    self.mock_time = datetime.datetime(2026, 1, 1, tzinfo=None)
    self.mock.datetime.datetime.now.return_value = self.mock_time
    self.mock.datetime.timezone = datetime.timezone

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=fuzzers.CreateHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

  def test_create_fuzzer(self):
    """Test create fuzzer with basic properties."""
    fuzzer_name = 'test_fuzzer'

    resp = self.app.post_json('/', {
        'csrf_token': form.generate_csrf_token(),
        'name': fuzzer_name,
    })

    self.assertEqual(200, resp.status_int)

    self.mock.apply_fuzzer_changes.assert_called_once()

    fuzzer = self.mock.apply_fuzzer_changes.call_args[0][1]

    self.assertEqual(fuzzer.name, fuzzer_name)
    self.assertEqual(fuzzer.revision, 0)
    self.assertEqual(fuzzer.created_at, self.mock_time)


@test_utils.with_cloud_emulators('datastore')
class EditHandlerTest(unittest.TestCase):
  """Tests EditHandler updates an existing Fuzzer"""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.has_access',
        'libs.auth.get_current_user',
        'libs.helpers.get_user_email',
        'handlers.fuzzers.datetime',
        'handlers.fuzzers.EditHandler.get_upload',
        'handlers.fuzzers.EditHandler._get_executable_path',
        'handlers.fuzzers.EditHandler._get_launcher_script',
    ])
    self.mock.has_access.return_value = True
    self.mock.get_current_user().email = 'test@user.com'
    self.mock.get_user_email.return_value = 'test@user.com'
    self.mock.get_upload.return_value = storage.GcsBlobInfo(
        bucket='test-bucket', object_path='key', filename='file.zip', size=123)

    self.mock._get_executable_path.return_value = 'executable'
    self.mock._get_launcher_script.return_value = 'launcher'

    self.mock_time = datetime.datetime(2026, 1, 1, tzinfo=None)
    self.mock.datetime.datetime.now.return_value = self.mock_time
    self.mock.datetime.timezone = datetime.timezone

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/fuzzers/edit', view_func=fuzzers.EditHandler.as_view('/fuzzers/edit'))
    self.app = webtest.TestApp(flaskapp)

  def test_update_fuzzer(self):
    """Test fuzzers/edit updates the fuzzer"""

    fuzzer_name = 'test_fuzzer'
    fuzzer = data_types.Fuzzer(
        name=fuzzer_name,
        jobs=[],
        revision=1,
        timeout=10,
    )
    fuzzer.put()

    request_payload = {
        'additional_environment_string': 'args=123',
        'csrf_token': form.generate_csrf_token(),
        'data_bundle_name': 'test_bundle',
        'external_contribution': True,
        'jobs': [],
        'key': fuzzer.key.id(),
        'max_testcases': 100,
        'name': fuzzer_name,
        'timeout': 30,
    }

    self.app.post_json('/fuzzers/edit', request_payload)

    fuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == fuzzer_name).get()

    self.assertEqual(
        fuzzer.get_config_dict(), {
            'additional_environment_string': 'args=123',
            'data_bundle_name': 'test_bundle',
            'external_contribution': True,
            'executable_path': 'executable',
            'launcher_script': 'launcher',
            'jobs': [],
            'max_testcases': 100,
            'revision': 2,
            'source': 'test@user.com',
            'timeout': 30,
        })

# Copyright 2021 Google LLC
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
"""Tests for external_update."""

import base64
import datetime
import json
import os
import unittest

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import external_update

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'external_update_data')


@test_utils.with_cloud_emulators('datastore')
class ExternalUpdatesTest(unittest.TestCase):
  """Test external updates."""

  def _read_test_data(self, name):
    """Helper function to read test data."""
    with open(os.path.join(DATA_DIRECTORY, name), 'rb') as handle:
      return handle.read()

  def setUp(self):
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/external-update', view_func=external_update.Handler.as_view(''))
    self.app = webtest.TestApp(flaskapp)

    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
        'google.oauth2.id_token.verify_oauth2_token',
    ])

    self.mock.verify_oauth2_token.return_value = {
        'email_verified': True,
        'email': 'test-clusterfuzz@appspot.gserviceaccount.com',
    }
    self.mock.utcnow.return_value = datetime.datetime(2021, 1, 1)

    data_types.Job(
        name='libfuzzer_external_job',
        external_reproduction_topic='topic',
        external_updates_subscription='subscription').put()
    data_types.Job(name='job').put()

    data_types.FuzzTarget(engine='libFuzzer', binary='fuzzer').put()

    self.testcase = data_types.Testcase(
        open=True,
        status='Processed',
        fuzzer_name='libFuzzer',
        overridden_fuzzer_name='libFuzzer_fuzzer',
        job_type='libfuzzer_external_job',
        crash_state=('blink::InputTypeView::element\n'
                     'blink::TextFieldInputType::didSetValueByUserEdit\n'
                     'blink::TextFieldInputType::subtreeHasChanged\n'),
        crash_revision=1336,
        crash_stacktrace='original',
        last_tested_crash_stacktrace='last_tested',
        crash_type='',
        security_flag=True)
    self.testcase.put()

  def _make_message(self, data, attributes):
    """Make a message."""
    return json.dumps({
        'message': {
            'data': base64.b64encode(data).decode(),
            'attributes': attributes,
        }
    })

  def test_update_still_crashing(self):
    """Test an update that is still crashing."""
    stacktrace = self._read_test_data('asan_uaf.txt')
    self.app.post(
        '/external-update',
        params=self._make_message(stacktrace, {
            'testcaseId': self.testcase.key.id(),
            'revision': '1337'
        }),
        headers={'Authorization': 'Bearer fake'},
        content_type='application/octet-stream')

    updated_testcase = self.testcase.key.get()
    self.assertTrue(updated_testcase.open)
    self.assertEqual('', updated_testcase.fixed)
    self.assertEqual(stacktrace.decode(),
                     updated_testcase.last_tested_crash_stacktrace)
    self.assertEqual(1337,
                     updated_testcase.get_metadata('last_tested_revision'))
    self.assertEqual(
        1337, updated_testcase.get_metadata('last_tested_crash_revision'))

  def test_update_changed_security(self):
    """Test an update that is still crashing, but with a different security
    flag."""
    self.testcase.security_flag = False
    self.testcase.put()

    stacktrace = self._read_test_data('asan_uaf.txt')
    self.app.post(
        '/external-update',
        params=self._make_message(stacktrace, {
            'testcaseId': self.testcase.key.id(),
            'revision': '1337'
        }),
        headers={'Authorization': 'Bearer fake'},
        content_type='application/octet-stream')

    updated_testcase = self.testcase.key.get()
    self.assertFalse(updated_testcase.open)
    self.assertEqual('1336:1337', updated_testcase.fixed)
    self.assertEqual('last_tested',
                     updated_testcase.last_tested_crash_stacktrace)
    self.assertEqual(1337,
                     updated_testcase.get_metadata('last_tested_revision'))
    self.assertIsNone(
        updated_testcase.get_metadata('last_tested_crash_revision'))

  def test_update_older_revision(self):
    """Test an update that is for an older revision."""
    self.app.post(
        '/external-update',
        params=self._make_message(b'', {
            'testcaseId': self.testcase.key.id(),
            'revision': '1335'
        }),
        headers={'Authorization': 'Bearer fake'},
        content_type='application/octet-stream')

    updated_testcase = self.testcase.key.get()
    self.assertTrue(updated_testcase.open)
    self.assertEqual('', updated_testcase.fixed)
    self.assertEqual('last_tested',
                     updated_testcase.last_tested_crash_stacktrace)
    self.assertIsNone(updated_testcase.get_metadata('last_tested_revision'))
    self.assertIsNone(
        updated_testcase.get_metadata('last_tested_crash_revision'))

  def test_update_fixed(self):
    """Test an update that is no longer crashing."""
    self.app.post(
        '/external-update',
        params=self._make_message(b'', {
            'testcaseId': self.testcase.key.id(),
            'revision': '1337'
        }),
        headers={'Authorization': 'Bearer fake'},
        content_type='application/octet-stream')

    updated_testcase = self.testcase.key.get()
    self.assertFalse(updated_testcase.open)
    self.assertEqual('1336:1337', updated_testcase.fixed)
    self.assertEqual('last_tested',
                     updated_testcase.last_tested_crash_stacktrace)
    self.assertEqual(1337,
                     updated_testcase.get_metadata('last_tested_revision'))
    self.assertIsNone(
        updated_testcase.get_metadata('last_tested_crash_revision'))

  def test_update_error(self):
    """Test an update that has errored out."""
    self.app.post(
        '/external-update',
        params=self._make_message(
            b'', {
                'testcaseId': self.testcase.key.id(),
                'revision': '1337',
                'error': 'error'
            }),
        headers={'Authorization': 'Bearer fake'},
        content_type='application/octet-stream')

    updated_testcase = self.testcase.key.get()
    self.assertFalse(updated_testcase.open)
    self.assertEqual('NA', updated_testcase.fixed)
    self.assertEqual('last_tested',
                     updated_testcase.last_tested_crash_stacktrace)
    self.assertEqual(1337,
                     updated_testcase.get_metadata('last_tested_revision'))
    self.assertIsNone(
        updated_testcase.get_metadata('last_tested_crash_revision'))

  def test_update_not_external(self):
    """Test trying to update a testcase that isn't external."""
    self.testcase.job_type = 'job'
    self.testcase.put()
    stacktrace = self._read_test_data('asan_uaf.txt')
    resp = self.app.post(
        '/external-update',
        params=self._make_message(stacktrace, {
            'testcaseId': self.testcase.key.id(),
            'revision': '1337'
        }),
        headers={'Authorization': 'Bearer fake'},
        content_type='application/octet-stream',
        expect_errors=True)
    self.assertEqual(400, resp.status_int)

  def test_update_records_fuzz_target(self):
    """Test that updating records the fuzz target."""
    stacktrace = self._read_test_data('asan_uaf.txt')
    self.app.post(
        '/external-update',
        params=self._make_message(stacktrace, {
            'testcaseId': self.testcase.key.id(),
            'revision': '1337'
        }),
        headers={'Authorization': 'Bearer fake'},
        content_type='application/octet-stream')

    fuzz_target_job = data_types.FuzzTargetJob.get_by_id(
        'libFuzzer_fuzzer/libfuzzer_external_job')
    self.assertIsNotNone(fuzz_target_job)
    self.assertEqual(datetime.datetime(2021, 1, 1), fuzz_target_job.last_run)

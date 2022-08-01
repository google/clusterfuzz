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
"""oss_fuzz_apply_ccs tests."""
import unittest

import flask
from google.cloud import ndb
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import oss_fuzz_generate_certs


@test_utils.with_cloud_emulators('datastore')
class OssFuzzGenerateCertsTest(unittest.TestCase):
  """Test oss_fuzz_generate_certs."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'handlers.base_handler.Handler.is_cron',
    ])

    self.mock.is_cron.return_value = True
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/generate-certs',
        view_func=oss_fuzz_generate_certs.Handler.as_view('/generate-certs'))
    self.app = webtest.TestApp(flaskapp)

    data_types.OssFuzzProject(name='project1').put()
    data_types.OssFuzzProject(name='project2').put()

    data_types.WorkerTlsCert(
        id='project2',
        project_name='project2',
        cert_contents=b'cert_contents',
        key_contents=b'key_contents').put()

  def test_execute(self):
    """Tests executing of cron job."""
    # Defer import to avoid issues on Python 2.
    from OpenSSL import crypto

    self.app.get('/generate-certs')

    # New cert.
    tls_cert = ndb.Key(data_types.WorkerTlsCert, 'project1').get()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, tls_cert.cert_contents)
    self.assertEqual('US', cert.get_subject().C)
    self.assertEqual('*.c.test-clusterfuzz.internal', cert.get_subject().CN)
    self.assertEqual('project1', cert.get_subject().O)
    self.assertEqual(9001, cert.get_serial_number())
    self.assertEqual(b'20000101000000Z', cert.get_notBefore())
    self.assertEqual(b'21000101000000Z', cert.get_notAfter())

    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                         tls_cert.key_contents)
    self.assertTrue(private_key.check())

    # Should be unchanged.
    tls_cert = ndb.Key(data_types.WorkerTlsCert, 'project2').get()
    self.assertEqual(b'cert_contents', tls_cert.cert_contents)
    self.assertEqual(b'key_contents', tls_cert.key_contents)

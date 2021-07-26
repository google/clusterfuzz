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
"""Download testcase tests."""
import unittest

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.testcase_detail import download_testcase
from libs import helpers


@test_utils.with_cloud_emulators('datastore')
class OAuthHandlerTest(unittest.TestCase):
  """Test OAuthHandler."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.blobs.get_blob_info',
        'libs.access.check_access_and_get_testcase',
        'libs.handler.get_email_and_access_token',
        'libs.gcs.get_signed_url',
    ])
    self.mock.get_email_and_access_token.return_value = ('test@test.com',
                                                         'access_token')
    self.mock.get_signed_url.return_value = 'https://SIGNED_URL'

    self.mock.get_blob_info.side_effect = (
        lambda key: storage.GcsBlobInfo('blobs-bucket', key, 'file.tar.gz', 1))

  def _test_download(self, handler_class):
    """Test download."""
    testcase = data_types.Testcase()
    testcase.minimized_keys = 'key'
    testcase.put()

    self.mock.check_access_and_get_testcase.return_value = testcase
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=handler_class.as_view('/'))
    app = webtest.TestApp(flaskapp)
    resp = app.get('/?id=%s' % testcase.key.id())

    self.assertEqual(302, resp.status_int)
    # pylint: disable=line-too-long
    # According to https://cloud.google.com/appengine/docs/go/how-requests-are-handled
    # Appengine replaces X-AppEngine-BlobKey with the blob content.
    self.assertEqual(
        'https://SIGNED_URL&response-content-disposition=attachment'
        '%3B+filename%3Dtestcase-1-file.tar.gz', resp.location)

  def test_download(self):
    """Test download on Handler."""
    self._test_download(download_testcase.Handler)


@test_utils.with_cloud_emulators('datastore')
class GetTestcaseBlobInfoTest(unittest.TestCase):
  """Test get_testcase_blob_info."""

  def setUp(self):
    self.testcase = data_types.Testcase()
    self.testcase.put()

    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.blobs.get_blob_info',
    ])

    self.key = 'key'
    self.mock.get_blob_info.side_effect = (
        lambda key: storage.GcsBlobInfo('blobs-bucket', key, 'file.tar.gz', 1))

  def test_minimized(self):
    """Test getting minimized testcase."""
    self.testcase.minimized_keys = self.key
    self.testcase.fuzzed_keys = ''
    self.testcase.put()

    blob_info, using_minimized_keys = (
        download_testcase.get_testcase_blob_info(self.testcase))
    self.assertEqual(self.key, blob_info.key())
    self.assertEqual('file.tar.gz', blob_info.filename)
    self.assertTrue(using_minimized_keys)

  def test_unminimized(self):
    """Test getting unminimized."""
    self.testcase.minimized_keys = ''
    self.testcase.fuzzed_keys = self.key
    self.testcase.put()

    blob_info, using_minimized_keys = (
        download_testcase.get_testcase_blob_info(self.testcase))
    self.assertEqual(self.key, blob_info.key())
    self.assertEqual('file.tar.gz', blob_info.filename)
    self.assertFalse(using_minimized_keys)

  def test_error(self):
    """Test no blobkey."""
    self.testcase.minimized_keys = ''
    self.testcase.fuzzed_keys = ''
    self.testcase.put()

    with self.assertRaises(helpers.EarlyExitException) as cm:
      download_testcase.get_testcase_blob_info(self.testcase)

    self.assertEqual(400, cm.exception.status)
    self.assertEqual((
        "The testcase (%d) doesn't have fuzzed keys." % self.testcase.key.id()),
                     str(cm.exception))

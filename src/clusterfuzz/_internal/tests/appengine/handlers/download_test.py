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
"""Tests for download."""

import unittest
import urllib.parse

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import download
from libs.issue_management import issue_tracker


@test_utils.with_cloud_emulators('datastore')
class DownloadTest(unittest.TestCase):
  """Test download handler."""

  def setUp(self):
    self.minimized_key = 'minimized'
    self.fuzzed_key = 'fuzzed'
    self.unused_key = 'unused'

    self.testcase = data_types.Testcase(
        minimized_keys=self.minimized_key,
        fuzzed_keys=self.fuzzed_key,
        bug_information='1337')
    self.testcase.put()

    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.is_oss_fuzz',
        'clusterfuzz._internal.google_cloud_utils.blobs.get_blob_info',
        'libs.access.can_user_access_testcase',
        'libs.access.has_access',
        'libs.gcs.get_signed_url',
        'libs.helpers.get_user_email',
        'libs.issue_management.issue_tracker_utils.'
        'get_issue_tracker_for_testcase',
    ])
    self.mock.is_oss_fuzz.return_value = False
    self.mock.can_user_access_testcase.return_value = False
    self.mock.has_access.return_value = False
    self.mock.get_user_email.return_value = 'a@user.com'
    self.mock.get_signed_url.side_effect = (
        lambda b, p: 'https://SIGNED_URL?path=' + p)

    self.mock.get_blob_info.side_effect = (
        lambda key: storage.GcsBlobInfo('blobs-bucket', key, 'file.ext', 1337))

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/download', view_func=download.Handler.as_view(''))
    flaskapp.add_url_rule(
        '/download/<resource>',
        view_func=download.Handler.as_view('/download/<resource>'))
    self.app = webtest.TestApp(flaskapp)

  def _test_download(self,
                     blob_key=None,
                     testcase_id=None,
                     expect_status=302,
                     expect_blob=True,
                     expect_filename=None):
    """Test a download."""
    request = '/download'
    if blob_key:
      request += '/%s' % blob_key
    if testcase_id:
      request += '?testcase_id=%s' % str(testcase_id)

    resp = self.app.get(request, expect_errors=True)
    self.assertEqual(expect_status, resp.status_int)

    expected_blob_key = blob_key if blob_key else self.minimized_key
    expected_url = 'https://SIGNED_URL?path=' + expected_blob_key

    if expect_filename:
      expected_url += (
          '&response-content-disposition='
          'attachment%3B+filename%3D' + urllib.parse.quote(expect_filename))

    if expect_blob:
      self.assertEqual(expected_url, resp.location)
    elif expect_status == 302:
      self.assertNotIn('SIGNED_URL', resp.location)

  def test_download_nothing(self):
    """Test download fails when nothing is requested."""
    self._test_download('', expect_status=400, expect_blob=False)

  def test_download_not_logged_in(self):
    """Test download (not logged in)."""
    self.mock.get_user_email.return_value = ''
    self._test_download(
        self.minimized_key, expect_status=302, expect_blob=False)
    self._test_download(self.fuzzed_key, expect_status=302, expect_blob=False)
    self._test_download(self.unused_key, expect_status=302, expect_blob=False)

    self._test_download(
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)
    self._test_download(
        self.minimized_key,
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)
    self._test_download(
        self.fuzzed_key,
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)

  def test_download_user(self):
    """Test download with an internal user."""
    self.mock.has_access.return_value = True
    self._test_download(self.minimized_key, expect_filename='file.ext')
    self._test_download(self.fuzzed_key, expect_filename='file.ext')
    self._test_download(self.unused_key, expect_filename='file.ext')

    self._test_download(
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-minimized-1.ext')
    self._test_download(
        self.minimized_key,
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-minimized-1.ext')
    self._test_download(
        self.fuzzed_key,
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-1.ext')

  def test_download_testcase_user(self):
    """Test download with an user that has access to a testcase."""
    self.mock.can_user_access_testcase.return_value = True
    self._test_download(
        self.minimized_key, expect_status=403, expect_blob=False)
    self._test_download(self.fuzzed_key, expect_status=403, expect_blob=False)
    self._test_download(self.unused_key, expect_status=403, expect_blob=False)

    self._test_download(
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-minimized-1.ext')
    self._test_download(
        self.minimized_key,
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-minimized-1.ext')
    self._test_download(
        self.fuzzed_key,
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-1.ext')

  def test_download_testcase_no_user_access(self):
    """Test download testcase with a user that doesn't have access to the
    testcase."""
    self.mock.can_user_access_testcase.return_value = False
    self._test_download(
        testcase_id=self.testcase.key.id(),
        expect_status=403,
        expect_blob=False)
    self._test_download(
        self.minimized_key,
        testcase_id=self.testcase.key.id(),
        expect_status=403,
        expect_blob=False)
    self._test_download(
        self.fuzzed_key,
        testcase_id=self.testcase.key.id(),
        expect_status=403,
        expect_blob=False)

  def test_public_download_chromium(self):
    """Test public downloading chromium testcases (should fail)."""
    self.mock.get_user_email.return_value = ''
    self.mock.is_oss_fuzz.return_value = False
    mock_issue = self.mock.get_issue_tracker_for_testcase(None).get_issue()
    mock_issue.labels = issue_tracker.LabelStore([])

    self._test_download(
        self.minimized_key, expect_status=302, expect_blob=False)
    self._test_download(
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)
    self._test_download(
        self.minimized_key,
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)
    self._test_download(
        self.fuzzed_key,
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)

  def test_public_download_oss_fuzz(self):
    """Test public downloading OSS-Fuzz testcases."""
    self.mock.get_user_email.return_value = ''

    self.mock.is_oss_fuzz.return_value = True
    mock_issue = self.mock.get_issue_tracker_for_testcase(None).get_issue()
    mock_issue.labels = issue_tracker.LabelStore([])

    self._test_download(
        self.minimized_key, expect_status=302, expect_blob=False)
    self._test_download(
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-minimized-1.ext')
    self._test_download(
        self.minimized_key,
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-minimized-1.ext')
    # Only have access to minimized testcase.
    self._test_download(
        self.fuzzed_key,
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)

    mock_issue.labels = issue_tracker.LabelStore(['restrict-view-commit'])
    self._test_download(
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)
    self._test_download(
        self.minimized_key,
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)
    self._test_download(
        self.fuzzed_key,
        testcase_id=self.testcase.key.id(),
        expect_status=302,
        expect_blob=False)

    # Privileged users should still be able to access everything.
    self.mock.get_user_email.return_value = 'a@user.com'
    self.mock.has_access.return_value = True

    self._test_download(
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-minimized-1.ext')
    self._test_download(
        self.minimized_key,
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-minimized-1.ext')
    self._test_download(
        self.fuzzed_key,
        testcase_id=self.testcase.key.id(),
        expect_filename='clusterfuzz-testcase-1.ext')

  def test_download_invalid_id(self):
    """Test download with an invalid testcase ID."""
    self.mock.has_access.return_value = True
    self._test_download(testcase_id=1337, expect_blob=False, expect_status=400)
    self._test_download(
        self.minimized_key,
        testcase_id=1337,
        expect_blob=False,
        expect_status=400)

  def test_download_mismatch_testcase_blob_key(self):
    """Test download with a blob key that doesn't match the testcase.."""
    self.mock.has_access.return_value = True
    self._test_download(
        self.unused_key,
        testcase_id=self.testcase.key.id(),
        expect_status=400,
        expect_blob=False)

  def test_download_filename(self):
    """Test filename of downloaded files."""
    self.mock.has_access.return_value = True

    expect_filename = 'file.ext'
    self._test_download(self.minimized_key, expect_filename=expect_filename)

    expect_filename = (
        'clusterfuzz-testcase-minimized-%s.ext' % self.testcase.key.id())
    self._test_download(
        testcase_id=self.testcase.key.id(), expect_filename=expect_filename)
    self._test_download(
        self.minimized_key,
        testcase_id=self.testcase.key.id(),
        expect_filename=expect_filename)

    expect_filename = ('clusterfuzz-testcase-%s.ext' % self.testcase.key.id())
    self._test_download(
        self.fuzzed_key,
        testcase_id=self.testcase.key.id(),
        expect_filename=expect_filename)

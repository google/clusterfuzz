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
"""Reproduce tool HTTP utility tests."""
import unittest

from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs.reproduce_tool_fakes import \
    FakeConfig
from clusterfuzz._internal.tests.test_libs.reproduce_tool_fakes import \
    FakeResponse
from clusterfuzz._internal.tests.test_libs.reproduce_tool_fakes import FakeHttp
from local.butler.reproduce_tool import http_utils


class RequestTest(unittest.TestCase):
  """Tests for the request function."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.read_data_from_file',
        'clusterfuzz._internal.base.utils.write_data_to_file',
        'httplib2.Http',
        'local.butler.reproduce_tool.prompts.get_string',
        'webbrowser.open',
    ])

    self.config = FakeConfig()

  def test_multiple_auth_failures(self):
    """Ensure that we don't recurse indefinitely if auth fails persistently."""
    http = FakeHttp([(FakeResponse(401), {}), (FakeResponse(401), {})])
    self.mock.Http.return_value = http
    response, _ = http_utils.request('https://url/', configuration=self.config)

    # Ensure that all expected requests were made.
    self.assertEqual(http.replies, [])

    self.assertEqual(response.status, 401)

  def test_unauthenticated_request(self):
    """Ensure that we can make an unauthenticated request."""
    http = FakeHttp([(FakeResponse(200), {})])
    self.mock.Http.return_value = http
    response, _ = http_utils.request('https://url/', body='test body')

    # Ensure that all expected requests were made.
    self.assertEqual(http.replies, [])

    self.assertEqual(http.last_body, '"test body"')
    self.assertEqual(http.last_headers, {})
    self.assertEqual(response.status, 200)

  def test_authentication(self):
    """Ensure that we can authenticate properly if needed."""
    http = FakeHttp([(FakeResponse(401), {}), (FakeResponse(
        200, include_auth_header=True), {})])
    self.mock.Http.return_value = http
    response, _ = http_utils.request('https://url/', configuration=self.config)

    # Ensure that all expected requests were made.
    self.assertEqual(http.replies, [])

    self.mock.write_data_to_file.assert_called_once_with(
        'fake auth token', http_utils.AUTHORIZATION_CACHE_FILE)
    self.assertEqual(response.status, 200)

  def test_authenticated_request(self):
    """Ensure that we reuse credentials if we've previously authenticated."""
    http = FakeHttp([(FakeResponse(200), {})])
    self.mock.Http.return_value = http
    self.mock.read_data_from_file.return_value = 'cached auth token'
    response, _ = http_utils.request('https://url/', configuration=self.config)

    # Ensure that all expected requests were made.
    self.assertEqual(http.replies, [])

    self.assertEqual(http.last_headers, {
        'Authorization': 'cached auth token',
        'User-Agent': 'clusterfuzz-reproduce'
    })
    self.assertEqual(response.status, 200)

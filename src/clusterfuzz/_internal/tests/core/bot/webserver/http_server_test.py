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
"""Tests for the http_server module."""

import os
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.bot.webserver import http_server
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class TestRequestHandler(http_server.RequestHandler):
  """Override methods which would be problematic for testing."""

  class TestWFile:

    def __init__(self):
      self.contents = ''

    def write(self, data):
      # Since the fake files are being created with simple contents, we can
      # just decode that as 'utf-8'.
      self.contents += data.decode("utf-8")

  def __init__(self, path):  # pylint: disable=super-init-not-called
    self.response_code = 0
    self.wfile = self.TestWFile()
    self.path = path

  def send_response(self, response_code, _=None):  # pylint: disable=arguments-differ,arguments-renamed
    self.response_code = response_code

  def send_header(self, *_):  # pylint: disable=arguments-differ
    pass

  def end_headers(self):
    pass


class RequestHandlerTest(fake_filesystem_unittest.TestCase):
  """Tests for the RequestHandler class."""

  def setUp(self):
    """Setup for request handler test."""
    test_utils.set_up_pyfakefs(self, allow_root_user=False)
    helpers.patch_environ(self)

    os.environ['FUZZ_DATA'] = '/data'
    os.environ['FUZZERS_DIR'] = '/fuzzers'
    os.environ['INPUT_DIR'] = '/input'
    self.fs.create_file(
        os.path.join('/input', 'valid.txt'), contents='valid file')
    self.fs.create_file(
        os.path.join('/input', 'unreadable.txt'), contents='unreadable file')
    os.chmod(os.path.join('/input', 'unreadable.txt'), 0)

  def _assert_get(self, request_path, expected_code, expected_contents=''):
    handler = TestRequestHandler(request_path)
    handler.do_GET()
    self.assertEqual(handler.response_code, expected_code, msg=request_path)
    self.assertEqual(
        handler.wfile.contents, expected_contents, msg=request_path)

  def test_nonexistent_file(self):
    """Ensure that we respond with 404 for a nonexistent file."""
    handler = TestRequestHandler('/invalid.txt')
    handler.do_GET()

    self.assertEqual(handler.response_code, 404)
    self.assertEqual(handler.wfile.contents, '')

  def test_unreadable_file(self):
    """Ensure that we respond with 403 for a file we can't read."""
    handler = TestRequestHandler('/unreadable.txt')
    handler.do_GET()

    self.assertEqual(handler.response_code, 403)
    self.assertEqual(handler.wfile.contents, '')

  def test_valid_file(self):
    """Ensure that we respond with 200 and the file contents for a valid one."""
    handler = TestRequestHandler('/valid.txt')
    handler.do_GET()

    self.assertEqual(handler.response_code, 200)
    self.assertEqual(handler.wfile.contents, 'valid file')

  def test_http_aliases(self):
    """Ensure every HTTP_ALIASES prefix resolves to each of its targets."""
    for i, (prefix, targets) in enumerate(http_server.HTTP_ALIASES):
      for j, target in enumerate(targets):
        # Unique filename so only this target can satisfy the request.
        filename = f'alias_{i}_{j}.js'
        target_relpath = os.path.join(target, filename)
        self.fs.create_file(
            os.path.join('/data', target_relpath), contents=target_relpath)
        self._assert_get(prefix + filename, 200, target_relpath)

  def test_url_normalization(self):
    """Ensure ?query, #fragment, and %20 are handled for aliased paths."""
    self.fs.create_file(
        '/data/WebKit/LayoutTests/http/tests/resources/payment request.js',
        contents='payment')
    self._assert_get('/resources/payment%20request.js?pipe=sub#frag', 200,
                     'payment')

  def test_longest_alias_prefix_wins(self):
    """Ensure /tests/SimpleTest/ beats /tests/ regardless of alias order."""
    self.fs.create_file('/data/gecko-tests/SimpleTest/shared.js', contents='no')
    self.fs.create_file(
        '/data/gecko-tests/testing/mochitest/tests/SimpleTest/shared.js',
        contents='yes')
    self._assert_get('/tests/SimpleTest/shared.js', 200, 'yes')

    # Declaration order must not matter.
    with mock.patch.object(http_server, 'HTTP_ALIASES',
                           tuple(reversed(http_server.HTTP_ALIASES))):
      self._assert_get('/tests/SimpleTest/shared.js', 200, 'yes')

  def test_search_paths_take_precedence_over_aliases(self):
    """Ensure root search_paths (WPT) win over the WebKit alias fallback."""
    self.fs.create_file(
        '/data/LayoutTests/external/wpt/resources/testharness.js',
        contents='wpt')
    self.fs.create_file(
        '/data/WebKit/LayoutTests/resources/testharness.js', contents='webkit')
    self._assert_get('/resources/testharness.js?pipe=sub', 200, 'wpt')

  def test_path_traversal_rejected(self):
    """Ensure raw and percent-encoded ../ or ..\\ traversals return 404."""
    self.fs.create_file('/etc/passwd', contents='secret')
    self.fs.create_file('/data/secret.txt', contents='secret')
    self.fs.create_dir('/data/gecko-tests/sub')

    for malicious_path in [
        '/../etc/passwd',
        '/tests/../../secret.txt',
        '/%2e%2e/%2e%2e/etc/passwd',
        '/%5c..%5c..%5cetc/passwd',
    ]:
      self._assert_get(malicious_path, 404)


class GuessMimeTypeTest(unittest.TestCase):
  """Tests for guess_mime_type."""

  def test_common_mime_types(self):
    """Ensure that we are able to guess common mime types."""
    expected_types_map = {
        'file.html': 'text/html',
        'file.css': 'text/css',
        'file.jpg': 'image/jpeg',
    }
    for filename, expected_value in expected_types_map.items():
      self.assertEqual(http_server.guess_mime_type(filename), expected_value)

  def test_invalid_type(self):
    """Ensure that guess_mime_type returns none"""
    self.assertIsNone(
        http_server.guess_mime_type('file.uncommon_extension_79d8f8f6'))

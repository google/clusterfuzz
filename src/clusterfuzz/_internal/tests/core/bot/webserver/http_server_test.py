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

from pyfakefs import fake_filesystem_unittest
import six

from clusterfuzz._internal.bot.webserver import http_server
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class TestRequestHandler(http_server.RequestHandler):
  """Override methods which would be problematic for testing."""

  class TestWFile(object):

    def __init__(self):
      self.contents = ''

    def write(self, data):
      self.contents += data

  def __init__(self, path):  # pylint: disable=super-init-not-called
    self.response_code = 0
    self.wfile = self.TestWFile()
    self.path = path

  def send_response(self, response_code, _=None):  # pylint: disable=arguments-differ
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


class GuessMimeTypeTest(unittest.TestCase):
  """Tests for guess_mime_type."""

  def test_common_mime_types(self):
    """Ensure that we are able to guess common mime types."""
    expected_types_map = {
        'file.html': 'text/html',
        'file.css': 'text/css',
        'file.jpg': 'image/jpeg',
    }
    for filename, expected_value in six.iteritems(expected_types_map):
      self.assertEqual(http_server.guess_mime_type(filename), expected_value)

  def test_invalid_type(self):
    """Ensure that guess_mime_type returns none"""
    self.assertIsNone(
        http_server.guess_mime_type('file.uncommon_extension_79d8f8f6'))

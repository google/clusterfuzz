# Copyright 2025 Google LLC
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
"""Tests for fast_http.py."""
# fast_http_test.py

import asyncio
import functools
import http.server
import os
import shutil
import socket
import tempfile
import threading
import unittest

import aiohttp

from clusterfuzz._internal.system import fast_http
from clusterfuzz._internal.tests.test_libs import helpers


class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
  """Doesn't log requests to stderr."""

  def log_message(self, *args):
    del args


def find_free_port():
  """Finds and returns an available port number on the local machine."""
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(('127.0.0.1', 0))
    return sock.getsockname()[1]


class ErrorTolerantDownloadTest(unittest.TestCase):
  """Tests for the _error_tolerant_download_file function."""
  httpd = None
  server_thread = None
  server_address = None
  tmp_dir = None
  port = None

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.warning',
    ])

  @classmethod
  def setUpClass(cls):
    """Sets up a temporary directory and a local HTTP server for all tests in this class."""
    cls.tmp_dir = tempfile.mkdtemp()
    cls.source_filename = 'test.txt'
    cls.source_content = b' '
    source_filepath = os.path.join(cls.tmp_dir, cls.source_filename)
    with open(source_filepath, 'wb') as f:
      f.write(cls.source_content)
    cls.port = find_free_port()
    handler_factory = functools.partial(
        QuietHTTPRequestHandler, directory=cls.tmp_dir)
    cls.httpd = http.server.HTTPServer(('127.0.0.1', cls.port), handler_factory)
    cls.server_address = f'http://localhost:{cls.port}'

    cls.server_thread = threading.Thread(target=cls.httpd.serve_forever)
    cls.server_thread.daemon = True
    cls.server_thread.start()

  @classmethod
  def tearDownClass(cls):
    """
    Cleans up resources by explicitly shutting down the server and thread,
    then removing the temporary directory.
    """
    cls.httpd.shutdown()
    cls.httpd.server_close()
    cls.server_thread.join()
    shutil.rmtree(cls.tmp_dir)

  def test_download_success(self):
    """Tests a successful file download."""

    async def run_test():
      url = f'{self.server_address}/{self.source_filename}'
      destination_path = os.path.join(self.tmp_dir, 'downloaded_file.txt')
      async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(
          total=60)) as session:
        result = await fast_http._error_tolerant_download_file(  # pylint: disable=protected-access
            session, url, destination_path)

      self.assertTrue(os.path.exists(destination_path))
      self.assertTrue(result)
      self.mock.warning.assert_not_called()

    asyncio.run(run_test())

  def test_404(self):
    """ Tests a failed file download due to a 404 Not Found error.
    """

    async def run_test():
      missing_filename = 'fake.txt'
      url = f'{self.server_address}/{missing_filename}'
      destination_path = os.path.join(self.tmp_dir, missing_filename)
      async with aiohttp.ClientSession() as session:
        result = await fast_http._error_tolerant_download_file(  # pylint: disable=protected-access
            session, url, destination_path)

      self.assertFalse(result)
      self.assertFalse(os.path.exists(destination_path))
      self.mock.warning.assert_called_with(f'Failed to download {url}.')

    asyncio.run(run_test())

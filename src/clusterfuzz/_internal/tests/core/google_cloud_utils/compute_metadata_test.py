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
"""Unit tests for compute_metadata."""

import contextlib
import http.server
import importlib
import os
import threading
import unittest
from unittest import mock

from clusterfuzz._internal.google_cloud_utils import compute_metadata


@contextlib.contextmanager
def _metadata_server(paths):
  """Runs a local HTTP metadata server serving 200 only for |paths|."""

  class Handler(http.server.BaseHTTPRequestHandler):
    """Serves the configured metadata paths and 404s everything else."""

    def do_GET(self):  # pylint: disable=invalid-name
      """Handles a metadata GET request."""
      path = self.path.removeprefix('/computeMetadata/v1/')
      if path in paths:
        body = paths[path].encode()
        self.send_response(200)
        self.send_header('Metadata-Flavor', 'Google')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
      else:
        self.send_error(404)

    def log_message(self, *args):  # pylint: disable=arguments-differ
      pass

  server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
  thread = threading.Thread(target=server.serve_forever, daemon=True)
  thread.start()
  try:
    host = f'127.0.0.1:{server.server_address[1]}'
    # Avoid routing localhost through any HTTP(S)_PROXY set on the machine.
    with mock.patch.dict(os.environ, {'NO_PROXY': '127.0.0.1',
                                      'no_proxy': '127.0.0.1'}), \
        mock.patch.object(compute_metadata, '_METADATA_URL',
                          f'http://{host}/computeMetadata/v1/'):
      yield
  finally:
    server.shutdown()
    server.server_close()
    thread.join()


class IsGceTest(unittest.TestCase):
  """Tests for is_gce()."""

  def test_real_metadata_server(self):
    """Verifies that a server returning instance/id is treated as GCE."""
    with _metadata_server({'instance/id': '1234'}):
      self.assertTrue(compute_metadata.is_gce())

  def test_token_only_emulator(self):
    """Verifies that a token-only emulator (e.g. LUCI's local auth server
    exported via GCE_METADATA_HOST on Swarming) is not treated as GCE."""
    with _metadata_server({
        'project/project-id': 'none',
        'instance/name': 'lin-19-h709',
        'instance/service-accounts/default/token': '{}',
    }):
      self.assertFalse(compute_metadata.is_gce())

  def test_unreachable_server(self):
    """Verifies that an unreachable metadata server is not treated as GCE."""
    with mock.patch.object(compute_metadata, '_METADATA_URL',
                           'http://127.0.0.1:1/computeMetadata/v1/'):
      self.assertFalse(compute_metadata.is_gce())


class MetadataHostTest(unittest.TestCase):
  """Tests for GCE_METADATA_HOST handling."""

  def test_gce_metadata_host_env_override(self):
    """Verifies that GCE_METADATA_HOST overrides the default metadata server and URL."""
    with mock.patch.dict(
        os.environ, {'GCE_METADATA_HOST': '127.0.0.1:45678'}, clear=False):
      importlib.reload(compute_metadata)
      self.assertEqual('127.0.0.1:45678', compute_metadata._METADATA_SERVER)  # pylint: disable=protected-access
      self.assertEqual('http://127.0.0.1:45678/computeMetadata/v1/',
                       compute_metadata._METADATA_URL)  # pylint: disable=protected-access

    importlib.reload(compute_metadata)

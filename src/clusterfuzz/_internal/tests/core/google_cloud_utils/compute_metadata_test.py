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

import importlib
import os
import socket
import unittest
from unittest import mock

from clusterfuzz._internal.google_cloud_utils import compute_metadata


class ComputeMetadataTest(unittest.TestCase):
  """Tests for compute_metadata host and port resolution."""

  def test_host_port_split(self):
    """Verifies that _metadata_host_port() defaults to port 80 for bare hostnames and parses explicit host:port values."""
    with mock.patch.object(compute_metadata, '_METADATA_SERVER',
                           'metadata.google.internal'):
      self.assertEqual(('metadata.google.internal', 80),
                       compute_metadata._metadata_host_port())  # pylint: disable=protected-access

    with mock.patch.object(compute_metadata, '_METADATA_SERVER',
                           '127.0.0.1:41234'):
      self.assertEqual(('127.0.0.1', 41234),
                       compute_metadata._metadata_host_port())  # pylint: disable=protected-access

  def test_is_gce_on_non_default_port(self):
    """Verifies that compute_metadata.is_gce() connects to the port in _METADATA_SERVER rather than hardcoding port 80."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
      listener.bind(('127.0.0.1', 0))
      listener.listen(1)
      port = listener.getsockname()[1]

      with mock.patch.object(compute_metadata, '_METADATA_SERVER',
                             f'127.0.0.1:{port}'):
        self.assertTrue(compute_metadata.is_gce())

    with mock.patch.object(compute_metadata, '_METADATA_SERVER', '127.0.0.1:1'):
      self.assertFalse(compute_metadata.is_gce())

  def test_gce_metadata_host_env_override(self):
    """Verifies that GCE_METADATA_HOST overrides the default metadata server and URL."""
    with mock.patch.dict(
        os.environ, {'GCE_METADATA_HOST': '127.0.0.1:45678'}, clear=False):
      importlib.reload(compute_metadata)
      self.assertEqual('127.0.0.1:45678', compute_metadata._METADATA_SERVER)  # pylint: disable=protected-access
      self.assertEqual('http://127.0.0.1:45678/computeMetadata/v1/',
                       compute_metadata._METADATA_URL)  # pylint: disable=protected-access

    importlib.reload(compute_metadata)

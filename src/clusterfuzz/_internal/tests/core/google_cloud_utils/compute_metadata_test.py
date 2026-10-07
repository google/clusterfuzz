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
import unittest
from unittest import mock

import requests

from clusterfuzz._internal.google_cloud_utils import compute_metadata


@mock.patch.object(compute_metadata, '_get_raw')
class IsGceTest(unittest.TestCase):
  """Tests for is_gce()."""

  def test_instance_id_served(self, mock_get_raw):
    """Verifies that is_gce() is True when instance/id is served."""
    mock_get_raw.return_value = '1234'
    self.assertTrue(compute_metadata.is_gce())
    mock_get_raw.assert_called_once_with('instance/id', timeout=5)

  def test_instance_id_missing(self, mock_get_raw):
    """Verifies that is_gce() is False when instance/id is not served (e.g.
    luci-auth's token-only server on Swarming)."""
    mock_get_raw.side_effect = requests.exceptions.HTTPError('404')
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

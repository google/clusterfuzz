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
"""Tests for fetch_artifact.py."""

import unittest
from unittest import mock

from clusterfuzz._internal.platforms.android import fetch_artifact
from clusterfuzz._internal.tests.test_libs import helpers

class FetchArtifactTest(unittest.TestCase):
  """Tests for fetch_artifact."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.fetch_artifact._get_client',
        'clusterfuzz._internal.platforms.android.fetch_artifact._use_v4',
        'clusterfuzz._internal.platforms.android.fetch_artifact._execute_request_with_retries',
    ])
    self.mock_client = mock.MagicMock()
    self.mock._get_client.return_value = self.mock_client

  def test_get_latest_artifact_v4_success(self):
    """Tests get_latest_artifact_info (V4). Expects extraction of {bid, branch, target} when list_builds returns data."""
    self.mock._use_v4.return_value = True
    self.mock_client.list_builds.return_value = {
        'builds': [{
            'buildId': '123',
            'target': {
                'name': 'test_target'
            }
        }]
    }

    result = fetch_artifact.get_latest_artifact_info('branch1', 'target1')
    self.assertEqual(result, {'bid': '123', 'branch': 'branch1', 'target': 'test_target'})
    self.mock_client.list_builds.assert_called_once_with('branch1', 'target1', False)

  def test_get_latest_artifact_v4_failure_no_builds(self):
    """Tests get_latest_artifact_info (V4) returns None gracefully when no builds are found."""
    self.mock._use_v4.return_value = True
    self.mock_client.list_builds.return_value = {}

    result = fetch_artifact.get_latest_artifact_info('branch1', 'target1')
    self.assertIsNone(result)

  def test_get_latest_artifact_v3_success(self):
    """Tests get_latest_artifact_info (V3). Expects extraction of {bid, branch, target} via legacy HTTP execution."""
    self.mock._use_v4.return_value = False
    
    mock_request = mock.MagicMock()
    self.mock_client.build().list.return_value = mock_request
    
    self.mock._execute_request_with_retries.return_value = {
        'builds': [{
            'buildId': '456',
            'target': {
                'name': 'test_target2'
            }
        }]
    }

    result = fetch_artifact.get_latest_artifact_info('branch2', 'target2', signed=True)
    self.assertEqual(result, {'bid': '456', 'branch': 'branch2', 'target': 'test_target2'})
    
    self.mock_client.build().list.assert_called_once_with(
        buildType='submitted',
        branch='branch2',
        target='target2',
        successful=True,
        maxResults=1,
        signed=True)
    self.mock._execute_request_with_retries.assert_called_once_with(mock_request)

  def test_get_latest_artifact_v3_failure_no_builds(self):
    """Tests get_latest_artifact_info (V3) returns None gracefully when the payload is empty."""
    self.mock._use_v4.return_value = False
    
    mock_request = mock.MagicMock()
    self.mock_client.build().list.return_value = mock_request
    self.mock._execute_request_with_retries.return_value = {'builds': []}

    result = fetch_artifact.get_latest_artifact_info('branch2', 'target2', signed=True)
    self.assertIsNone(result)

  def test_get_latest_artifact_client_auth_failure(self):
    """Tests get_latest_artifact_info exits early and returns None when client auth fails."""
    self.mock._get_client.return_value = None

    result = fetch_artifact.get_latest_artifact_info('branch1', 'target1')
    self.assertIsNone(result)

  def test_get_artifacts_for_build_empty_regexp(self):
    """Tests _get_artifacts_for_build returns [] returning early when regexp is empty, bypassing API calls."""
    result = fetch_artifact._get_artifacts_for_build(self.mock_client, 'bid', 'target', regexp='')
    self.assertEqual(result, [])
    self.mock_client.list_artifacts.assert_not_called()
    self.mock_client.buildartifact().list.assert_not_called()

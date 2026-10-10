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

# pylint: disable=protected-access

import unittest
from unittest import mock

from clusterfuzz._internal.base import feature_flags
from clusterfuzz._internal.platforms.android import fetch_artifact
from clusterfuzz._internal.tests.test_libs import helpers


class FetchArtifactTest(unittest.TestCase):
  """Tests for fetch_artifact."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.fetch_artifact._get_client',
        'clusterfuzz._internal.platforms.android.fetch_artifact._call_android_api_enabled',
    ])
    self.mock_client = mock.MagicMock()
    self.mock._get_client.return_value = self.mock_client
    self.mock._call_android_api_enabled.return_value = True

  def test_get_latest_artifact_success(self):
    """Tests get_latest_artifact_info. Expects extraction of {bid, branch, target} when list_builds returns data."""
    self.mock_client.list_builds.return_value = {
        'builds': [{
            'buildId': '123',
            'target': {
                'name': 'test_target'
            }
        }]
    }

    result = fetch_artifact.get_latest_artifact_info('branch1', 'target1')
    self.assertEqual(result, {
        'bid': '123',
        'branch': 'branch1',
        'target': 'test_target'
    })
    self.mock_client.list_builds.assert_called_once_with(
        'branch1', 'target1', False)

  def test_get_latest_artifact_failure_no_builds(self):
    """Tests get_latest_artifact_info returns None gracefully when no builds are found."""
    self.mock_client.list_builds.return_value = {}

    result = fetch_artifact.get_latest_artifact_info('branch1', 'target1')
    self.assertIsNone(result)

  def test_get_latest_artifact_client_auth_failure(self):
    """Tests get_latest_artifact_info exits early and returns None when client auth fails."""
    self.mock._get_client.return_value = None

    result = fetch_artifact.get_latest_artifact_info('branch1', 'target1')
    self.assertIsNone(result)

  def test_get_latest_artifact_disabled_by_feature_flag(self):
    """Tests get_latest_artifact_info exits early and returns None when disabled by feature flag."""
    self.mock._call_android_api_enabled.return_value = False

    result = fetch_artifact.get_latest_artifact_info('branch1', 'target1')
    self.assertIsNone(result)

  def test_get_artifacts_for_build_empty_regexp(self):
    """Tests _get_artifacts_for_build returns [] returning early when regexp is empty, bypassing API calls."""
    result = fetch_artifact._get_artifacts_for_build(
        self.mock_client, 'bid', 'target', regexp='')
    self.assertEqual(result, [])
    self.mock_client.list_artifacts.assert_not_called()


class CallAndroidApiEnabledTest(unittest.TestCase):
  """Tests for _call_android_api_enabled."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.is_uworker',
    ])
    self.mock.is_uworker.return_value = False

  def test_is_uworker_returns_false(self):
    self.mock.is_uworker.return_value = True
    self.assertFalse(fetch_artifact._call_android_api_enabled())

  def test_flag_none_returns_true(self):
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = None
      self.assertTrue(fetch_artifact._call_android_api_enabled())

  def test_flag_enabled_returns_true(self):
    mock_flag_obj = mock.MagicMock()
    mock_flag_obj.enabled = True
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = mock_flag_obj
      self.assertTrue(fetch_artifact._call_android_api_enabled())

  def test_flag_disabled_returns_false(self):
    mock_flag_obj = mock.MagicMock()
    mock_flag_obj.enabled = False
    with mock.patch.object(
        feature_flags.FeatureFlags, 'flag',
        new_callable=mock.PropertyMock) as mock_flag:
      mock_flag.return_value = mock_flag_obj
      self.assertFalse(fetch_artifact._call_android_api_enabled())

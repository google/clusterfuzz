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
"""Tests for android_build_v4_api.py."""

import os
import tempfile
import unittest
from unittest import mock

import google.auth.exceptions
import requests

from clusterfuzz._internal.platforms.android.android_build_v4_api import \
    AndroidBuildV4Api
from clusterfuzz._internal.tests.test_libs import helpers


class AndroidBuildV4ApiTest(unittest.TestCase):
  """Tests for AndroidBuildV4Api."""

  def setUp(self):
    helpers.patch(self, [
        'requests.get',
    ])

    self.mock_credentials = mock.MagicMock()
    self.mock_credentials.valid = True
    self.mock_credentials.token = 'test_token'

    self.api = AndroidBuildV4Api.create_authenticated(self.mock_credentials)

  def test_create_authenticated_refreshes_invalid_credentials(self):
    """Tests that create_authenticated refreshes invalid credentials and returns
    an API client instance.
    """
    mock_creds = mock.MagicMock()
    mock_creds.valid = False
    mock_creds.token = 'refreshed'

    client = AndroidBuildV4Api.create_authenticated(mock_creds)
    mock_creds.refresh.assert_called_once()
    self.assertIsInstance(client, AndroidBuildV4Api)

  def test_create_authenticated_auth_error(self):
    """Tests that create_authenticated raises GoogleAuthError when credential
    token refresh fails.
    """
    mock_creds = mock.MagicMock()
    mock_creds.valid = False
    mock_creds.refresh.side_effect = (
        google.auth.exceptions.GoogleAuthError('Refresh failed'))

    with self.assertRaises(google.auth.exceptions.GoogleAuthError):
      AndroidBuildV4Api.create_authenticated(mock_creds)

  def test_list_builds_success(self):
    """Tests that list_builds sends correct GET request parameters and returns
    parsed build data on success.
    """
    mock_response = mock.MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'builds': [{
            'buildId': '123456',
            'target': {
                'name': 'target_name'
            }
        }]
    }
    self.mock.get.return_value = mock_response

    result = self.api.list_builds('git_main', 'target_name', signed=True)
    self.assertEqual(
        result,
        {'builds': [{
            'buildId': '123456',
            'target': {
                'name': 'target_name'
            }
        }]})
    self.mock.get.assert_called_once_with(
        'https://androidbuild-pa.googleapis.com/v4/builds',
        headers={
            'Authorization': 'Bearer test_token',
            'Accept': 'application/json'
        },
        params={
            'buildType': 'submitted',
            'branches': 'git_main',
            'targets': 'target_name',
            'successful': 'true',
            'pageSize': 1,
            'signed': 'true',
        },
        stream=False,
        timeout=60)

  def test_list_builds_error(self):
    """Tests that list_builds handles HTTP errors gracefully by logging and
    returning None.
    """
    mock_response = mock.MagicMock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        'Server error', response=mock_response)
    self.mock.get.return_value = mock_response

    result = self.api.list_builds('git_main', 'target_name')
    self.assertIsNone(result)

  def test_list_builds_json_error(self):
    """Tests that list_builds handles JSON decoding errors (ValueError) by
    returning None.
    """
    mock_response = mock.MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = ValueError('Invalid JSON')
    self.mock.get.return_value = mock_response

    result = self.api.list_builds('git_main', 'target_name')
    self.assertIsNone(result)

  def test_list_artifacts_pagination(self):
    """Tests that list_artifacts follows nextPageToken pagination and
    aggregates artifacts across pages.
    """
    resp1 = mock.MagicMock()
    resp1.status_code = 200
    resp1.json.return_value = {
        'artifacts': [{
            'name': 'art1'
        }],
        'nextPageToken': 'token123'
    }

    resp2 = mock.MagicMock()
    resp2.status_code = 200
    resp2.json.return_value = {'artifacts': [{'name': 'art2'}]}

    self.mock.get.side_effect = [resp1, resp2]

    artifacts = self.api.list_artifacts('123', 'target_name', regexp='.*zip')
    self.assertEqual(artifacts, [{'name': 'art1'}, {'name': 'art2'}])

  def test_list_artifacts_error(self):
    """Tests that list_artifacts handles HTTP request errors gracefully by
    returning an empty list.
    """
    mock_response = mock.MagicMock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        'Server error', response=mock_response)
    self.mock.get.return_value = mock_response

    artifacts = self.api.list_artifacts('123', 'target_name')
    self.assertEqual(artifacts, [])

  def test_get_artifact_metadata(self):
    """Tests that get_artifact_metadata retrieves metadata dictionary for a
    specific build artifact.
    """
    mock_response = mock.MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'buildArtifactMetadata': {
            'name': 'file.zip',
            'size': '100'
        }
    }
    self.mock.get.return_value = mock_response

    metadata = self.api.get_artifact_metadata('123', 'target', 'latest',
                                              'file.zip')
    self.assertEqual(metadata, {'name': 'file.zip', 'size': '100'})

  def test_get_artifact_metadata_error(self):
    """Tests that get_artifact_metadata handles HTTP errors (e.g. 404) by
    returning None.
    """
    mock_response = mock.MagicMock()
    mock_response.status_code = 404
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        'Not found', response=mock_response)
    self.mock.get.return_value = mock_response

    metadata = self.api.get_artifact_metadata('123', 'target', 'latest',
                                              'file.zip')
    self.assertIsNone(metadata)

  def test_download_artifact_file(self):
    """Tests that download_artifact_file fetches a signed URL and streams file
    chunks to local path.
    """
    resp_url = mock.MagicMock()
    resp_url.status_code = 200
    resp_url.json.return_value = {
        'signedUrl': 'https://storage.googleapis.com/test'
    }

    resp_dl = mock.MagicMock()
    resp_dl.status_code = 200
    resp_dl.iter_content.return_value = [b'chunk1', b'chunk2']

    self.mock.get.side_effect = [resp_url, resp_dl]

    with tempfile.TemporaryDirectory() as temp_dir:
      output_path = os.path.join(temp_dir, 'output.txt')
      success = self.api.download_artifact_file('123', 'target', 'latest',
                                                'file.txt', output_path)
      self.assertTrue(success)
      with open(output_path, 'rb') as f:
        self.assertEqual(f.read(), b'chunk1chunk2')

  def test_download_artifact_file_url_error(self):
    """Tests that download_artifact_file handles HTTP errors during signed URL
    retrieval and returns False.
    """
    mock_response = mock.MagicMock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        'Server error', response=mock_response)
    self.mock.get.return_value = mock_response

    success = self.api.download_artifact_file('123', 'target', 'latest',
                                              'file.txt', '/tmp/file.txt')
    self.assertFalse(success)

  def test_download_artifact_file_os_error(self):
    """Tests that download_artifact_file handles local filesystem OSError
    during download and returns False.
    """
    resp_url = mock.MagicMock()
    resp_url.status_code = 200
    resp_url.json.return_value = {
        'signedUrl': 'https://storage.googleapis.com/test'
    }

    resp_dl = mock.MagicMock()
    resp_dl.status_code = 200
    resp_dl.raise_for_status.side_effect = OSError('Disk error')

    self.mock.get.side_effect = [resp_url] + [resp_dl] * 10

    success = self.api.download_artifact_file('123', 'target', 'latest',
                                              'file.txt', '/invalid/dir/file')
    self.assertFalse(success)

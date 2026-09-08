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

import json
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
        'clusterfuzz._internal.base.utils.fetch_url',
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
    self.mock.fetch_url.return_value = json.dumps({
        'builds': [{
            'buildId': '123456',
            'target': {
                'name': 'target_name'
            }
        }]
    })

    result = self.api.list_builds(
        branch='git_main', target='target_name', signed=True)
    self.assertEqual(
        result,
        {'builds': [{
            'buildId': '123456',
            'target': {
                'name': 'target_name'
            }
        }]})
    self.mock.fetch_url.assert_called_once_with(
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
        request_timeout=60,
        raise_for_not_found=True)

  def test_list_builds_error(self):
    """Tests that list_builds handles HTTP errors gracefully by logging and
    returning None.
    """
    self.mock.fetch_url.side_effect = requests.exceptions.HTTPError(
        'Server error')

    result = self.api.list_builds('git_main', 'target_name')
    self.assertIsNone(result)

  def test_list_builds_json_error(self):
    """Tests that list_builds handles JSON decoding errors (ValueError) by
    returning None.
    """
    self.mock.fetch_url.return_value = 'invalid json'

    result = self.api.list_builds(branch='git_main', target='target_name')
    self.assertIsNone(result)

  def test_list_artifacts_pagination(self):
    """Tests that list_artifacts follows nextPageToken pagination and
    aggregates artifacts across pages.
    """
    resp1 = json.dumps({
        'artifacts': [{
            'name': 'art1'
        }],
        'nextPageToken': 'token123'
    })
    resp2 = json.dumps({'artifacts': [{'name': 'art2'}]})

    self.mock.fetch_url.side_effect = [resp1, resp2]

    artifacts = self.api.list_artifacts(
        bid='123', target='target_name', regexp='.*zip')
    self.assertEqual(artifacts, [{'name': 'art1'}, {'name': 'art2'}])

  def test_list_artifacts_error(self):
    """Tests that list_artifacts handles HTTP request errors gracefully by
    returning an empty list.
    """
    self.mock.fetch_url.side_effect = requests.exceptions.HTTPError(
        'Server error')

    artifacts = self.api.list_artifacts(bid='123', target='target_name')
    self.assertEqual(artifacts, [])

  def test_get_artifact_metadata(self):
    """Tests that get_artifact_metadata retrieves metadata dictionary for a
    specific build artifact.
    """
    self.mock.fetch_url.return_value = json.dumps({
        'buildArtifactMetadata': {
            'name': 'file.zip',
            'size': '100'
        }
    })

    metadata = self.api.get_artifact_metadata('123', 'target', 'latest',
                                              'file.zip')
    self.assertEqual(metadata, {'name': 'file.zip', 'size': '100'})

  def test_get_artifact_metadata_error(self):
    """Tests that get_artifact_metadata handles HTTP errors (e.g. 404) by
    returning None.
    """
    self.mock.fetch_url.side_effect = requests.exceptions.HTTPError('Not found')

    metadata = self.api.get_artifact_metadata(
        bid='123', target='target', attempt_id='latest', name='file.zip')
    self.assertIsNone(metadata)

  def test_download_artifact_file(self):
    """Tests that download_artifact_file fetches a signed URL and streams file
    chunks to local path.
    """
    resp_url = json.dumps({'signedUrl': 'https://storage.googleapis.com/test'})
    resp_dl = mock.MagicMock()
    resp_dl.status_code = 200
    resp_dl.iter_content.return_value = [b'chunk1', b'chunk2']

    self.mock.fetch_url.side_effect = [resp_url, resp_dl]

    with tempfile.TemporaryDirectory() as temp_dir:
      output_path = os.path.join(temp_dir, 'output.txt')
      success = self.api.download_artifact_file(
          bid='123',
          target='target',
          attempt_id='latest',
          name='file.txt',
          output_path=output_path)
      self.assertTrue(success)
      with open(output_path, 'rb') as f:
        self.assertEqual(f.read(), b'chunk1chunk2')

  def test_download_artifact_file_url_error(self):
    """Tests that download_artifact_file handles HTTP errors during signed URL
    retrieval and returns False.
    """
    self.mock.fetch_url.side_effect = requests.exceptions.HTTPError(
        'Server error')

    success = self.api.download_artifact_file(
        bid='123',
        target='target',
        attempt_id='latest',
        name='file.txt',
        output_path='/tmp/file.txt')
    self.assertFalse(success)

  def test_download_artifact_file_os_error(self):
    """Tests that download_artifact_file handles local filesystem OSError
    during download and returns False.
    """
    resp_url = json.dumps({'signedUrl': 'https://storage.googleapis.com/test'})
    resp_dl = mock.MagicMock()
    resp_dl.status_code = 200
    resp_dl.iter_content.side_effect = OSError('Disk error')

    self.mock.fetch_url.side_effect = [resp_url, resp_dl]

    with tempfile.TemporaryDirectory() as temp_dir:
      output_path = os.path.join(temp_dir, 'output.txt')
      success = self.api.download_artifact_file(
          bid='123',
          target='target',
          attempt_id='latest',
          name='file.txt',
          output_path=output_path)
      self.assertFalse(success)

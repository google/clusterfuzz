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
"""HTTP client for Android Build API V4 REST endpoints."""

import json
import os
from urllib.parse import quote

import google.auth.exceptions
from google.auth.transport.requests import Request
from google.oauth2 import service_account
import requests

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs

# HTTP request timeout in seconds.
HTTP_TIMEOUT = 60

# 20 MB default chunk size for file downloads.
DEFAULT_CHUNK_SIZE = 20 * 1024 * 1024


class AndroidBuildV4Api:
  """HTTP client for Android Build API V4 REST endpoints."""

  BASE_URL = 'https://androidbuild-pa.googleapis.com'

  def __init__(self, token: str):
    """Initializes the Android Build API V4 client.

    Do not call this directly. Use AndroidBuildV4Api.create_authenticated()
    instead.

    Args:
      token: OAuth2 authorization bearer token.
    """
    self.token = token

  @staticmethod
  def create_authenticated(
      credentials: service_account.Credentials) -> 'AndroidBuildV4Api':
    """Validates credentials and constructs an authenticated client instance.

    Args:
      credentials: Service account credentials for authenticating requests.

    Returns:
      An instance of AndroidBuildV4Api ready for requests.

    Raises:
      google.auth.exceptions.GoogleAuthError: If authentication token refresh
        fails.
    """
    if not credentials.valid:
      credentials.refresh(Request())
    return AndroidBuildV4Api(credentials.token)

  def _get_headers(self) -> dict[str, str]:
    """Returns headers required for Android Build API V4 requests.

    Returns:
      A dictionary containing the Authorization and Accept headers.
    """
    return {
        'Authorization': f'Bearer {self.token}',
        'Accept': 'application/json',
    }

  def _download_file(self, url: str, output_path: str) -> None:
    """Downloads content from a URL to output_path.

    Args:
      url: Download URL.
      output_path: Local filesystem path where the file should be saved.

    Raises:
      requests.exceptions.RequestException: If the HTTP download fails.
      OSError: If creating directories or writing the file fails.
    """
    dirname = os.path.dirname(output_path)
    if dirname:
      os.makedirs(dirname, exist_ok=True)

    response = utils.fetch_url(
        url,
        request_timeout=HTTP_TIMEOUT,
        raise_for_not_found=True,
        stream=True)
    with open(output_path, 'wb') as f:
      for chunk in response.iter_content(chunk_size=DEFAULT_CHUNK_SIZE):
        if chunk:
          f.write(chunk)

  def list_builds(self, branch: str, target: str,
                  signed: bool = False) -> dict | None:
    """List builds for a branch and target.

    Args:
      branch: Android build branch (e.g. 'git_main').
      target: Android build target (e.g. 'cf_x86_64_phone-next-userdebug').
      signed: Whether to request signed builds only.

    Returns:
      JSON response dictionary containing builds, or None on failure.
    """
    params = {
        'buildType': 'submitted',
        'branches': branch,
        'targets': target,
        'successful': 'true',
        'pageSize': 1,
    }
    if signed:
      params['signed'] = 'true'

    url = f'{self.BASE_URL}/v4/builds'
    try:
      response_text = utils.fetch_url(
          url,
          params=params,
          headers=self._get_headers(),
          request_timeout=HTTP_TIMEOUT,
          raise_for_not_found=True)
      data = json.loads(response_text)
      if data.get('builds') and len(data['builds']) > 0:
        return data
      return None
    except (requests.exceptions.RequestException,
            google.auth.exceptions.GoogleAuthError, ValueError) as e:
      logs.error(
          f'V4 list_builds failed for branch {branch}, target {target}: {e}')
      return None

  def list_artifacts(self,
                     bid: str,
                     target: str,
                     attempt_id: str = 'latest',
                     regexp: str | None = None,
                     page_size: int = 100) -> list:
    """List artifacts for a given build.

    Args:
      bid: Android build ID.
      target: Android build target name.
      attempt_id: Build attempt identifier (defaults to 'latest').
      regexp: Optional regular expression pattern to filter artifact names.
      page_size: Number of artifacts per page (defaults to 100).

    Returns:
      List of artifact dictionary objects.
    """
    params = {'pageSize': page_size}
    if regexp:
      params['nameRegexp'] = regexp

    path = f'/v4/builds/{bid}/{target}/attempts/{attempt_id}/artifacts'
    url = f'{self.BASE_URL}{path}'
    artifacts = []

    page_token = None
    while True:
      if page_token:
        params['pageToken'] = page_token

      try:
        response_text = utils.fetch_url(
            url,
            params=params,
            headers=self._get_headers(),
            request_timeout=HTTP_TIMEOUT,
            raise_for_not_found=True)
        result = json.loads(response_text)
      except (requests.exceptions.RequestException,
              google.auth.exceptions.GoogleAuthError, ValueError) as e:
        logs.error(
            f'V4 list_artifacts failed for build {bid}, target {target}: {e}')
        break

      if 'artifacts' in result:
        artifacts.extend(result['artifacts'])

      page_token = result.get('nextPageToken')
      if not page_token:
        break

    return artifacts

  def get_artifact_metadata(self, bid: str, target: str, attempt_id: str,
                            name: str) -> dict | None:
    """Get artifact metadata.

    Args:
      bid: Android build ID.
      target: Android build target name.
      attempt_id: Build attempt identifier.
      name: Artifact name.

    Returns:
      Artifact metadata dictionary, or None on failure.
    """
    resource_id = quote(name, safe='')
    path = (f'/v4/builds/{bid}/{target}/attempts/{attempt_id}'
            f'/artifacts/{resource_id}')
    url = f'{self.BASE_URL}{path}'
    try:
      response_text = utils.fetch_url(
          url,
          headers=self._get_headers(),
          request_timeout=HTTP_TIMEOUT,
          raise_for_not_found=True)
      data = json.loads(response_text)
      return data.get('buildArtifactMetadata', data)
    except (requests.exceptions.RequestException,
            google.auth.exceptions.GoogleAuthError, ValueError) as e:
      logs.error(f'V4 get_artifact_metadata failed for artifact {name}: {e}')
      return None

  def download_artifact_file(self, bid: str, target: str, attempt_id: str,
                             name: str, output_path: str) -> bool:
    """Download artifact file content using signed URL.

    Args:
      bid: Android build ID.
      target: Android build target name.
      attempt_id: Build attempt identifier.
      name: Artifact name.
      output_path: Local filesystem path where the file should be saved.

    Returns:
      True if download succeeded, False otherwise.
    """
    resource_id = quote(name, safe='')
    path = (f'/v4/builds/{bid}/{target}/attempts/{attempt_id}'
            f'/artifacts/{resource_id}/url')
    url = f'{self.BASE_URL}{path}'
    try:
      response_text = utils.fetch_url(
          url,
          headers=self._get_headers(),
          request_timeout=HTTP_TIMEOUT,
          raise_for_not_found=True)
      signed_url = json.loads(response_text).get('signedUrl')
    except (requests.exceptions.RequestException,
            google.auth.exceptions.GoogleAuthError, ValueError) as e:
      logs.error(f'Error getting V4 download url for artifact {name}: {e}')
      return False

    if not signed_url:
      logs.error(f'V4 download url missing in response for artifact {name}')
      return False

    try:
      self._download_file(signed_url, output_path)
      return True
    except (requests.exceptions.RequestException, OSError) as e:
      logs.error(f'Error downloading V4 media for artifact {name}: {e}')
      return False

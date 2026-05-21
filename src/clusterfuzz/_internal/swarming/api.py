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
"""Swarming pRPC API client."""

from typing import Optional

from google.auth import exceptions as auth_exceptions
from google.protobuf import json_format

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config.local_config import SwarmingConfig
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.swarming import get_swarming_config

_SWARMING_SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/userinfo.email'
]

_COUNT_TASKS_ENDPOINT = 'swarming.v2.Tasks/CountTasks'
_NEW_TASK_ENDPOINT = 'swarming.v2.Tasks/NewTask'


class SwarmingApi:
  """Client for Swarming pRPC API."""

  _config: SwarmingConfig
  _base_url: str = ""

  def __init__(self, config: SwarmingConfig):
    self._config = config
    self._base_url = f"https://{self._config.get('swarming_server')}/prpc/"

  @staticmethod
  def create() -> Optional['SwarmingApi']:
    """Creates a SwarmingApi instance if config is available.

    Returns:
      A SwarmingApi instance if config is available, None otherwise.
    """
    config = get_swarming_config()
    if config is None:
      return None

    return SwarmingApi(config)

  def _get_token(self) -> str:
    """Gets a valid token for the Swarming API.  Returns "" if it fails."""
    try:
      creds = credentials.get_scoped_service_account_credentials(
          _SWARMING_SCOPES)
      if not creds:
        logs.error('[Swarming] Failed to get credentials. None found.')
        return ""

      return creds.token
    except (auth_exceptions.DefaultCredentialsError,
            auth_exceptions.RefreshError, auth_exceptions.TransportError) as e:
      logs.error(f'[Swarming] Failed to get token with: {e}.')
      return ""

  def _get_headers(self) -> dict[str, str]:
    """Checks config and returns headers for pRPC request.
    
    Returns:
      A dict containing headers.
    """
    token = self._get_token()

    return {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }

  def _make_request(self, endpoint: str, body: str) -> str:
    """Makes a pRPC request to the Swarming API.

    Args:
      endpoint: The pRPC endpoint (e.g. "swarming.v2.Tasks/NewTask").
      body: The JSON body of the request.
      
    Returns:
      The raw JSON response string from the server, or None if the response is
      empty.

    Raises:
      requests.exceptions.HTTPError: If the request fails with a 4xx or 5xx
        status code.
    """
    headers = self._get_headers()

    url = f'{self._base_url}{endpoint}'
    logs.info(
        f"[Swarming] Making request to {url}",
        url=self._base_url,
        endpoint=endpoint,
        body=body,
        headers=headers)
    response = utils.post_url(url=url, data=body, headers=headers)
    if not response:
      logs.error(f"[Swarming] Failed to make request to {url}. Empty response")
      return None
    return response

  def push_task(
      self,
      task_request: swarming_pb2.NewTaskRequest  # pylint: disable=no-member
  ) -> swarming_pb2.TaskRequestResponse | None:  # pylint: disable=no-member
    """Schedules a task on swarming.
    
    Args:
      task_request: The NewTaskRequest proto message.
      
    Returns:
      The TaskRequestResponse proto message from the server, or None if the
      response is empty.

    Raises:
      requests.exceptions.HTTPError: If the request fails with a 4xx or 5xx
        status code.
    """
    message_body = json_format.MessageToJson(task_request)

    raw_response = self._make_request(_NEW_TASK_ENDPOINT, message_body)
    if not raw_response:
      return None

    task_response = swarming_pb2.TaskRequestResponse()  # pylint: disable=no-member
    json_format.Parse(raw_response, task_response)
    return task_response

  def count_tasks(self,
                  count_request: swarming_pb2.TasksCountRequest) -> str | None:  # pylint: disable=no-member
    """Counts tasks on swarming.
    
    Args:
      count_request: The TasksCountRequest proto message.
      
    Returns:
      The raw JSON response string from the server, or None if the response is
      empty.

    Raises:
      requests.exceptions.HTTPError: If the request fails with a 4xx or 5xx
        status code.
    """
    message_body = json_format.MessageToJson(count_request)

    response = self._make_request(_COUNT_TASKS_ENDPOINT, message_body)
    return response

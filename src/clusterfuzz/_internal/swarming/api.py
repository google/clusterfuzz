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

from google.auth.transport import requests
from google.protobuf import json_format

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.errors import BadConfigError
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import swarming_pb2

_SWARMING_SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/userinfo.email'
]


class SwarmingAPI:
  """Client for Swarming pRPC API."""

  def __init__(self):
    try:
      self.config = local_config.SwarmingConfig()
    except (BadConfigError, ValueError) as e:
      logs.error(f'[Swarming] Failed to retrieve config: {e}')
      self.config = None

  def _get_headers(self) -> dict:
    """Checks config and returns headers for pRPC request.
    
    Returns:
      A dict containing headers, or empty dict if config is missing or
      auth fails.
    """
    if not self.config:
      logs.error('[Swarming] No config available.')
      return {}

    creds = credentials.get_scoped_service_account_credentials(_SWARMING_SCOPES)
    if not creds:
      logs.error('[Swarming] Failed to get credentials.')
      return {}

    if not creds.token:
      creds.refresh(requests.Request())

    return {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {creds.token}'
    }

  def push_task(self, task_request: swarming_pb2.NewTaskRequest) -> str | None:  # pylint: disable=no-member
    """Schedules a task on swarming.
    
    Args:
      task_request: The NewTaskRequest proto message.
      
    Returns:
      The raw JSON response string from the server, or None if the request
      could not be made (e.g. missing config, auth failure) or failed.
    """
    headers = self._get_headers()
    if not headers:
      return None

    swarming_server = self.config.get('swarming_server')
    url = f'https://{swarming_server}/prpc/swarming.v2.Tasks/NewTask'
    message_body = json_format.MessageToJson(task_request)

    logs.info(
        f"[Swarming] Pushing task {task_request.name}",
        url=url,
        body=message_body)

    response = utils.post_url(url=url, data=message_body, headers=headers)
    logs.info(
        f'[Swarming] Response from {task_request.name}', response=response)
    return response

  def count_tasks(self,
                  count_request: swarming_pb2.TasksCountRequest) -> str | None:  # pylint: disable=no-member
    """Counts tasks on swarming.
    
    Args:
      count_request: The TasksCountRequest proto message.
      
    Returns:
      The raw JSON response string from the server, or None if the request
      could not be made (e.g. missing config, auth failure) or failed.
    """
    headers = self._get_headers()
    if not headers:
      return None

    swarming_server = self.config.get('swarming_server')
    url = f'https://{swarming_server}/prpc/swarming.v2.Tasks/CountTasks'
    message_body = json_format.MessageToJson(count_request)

    logs.info("[Swarming] Counting tasks", url=url, body=message_body)

    response = utils.post_url(url=url, data=message_body, headers=headers)
    logs.info('[Swarming] Response from CountTasks', response=response)
    return response

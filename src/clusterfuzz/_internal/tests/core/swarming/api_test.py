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
"""Tests for api.py."""
import unittest
from unittest import mock

from google.protobuf import json_format
from requests.exceptions import HTTPError

from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.swarming.api import SwarmingApi
from clusterfuzz._internal.swarming.api import SwarmingApiError
from clusterfuzz._internal.tests.test_libs import helpers


class SwarmingAPITest(unittest.TestCase):
  """Tests for SwarmingAPI."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.post_url',
        'clusterfuzz._internal.google_cloud_utils.credentials.get_scoped_service_account_credentials',
        'google.auth.transport.requests.Request',
    ])
    helpers.patch_environ(self)

    self.mock_creds = mock.MagicMock()
    self.mock_creds.token = 'fake_token'
    self.mock.get_scoped_service_account_credentials.return_value = self.mock_creds

    self.api = SwarmingApi.create()

  def test_push_task(self):
    """Tests that push_task works as expected."""
    expected_response = '{"taskId": "123"}'
    self.mock.post_url.return_value = expected_response
    task_request = swarming_pb2.NewTaskRequest(
        name='test_task',
        priority=1,
        realm='realm-name',
        service_account='test-account@google.com',
        task_slices=[
            swarming_pb2.TaskSlice(
                expiration_secs=86400,
                properties=swarming_pb2.TaskProperties(
                    command=['./run.sh'],
                    dimensions=[
                        swarming_pb2.StringPair(key='os', value='Linux'),
                        swarming_pb2.StringPair(key='pool', value='test-pool')
                    ],
                    execution_timeout_secs=3600,
                    env=[
                        swarming_pb2.StringPair(key='UWORKER', value='True'),
                    ],
                    secret_bytes=b'secret_data'))
        ])

    response = self.api.push_task(task_request)

    expected_headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer fake_token'
    }
    expected_url = 'https://server-name/prpc/swarming.v2.Tasks/NewTask'
    self.mock.post_url.assert_called_with(
        url=expected_url,
        data=json_format.MessageToJson(task_request),
        headers=expected_headers)
    self.assertEqual(response, expected_response)

  def test_count_tasks(self):
    """Tests that count_tasks works as expected."""
    count_request = swarming_pb2.TasksCountRequest(tags=['tag1'])

    self.mock.post_url.return_value = '{"count": 42}'
    response = self.api.count_tasks(count_request)

    expected_headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer fake_token'
    }
    expected_url = 'https://server-name/prpc/swarming.v2.Tasks/CountTasks'

    expected_request = swarming_pb2.TasksCountRequest(tags=['tag1'])
    json_format.Parse('"2026-06-01T00:00:00Z"', expected_request.start)

    self.mock.post_url.assert_called_with(
        url=expected_url,
        data=json_format.MessageToJson(expected_request),
        headers=expected_headers)

    self.assertEqual(response.count, 42)

  def test_count_tasks_default_start(self):
    """Tests that count_tasks sets default start time if not provided."""
    count_request = swarming_pb2.TasksCountRequest(tags=['tag1'])
    self.mock.post_url.return_value = '{"count": 42}'

    self.api.count_tasks(count_request)

    kwargs = self.mock.post_url.call_args.kwargs
    sent_data = kwargs['data']
    sent_request = json_format.Parse(sent_data,
                                     swarming_pb2.TasksCountRequest())
    self.assertTrue(sent_request.HasField('start'))

  def test_count_tasks_empty_response(self):
    """Tests that count_tasks raises SwarmingApiError on empty response."""
    count_request = swarming_pb2.TasksCountRequest(tags=['tag1'])

    self.mock.post_url.return_value = ''

    with self.assertRaises(SwarmingApiError):
      self.api.count_tasks(count_request)

  def test_count_tasks_parse_error(self):
    """Tests that count_tasks raises SwarmingApiError on parse failure."""
    count_request = swarming_pb2.TasksCountRequest(tags=['tag1'])

    self.mock.post_url.return_value = 'invalid json'

    with self.assertRaises(SwarmingApiError):
      self.api.count_tasks(count_request)

  def test_create_no_config(self):
    """Tests that create returns None when config is missing."""
    with mock.patch('clusterfuzz._internal.swarming.api.get_swarming_config'
                   ) as mock_get_config:
      mock_get_config.return_value = None
      self.assertIsNone(SwarmingApi.create())

  def test_push_task_no_credentials(self):
    """Tests that push_task gets called with an empty token when credentials are missing."""
    self.mock.get_scoped_service_account_credentials.return_value = None
    self.api.push_task(swarming_pb2.NewTaskRequest())

    _, kwargs = self.mock.post_url.call_args
    self.assertEqual(kwargs['headers']['Authorization'], 'Bearer ')

  def test_count_tasks_no_credentials(self):
    """Tests that count_tasks gets called with an empty token when credentials are missing."""
    self.mock.get_scoped_service_account_credentials.return_value = None
    self.mock.post_url.return_value = '{}'
    self.api.count_tasks(swarming_pb2.TasksCountRequest())

    _, kwargs = self.mock.post_url.call_args
    self.assertEqual(kwargs['headers']['Authorization'], 'Bearer ')

  def test_push_task_auth_error(self):
    """Tests that push_task raises HTTPError on auth failure."""
    self.mock.get_scoped_service_account_credentials.return_value = None
    self.mock.post_url.side_effect = HTTPError(
        "Unauthorized", response=mock.Mock(status_code=401))

    with self.assertRaises(HTTPError):
      self.api.push_task(swarming_pb2.NewTaskRequest())

  def test_count_tasks_auth_error(self):
    """Tests that count_tasks raises SwarmingApiError on auth failure."""
    self.mock.get_scoped_service_account_credentials.return_value = None
    self.mock.post_url.side_effect = HTTPError(
        "Unauthorized", response=mock.Mock(status_code=401))

    with self.assertRaises(SwarmingApiError):
      self.api.count_tasks(swarming_pb2.TasksCountRequest())

  def test_get_token_catches_default_credentials_error(self):
    """Tests that _get_token catches DefaultCredentialsError and returns empty token."""
    from google.auth.exceptions import DefaultCredentialsError
    self.mock.get_scoped_service_account_credentials.side_effect = DefaultCredentialsError(
        "No creds")

    self.api.push_task(swarming_pb2.NewTaskRequest())

    _, kwargs = self.mock.post_url.call_args
    self.assertEqual(kwargs['headers']['Authorization'], 'Bearer ')

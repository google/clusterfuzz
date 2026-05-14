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

from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.swarming.api import SwarmingAPI
from clusterfuzz._internal.tests.test_libs import helpers


class SwarmingAPITest(unittest.TestCase):
  """Tests for SwarmingAPI."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.post_url',
        'clusterfuzz._internal.google_cloud_utils.credentials.get_scoped_service_account_credentials',
        'google.auth.transport.requests.Request',
    ])

    self.mock_creds = mock.MagicMock()
    self.mock_creds.token = 'fake_token'
    self.mock.get_scoped_service_account_credentials.return_value = self.mock_creds

    self.api = SwarmingAPI()

  def test_push_task(self):
    """Tests that push_task works as expected."""
    task_request = swarming_pb2.NewTaskRequest(name='test_task')
    self.api.push_task(task_request)

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

  def test_count_tasks(self):
    """Tests that count_tasks works as expected."""
    count_request = swarming_pb2.TasksCountRequest(tags=['tag1'])

    # Mock response from post_url
    self.mock.post_url.return_value = '{"count": 42}'

    response = self.api.count_tasks(count_request)

    expected_headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer fake_token'
    }
    expected_url = 'https://server-name/prpc/swarming.v2.Tasks/CountTasks'
    self.mock.post_url.assert_called_with(
        url=expected_url,
        data=json_format.MessageToJson(count_request),
        headers=expected_headers)

    self.assertEqual(response, '{"count": 42}')

  def test_push_task_no_config(self):
    """Tests that push_task fails when config is missing."""
    with mock.patch('clusterfuzz._internal.config.local_config.SwarmingConfig'
                   ) as mock_config:
      mock_config.side_effect = ValueError('Failed to load')
      api = SwarmingAPI()
      response = api.push_task(swarming_pb2.NewTaskRequest())
      self.assertIsNone(response)

  def test_push_task_no_credentials(self):
    """Tests that push_task fails when credentials are missing."""
    self.mock.get_scoped_service_account_credentials.return_value = None
    response = self.api.push_task(swarming_pb2.NewTaskRequest())
    self.assertIsNone(response)

  def test_count_tasks_no_credentials(self):
    """Tests that count_tasks fails when credentials are missing."""
    self.mock.get_scoped_service_account_credentials.return_value = None
    response = self.api.count_tasks(swarming_pb2.TasksCountRequest())
    self.assertIsNone(response)

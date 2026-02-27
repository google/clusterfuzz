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
"""Tests for queue size retrieval."""
import unittest
from unittest import mock

from clusterfuzz._internal.base import tasks


class GetUtaskMainQueueSizeTest(unittest.TestCase):
  """Tests for getting utask main queue size."""

  def setUp(self):
    self.creds_patcher = mock.patch(
        'clusterfuzz._internal.google_cloud_utils.credentials.get_default')
    self.mock_creds = self.creds_patcher.start()
    self.mock_creds.return_value = (mock.Mock(), 'project')

    self.monitoring_patcher = mock.patch(
        'google.cloud.monitoring_v3.MetricServiceClient')
    self.mock_monitoring = self.monitoring_patcher.start()

    self.env_patcher = mock.patch(
        'clusterfuzz._internal.system.environment.get_value')
    self.mock_env = self.env_patcher.start()
    self.mock_env.return_value = None  # Default no OS version

    self.utils_patcher = mock.patch(
        'clusterfuzz._internal.base.utils.get_application_id')
    self.mock_utils = self.utils_patcher.start()
    self.mock_utils.return_value = 'test-project'

  def tearDown(self):
    self.creds_patcher.stop()
    self.monitoring_patcher.stop()
    self.env_patcher.stop()
    self.utils_patcher.stop()

  def test_get_size_success(self):
    """Test successful retrieval of queue size."""
    mock_client = self.mock_monitoring.return_value
    mock_point = mock.Mock()
    mock_point.value.int64_value = 12345
    mock_series = mock.Mock()
    mock_series.points = [mock_point]
    mock_client.list_time_series.return_value = [mock_series]

    size = tasks.get_utask_main_queue_size(__memoize_force__=True)
    self.assertEqual(size, 12345)

    mock_client.list_time_series.assert_called_once()
    kwargs = mock_client.list_time_series.call_args[1]
    self.assertIn(
        'metric.type="pubsub.googleapis.com/subscription/num_undelivered_messages"',
        kwargs['request']['filter'])
    self.assertIn('resource.labels.subscription_id="utask_main"',
                  kwargs['request']['filter'])

  def test_get_size_with_os_version(self):
    """Test retrieval of queue size with OS version suffix."""
    self.mock_env.return_value = 'focal'
    mock_client = self.mock_monitoring.return_value
    mock_point = mock.Mock()
    mock_point.value.int64_value = 10
    mock_series = mock.Mock()
    mock_series.points = [mock_point]
    mock_client.list_time_series.return_value = [mock_series]

    size = tasks.get_utask_main_queue_size(__memoize_force__=True)
    self.assertEqual(size, 10)

    kwargs = mock_client.list_time_series.call_args[1]
    self.assertIn('resource.labels.subscription_id="utask_main-focal"',
                  kwargs['request']['filter'])

  def test_get_size_failure(self):
    """Test failure to retrieve queue size (returns 0)."""
    mock_client = self.mock_monitoring.return_value
    mock_client.list_time_series.side_effect = Exception("Boom")
    size = tasks.get_utask_main_queue_size(__memoize_force__=True)
    self.assertEqual(size, 0)

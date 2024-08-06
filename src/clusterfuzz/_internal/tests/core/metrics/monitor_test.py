# Copyright 2019 Google LLC
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
"""Tests for monitor."""
# pylint: disable=protected-access

import os
import queue
import unittest
from unittest.mock import patch

from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.tests.test_libs import helpers


class InitializeTest(unittest.TestCase):
  """Tests for initialize."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.ProjectConfig.get',
        'clusterfuzz._internal.metrics.monitor.check_module_loaded',
        'google.cloud.monitoring_v3.MetricServiceClient',
        'threading.Thread.start',
    ])
    helpers.patch_environ(self, {})
    self.mock.check_module_loaded.return_value = True
    self.mock.get.return_value = True

    os.environ['BOT_NAME'] = 'somebot'

  def test_local(self):
    """Tests no initialization on local development."""
    os.environ['LOCAL_DEVELOPMENT'] = '1'
    monitor.initialize()
    self.assertEqual(0, self.mock.start.call_count)

  def test_disabled(self):
    """Tests no initialization when monitoring is disabled in config."""
    self.mock.get.return_value = False
    monitor.initialize()
    self.assertEqual(0, self.mock.start.call_count)

  def test_error(self):
    """Tests error."""
    self.mock.check_module_loaded.return_value = False
    monitor.initialize()
    self.assertEqual(0, self.mock.start.call_count)

  def test_initialize(self):
    """Tests initialization."""
    monitor.initialize()
    self.assertEqual(1, self.mock.start.call_count)


class MonitorTest(unittest.TestCase):
  """Tests for monitor functions."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.monitor.check_module_loaded',
    ])
    self.mock.check_module_loaded.return_value = True
    monitor.metrics_store().reset_for_testing()

  def test_counter_metric_success(self):
    self.assertIsInstance(
        monitor.CounterMetric('t', 'desc', field_spec=None),
        monitor._CounterMetric)

  def test_counter_metric_failure(self):
    """Test counter metric failure."""
    self.mock.check_module_loaded.return_value = False
    counter = monitor.CounterMetric(
        't', 'desc', field_spec=[
            monitor.StringField('name'),
        ])
    counter.increment()
    counter.increment({'name': 'test'})
    counter.increment_by(5)
    self.assertIsInstance(counter, monitor._MockMetric)

  def test_cumulative_distribution_metric_success(self):
    self.assertIsInstance(
        monitor.CumulativeDistributionMetric(
            'd', 'desc', bucketer=None, field_spec=None),
        monitor._CumulativeDistributionMetric)

  def test_cumulative_distribution_metric_failure(self):
    self.mock.check_module_loaded.return_value = False
    counter = monitor.CumulativeDistributionMetric(
        'd', 'desc', bucketer=None, field_spec=None)
    counter.add(10)
    self.assertIsInstance(counter, monitor._MockMetric)

  def test_get_region(self):
    """Ensure it assigns the right region"""
    self.assertEqual('linux', monitor._get_region('clusterfuzz-linux-0123'))
    self.assertEqual('linux', monitor._get_region('clusterfuzz-linux-hijk'))
    self.assertEqual('linux-high-end',
                     monitor._get_region('clusterfuzz-linux-high-end-0017'))
    self.assertEqual('linux-pre',
                     monitor._get_region('clusterfuzz-linux-pre-0123'))
    self.assertEqual('windows', monitor._get_region('clusterfuzz-windows-0010'))
    self.assertEqual('windows-pre',
                     monitor._get_region('clusterfuzz-windows-pre-0017'))
    self.assertEqual('android', monitor._get_region('clusterfuzz-android-1337'))
    self.assertEqual('mac', monitor._get_region('clusterfuzz-mac-1337'))
    self.assertEqual('unknown', monitor._get_region('diwejfwlejf'))

  def test_cumulative_distribution_metric_fixed(self):
    """Test _CumulativeDistributionMetric with fixed bucketer."""
    # Buckets:
    #   [-Inf, 0.1)
    #   [0.1, 0.2)
    #   [0.2, 0.3)
    #   ...
    #   [1.0, Inf)
    metric = monitor.CumulativeDistributionMetric(
        'name',
        description='test metric',
        bucketer=monitor.FixedWidthBucketer(width=0.1, num_finite_buckets=10),
        field_spec=None)

    metric.add(-1)
    metric.add(0.05)
    metric.add(0.1)
    metric.add(0.15)
    metric.add(0.3)
    metric.add(0.75)
    metric.add(1)
    metric.add(2)

    result = monitor.metrics_store().get(metric, None).value

    self.assertListEqual([
        1,
        1,
        2,
        1,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        2,
    ], result.buckets)

  def test_gauge_metric_success(self):
    """Test gauge metric success."""
    self.assertIsInstance(
        monitor.GaugeMetric('g', 'desc', field_spec=None), monitor._GaugeMetric)

  def test_gauge_metric_failure(self):
    """Test gauge metric failure."""
    self.mock.check_module_loaded.return_value = False
    gauge = monitor.GaugeMetric(
        'g', 'desc', field_spec=[
            monitor.StringField('name'),
        ])
    gauge.set(5)
    self.assertIsInstance(gauge, monitor._MockMetric)


class TestFlusherThread(unittest.TestCase):
  """Sets up the flusher thread and mocks MetricServiceClient."""

  @patch(
      'clusterfuzz._internal.metrics.monitor.monitoring_v3.MetricServiceClient')
  def test_flusher_thread(self, mock_client):
    """Sets up the flusher thread and calls run()."""

    monitor._monitoring_v3_client = mock_client.return_value
    monitor._flusher_thread = monitor._FlusherThread()
    monitor.FLUSH_INTERVAL_SECONDS = 1
    monitoring_metrics.BOT_COUNT.set(1, {'revision': '1'})
    monitoring_metrics.HOST_INCONSISTENT_COUNT.increment()
    os.environ['BOT_NAME'] = 'bot-1'

    call_queue = queue.Queue()
    mock_create_time_series = mock_client.return_value.create_time_series

    mock_create_time_series.side_effect = (
        lambda **kwargs: call_queue.put(kwargs))

    monitor._flusher_thread.start()
    try:
      args = call_queue.get(timeout=10)
      time_series = args['time_series']
      for i in range(1, len(time_series)):
        self.assertLessEqual(time_series[i - 1].points[0].interval.start_time,
                             time_series[i].points[0].interval.start_time)
    except queue.Empty:
      self.fail("Queue timed out, no arguments received from mocked method")
    monitor._flusher_thread.stop()


@unittest.skip('Skip this because it\'s only used by metzman for debugging.')
class JonathanDebugTest(unittest.TestCase):
  """Sets up the flusher thread so we can debug it."""

  def test_flush(self):
    """Sets up the flusher thread so we can debug it."""
    monitor.credentials._use_anonymous_credentials = lambda: False
    monitor._monitoring_v3_client = monitor.monitoring_v3.MetricServiceClient(
        credentials=monitor.credentials.get_default()[0])
    monitor._flusher_thread = monitor._FlusherThread()
    monitor.FLUSH_INTERVAL_SECONDS = 1
    monitoring_metrics.BOT_COUNT.set(1, {'revision': '1'})
    monitor.utils.get_application_id = lambda: 'google.com:clusterfuzz'
    os.environ['BOT_NAME'] = 'bot-1'
    monitor._initialize_monitored_resource()
    monitor._monitored_resource.labels['zone'] = 'us-central1-b'
    monitor._flusher_thread.run()

  def test_cumulative_distribution_metric_geometric(self):
    """Test _CumulativeDistributionMetric with geometric bucketer."""
    # Buckets:
    #   [-Inf, 1)
    #   [1, 2)
    #   [2, 4)
    #   [4, 8)
    #   [8, 16)
    #   [16, 32)
    #   [32, 64)
    #   [64, Inf)
    metric = monitor.CumulativeDistributionMetric(
        'name',
        description='test metric',
        bucketer=monitor.GeometricBucketer(
            scale=1.0, growth_factor=2, num_finite_buckets=6),
        field_spec=None)

    metric.add(0)
    metric.add(1)
    metric.add(2)
    metric.add(3)
    metric.add(12)
    metric.add(17)
    metric.add(31)
    metric.add(32.1)
    metric.add(40)
    metric.add(64.1)
    result = monitor.metrics_store().get(metric, None).value

    self.assertListEqual([
        1,
        1,
        2,
        0,
        1,
        2,
        2,
        1,
    ], result.buckets)

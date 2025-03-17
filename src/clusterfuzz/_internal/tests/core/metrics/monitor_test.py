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
import time
import unittest
from unittest.mock import patch

from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.platforms.android import flash
from clusterfuzz._internal.system import environment
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
        'clusterfuzz._internal.base.persistent_cache.get_value',
        'clusterfuzz._internal.base.persistent_cache.set_value',
        'clusterfuzz._internal.base.persistent_cache.delete_value',
        'clusterfuzz._internal.platforms.android.settings.is_google_device',
        'clusterfuzz._internal.platforms.android.fetch_artifact.get_latest_artifact_info',
        'clusterfuzz._internal.system.environment.is_android_cuttlefish',
        'clusterfuzz._internal.platforms.android.flash.download_latest_build',
        'clusterfuzz._internal.platforms.android.adb.connect_to_cuttlefish_device',
        'clusterfuzz._internal.platforms.android.adb.recreate_cuttlefish_device',
        'clusterfuzz._internal.platforms.android.adb.get_device_state',
        'clusterfuzz._internal.platforms.android.adb.bad_state_reached',
    ])
    self.mock.check_module_loaded.return_value = True
    self.mock.get_value.return_value = None
    self.mock.is_google_device.return_value = True
    self.mock.get_latest_artifact_info.return_value = {
        'bid': 'test-bid',
        'branch': 'test-branch',
        'target': 'test-target'
    }
    self.mock.is_android_cuttlefish.return_value = True
    environment.set_value('BUILD_BRANCH', 'test-branch')
    environment.set_value('BUILD_TARGET', 'test-target')
    monitor.metrics_store().reset_for_testing()

  def _setup_monitoring_daemon(self, mock_client):
    """Setup and start monitoring daemon."""
    monitor.credentials._use_anonymous_credentials = lambda: False
    monitor._monitoring_v3_client = mock_client.return_value
    monitor.FLUSH_INTERVAL_SECONDS = 10
    monitor._monitoring_daemon = monitor._MonitoringDaemon(
        monitor._flush_metrics, monitor.FLUSH_INTERVAL_SECONDS)
    monitor.utils.get_application_id = lambda: 'google.com:clusterfuzz'
    os.environ['BOT_NAME'] = 'bot-1'
    monitor._initialize_monitored_resource()
    monitor._monitored_resource.labels['zone'] = 'us-central1-b'
    call_queue = queue.Queue()
    mock_create_time_series = mock_client.return_value.create_time_series
    mock_create_time_series.side_effect = (
        lambda **kwargs: call_queue.put(kwargs))
    monitor._monitoring_daemon.start()
    return call_queue

  def _assert_cuttlefish_boot_metric(self, time_series, is_succeeded):
    """Asserts Cuttlefish boot failure metric presence and correctness in time series."""
    for ts in time_series:
      if ts.metric.type == "custom.googleapis.com/tip_boot_failure":
        if is_succeeded is not None and ts.metric.labels['is_succeeded'] != str(
            is_succeeded):
          continue
        self.assertEqual(ts.metric.labels['is_succeeded'], str(is_succeeded))
        self.assertEqual(ts.metric.labels['build_id'], "test-bid")

  @patch(
      'clusterfuzz._internal.metrics.monitor.monitoring_v3.MetricServiceClient')
  def test_cuttlefish_boot_success_metric(self, mock_client):
    """Tests the metric emission for a successful Cuttlefish boot."""
    call_queue = self._setup_monitoring_daemon(mock_client)
    self.mock.get_device_state.return_value = 'device'
    flash.flash_to_latest_build_if_needed()
    args = call_queue.get(timeout=20)
    time_series = args['time_series']
    self._assert_cuttlefish_boot_metric(time_series, True)
    monitor._monitoring_daemon.stop()

  @patch(
      'clusterfuzz._internal.metrics.monitor.monitoring_v3.MetricServiceClient')
  def test_cuttlefish_boot_failure_metric(self, mock_client):
    """Tests the metric emission for a failed Cuttlefish boot."""
    call_queue = self._setup_monitoring_daemon(mock_client)
    flash.flash_to_latest_build_if_needed()
    args = call_queue.get(timeout=20)
    time_series = args['time_series']
    self._assert_cuttlefish_boot_metric(time_series, False)
    monitor._monitoring_daemon.stop()

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


class TestMonitoringDaemon(unittest.TestCase):
  """Tests that the monitoring daemon correctly flushes, and terminates."""

  def test_monitoring_daemon_calls_flush_while_looping(self):
    """Tests that flushes happen during the flushing loop."""
    calls = 0

    def mock_flush():
      nonlocal calls
      calls += 1

    daemon = monitor._MonitoringDaemon(mock_flush, 1)
    daemon.start()
    time.sleep(2)
    assert calls > 0
    daemon.stop()
    assert not daemon._flushing_thread.is_alive()

  def test_monitoring_daemon_flushes_after_stop(self):
    """Tests that flushes happen during prior to exit."""
    calls = 0

    def mock_flush():
      nonlocal calls
      calls += 1

    # Impose an absurdly large ticking interval, so only the
    # closing flush happens
    daemon = monitor._MonitoringDaemon(mock_flush, 10000)
    daemon.start()
    assert calls == 0
    daemon.stop()
    assert not daemon._flushing_thread.is_alive()
    assert calls == 1


@unittest.skip('Skip this because it\'s only used by metzman for debugging.')
class JonathanDebugTest(unittest.TestCase):
  """Sets up the flusher thread so we can debug it."""

  def test_flush(self):
    """Sets up the flusher thread so we can debug it."""
    monitor.credentials._use_anonymous_credentials = lambda: False
    monitor._monitoring_v3_client = monitor.monitoring_v3.MetricServiceClient(
        credentials=monitor.credentials.get_default()[0])
    monitor.FLUSH_INTERVAL_SECONDS = 1
    monitor._monitoring_daemon = monitor._MonitoringDaemon(
        monitor._flush_metrics, monitor.FLUSH_INTERVAL_SECONDS)
    labels = {
        'revision': '1',
        'os_type': 'linux',
        'release': 'candidate',
        'os_version': 'v5'
    }
    monitoring_metrics.BOT_COUNT.set(1, labels)
    monitoring_metrics.CHROME_TEST_SYNCER_SUCCESS.increment()
    monitor.utils.get_application_id = lambda: 'google.com:clusterfuzz'
    os.environ['BOT_NAME'] = 'bot-1'
    monitor._initialize_monitored_resource()
    monitor._monitored_resource.labels['zone'] = 'us-central1-b'
    monitor._monitoring_daemon.start()

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

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
"""Monitoring."""
# pylint: disable=invalid-name
# TODO(ochang): Remove V3 from names once all metrics are migrated to
# stackdriver.

import bisect
from collections.abc import Iterator
import contextlib
import functools
import itertools
import re
import signal
import threading
import time
from typing import Any
from typing import Callable
from typing import cast
from typing import NamedTuple
from typing import Sequence
from typing import TypeVar

import requests

try:
  from google.cloud import monitoring_v3
  from google.cloud.monitoring_v3 import types as monitoring_v3_types
except (ImportError, RuntimeError):
  monitoring_v3: Any = None
  monitoring_v3_types: Any = None

from google.api import label_pb2
from google.api import metric_pb2
from google.api import monitored_resource_pb2
from google.api_core import exceptions
from google.api_core import retry
from google.protobuf import timestamp_pb2

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.google_cloud_utils import compute_metadata
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

CUSTOM_METRIC_PREFIX: str = 'custom.googleapis.com/'
FLUSH_INTERVAL_SECONDS: int = 10 * 60  # 10 minutes.
PREEMPTION_CHECK_INTERVAL: int = 15  # seconds
RETRY_DEADLINE_SECONDS: int = 5 * 60  # 5 minutes.
INITIAL_DELAY_SECONDS: int = 16
MAXIMUM_DELAY_SECONDS: int = 2 * 60  # 2 minutes.
MAX_TIME_SERIES_PER_CALL: int = 200

# Since `monitoring_v3` is only conditionally imported, pylint complains about
# any accesses to its members. Define type aliases here once and for all, for
# use below.
_TimeInterval: Any
_Point: Any
_TimeSeries: Any
_Timestamp: Any = getattr(timestamp_pb2, 'Timestamp')

if monitoring_v3 is not None and monitoring_v3_types is not None:
  _TimeInterval = monitoring_v3_types.TimeInterval  # pylint: disable=no-member
  _Point = monitoring_v3_types.Point  # pylint: disable=no-member
  _TimeSeries = monitoring_v3_types.TimeSeries  # pylint: disable=no-member
else:
  _TimeInterval = None
  _Point = None
  _TimeSeries = None


@retry.Retry(
    predicate=retry.if_exception_type((
        exceptions.Aborted,
        exceptions.DeadlineExceeded,
        exceptions.ResourceExhausted,
        exceptions.ServerError,
        exceptions.ServiceUnavailable,
    )),
    initial=INITIAL_DELAY_SECONDS,
    maximum=MAXIMUM_DELAY_SECONDS,
    deadline=RETRY_DEADLINE_SECONDS)
def _create_time_series(name: str, time_series: list[Any]) -> None:
  """Wraps `create_time_series()` from the monitoring client.

  Adds retries and logging.
  """
  try:
    _monitoring_v3_client.create_time_series(name=name, time_series=time_series)
  except Exception as e:
    logs.warning(f'Error uploading time series: {e}')
    logs.warning(f'Time series - {name} - contents: {time_series}')


class _MockMetric:
  """Mock metric object, used for when monitoring isn't available."""

  def _mock_method(self, *args: Any, **kwargs: Any) -> None:  # pylint: disable=unused-argument
    pass

  def __getattr__(self, _: str) -> Callable[..., None]:
    return self._mock_method


def _time_series_sort_key(ts: Any) -> Any:
  return ts.points[-1].interval.start_time


def _flush_metrics() -> None:
  """Flushes all metrics stored in _metrics_store"""
  app_id = utils.get_application_id()
  assert app_id is not None
  project_path = _monitoring_v3_client.common_project_path(  # pylint: disable=no-member
      app_id)
  assert _TimeSeries is not None
  try:
    time_series = []
    end_time = time.time()
    for metric, labels, start_time, value in _metrics_store.iter_values():
      if (metric.metric_kind == metric_pb2.MetricDescriptor.MetricKind.GAUGE  # pylint: disable=no-member
         ):
        start_time = end_time
      series = _TimeSeries()
      metric.monitoring_v3_time_series(series, labels, start_time, end_time,
                                       value)
      time_series.append(series)
      if len(time_series) == MAX_TIME_SERIES_PER_CALL:
        time_series.sort(key=_time_series_sort_key)
        _create_time_series(project_path, time_series)
        time_series = []
    if time_series:
      time_series.sort(key=_time_series_sort_key)
      _create_time_series(project_path, time_series)
  except Exception as e:
    if environment.is_android():
      # FIXME: This exception is extremely common on Android. We are already
      # aware of the problem, don't make more noise about it.
      logs.warning(f'Failed to flush metrics: {e}')
    else:
      logs.error(f'Failed to flush metrics: {e}')


_on_sigterm_callbacks: list[Callable[[], Any]] = []


def register_on_sigterm(callback: Callable[[], Any]) -> None:
  """Register a callback to be called on SIGTERM."""
  _on_sigterm_callbacks.append(callback)


def _trigger_shutdown_cleanup() -> None:
  """Runs registered callbacks and stops the monitoring daemon."""
  for callback in _on_sigterm_callbacks:
    try:
      callback()
    except Exception as e:
      logs.error(f'Error in callback: {e}')
  logs.info('Stopping monitoring daemon.')
  stop()


def handle_sigterm(signo: int, stack_frame: Any) -> None:  # pylint: disable=unused-argument
  logs.info('Handling SIGTERM.')
  _trigger_shutdown_cleanup()
  logs.info('SIGTERM handled, metrics flushed.')


@contextlib.contextmanager
def wrap_with_monitoring() -> Iterator[None]:
  """Wraps execution so we flush metrics on exit"""
  try:
    initialize()
    # Signals can only be handled in the main thread/interpreter
    # GAE crons do not satisfy this condition
    if not environment.is_running_on_app_engine():
      signal.signal(signal.SIGTERM, handle_sigterm)
    yield
  finally:
    stop()


class _MonitoringDaemon:
  """Wrapper for the daemon threads responsible for flushing metrics."""

  def __init__(self, flush_function: Callable[[], Any],
               tick_interval: float | int) -> None:
    self._tick_interval: float | int = tick_interval
    self._flush_function: Callable[[], Any] = flush_function
    self._flushing_thread: threading.Thread = threading.Thread(
        name='flushing_thread', target=self._flush_loop, daemon=True)
    self._flushing_thread_stop_event: threading.Event = threading.Event()

  def _flush_loop(self) -> None:
    while True:
      should_stop = self._flushing_thread_stop_event.wait(
          timeout=self._tick_interval)
      self._flush_function()
      if should_stop:
        break

  def start(self) -> None:
    self._flushing_thread.start()

  def stop(self) -> None:
    self._flushing_thread_stop_event.set()
    self._flushing_thread.join()


class _PreemptionPoller:
  """Background thread to poll GCP metadata for preemption."""

  def __init__(self, check_interval: float | int) -> None:
    self._check_interval: float | int = check_interval
    self._poller_thread: threading.Thread = threading.Thread(
        name='preemption_poller', target=self._poll_loop, daemon=True)
    self._poller_thread_stop_event: threading.Event = threading.Event()

  def _poll_loop(self) -> None:
    """Polls GCP metadata for preemption status."""
    if not compute_metadata.is_gce():
      return

    while True:
      should_stop = self._poller_thread_stop_event.wait(
          timeout=self._check_interval)
      if should_stop:
        break

      try:
        status = compute_metadata.get_preempted_status()
        if status and status.strip().upper() == 'TRUE':
          logs.info('Preemption detected via metadata!')
          _trigger_shutdown_cleanup()
          break
      except requests.exceptions.HTTPError as e:
        if cast(requests.Response, e.response).status_code != 404:
          logs.warning(f'HTTP error checking preemption metadata: {e}')
      except Exception as e:
        logs.warning(f'Unknown error checking preemption metadata: {e}')

  def start(self) -> None:
    self._poller_thread.start()

  def stop(self) -> None:
    self._poller_thread_stop_event.set()
    if threading.current_thread() != self._poller_thread:
      self._poller_thread.join()


class _StoreValue(NamedTuple):
  metric: 'Metric'
  labels: dict[str, Any] | None
  start_time: float
  value: Any


class _MetricsStore:
  """In-process metrics store."""

  def __init__(self) -> None:
    self._store: dict[tuple[str, tuple[tuple[str, Any], ...]
                            | None], _StoreValue] = {}
    self._lock: threading.RLock = threading.RLock()

  def _get_key(self, metric_name: str, labels: dict[str, Any] | None
              ) -> tuple[str, tuple[tuple[str, Any], ...] | None]:
    """Get the key used for storing values."""
    if labels:
      normalized_labels = tuple(sorted(labels.items()))
    else:
      normalized_labels = None

    return (metric_name, normalized_labels)

  def iter_values(self) -> Iterator[_StoreValue]:
    with self._lock:
      yield from self._store.values()

  def get(self, metric: 'Metric', labels: dict[str, Any] | None) -> _StoreValue:
    """Get the stored value for the metric."""
    with self._lock:
      key = self._get_key(metric.name, labels)
      return self._store[key]

  def put(self, metric: 'Metric', labels: dict[str, Any] | None,
          value: Any) -> None:
    """Store new value for the metric."""
    with self._lock:
      key = self._get_key(metric.name, labels)
      if key in self._store:
        start_time = self._store[key].start_time
      else:
        start_time = time.time()

      self._store[key] = _StoreValue(metric, labels, start_time, value)

  def increment(self, metric: 'Metric', labels: dict[str, Any] | None,
                delta: Any) -> None:
    """Increment a value by |delta|."""
    with self._lock:
      key = self._get_key(metric.name, labels)

      if key in self._store:
        start_time = self._store[key].start_time
        value = self._store[key].value + delta
      else:
        start_time = time.time()
        value = metric.default_value + delta

      self._store[key] = _StoreValue(metric, labels, start_time, value)

  def reset_for_testing(self) -> None:
    """Reset all data. Used for tests."""
    with self._lock:
      self._store.clear()


class _Field:
  """_Field is the base class used for field specs."""

  def __init__(self, name: str) -> None:
    self.name: str = name

  @property
  def value_type(self) -> int:
    raise NotImplementedError


class StringField(_Field):
  """StringField spec."""

  @property
  def value_type(self) -> int:
    return label_pb2.LabelDescriptor.ValueType.STRING  # pylint: disable=no-member


class BooleanField(_Field):
  """BooleanField spec."""

  @property
  def value_type(self) -> int:
    return label_pb2.LabelDescriptor.ValueType.BOOL  # pylint: disable=no-member


class IntegerField(_Field):
  """IntegerField spec."""

  @property
  def value_type(self) -> int:
    return label_pb2.LabelDescriptor.ValueType.INT64  # pylint: disable=no-member


class Metric:
  """Base metric class."""

  def __init__(self,
               name: str,
               description: str,
               field_spec: Sequence[_Field] | None = None) -> None:
    self.name: str = name
    self.description: str = description
    self.field_spec: Sequence[_Field] = field_spec or []

  @property
  def value_type(self) -> int:
    raise NotImplementedError

  @property
  def metric_kind(self) -> int:
    raise NotImplementedError

  @property
  def default_value(self) -> Any:
    raise NotImplementedError

  def _set_value(self, point: Any, value: Any) -> None:
    raise NotImplementedError

  def get(self, labels: dict[str, Any] | None = None) -> Any:
    """Return the current value for the labels. Used for testing."""
    try:
      return _metrics_store.get(self, labels).value
    except KeyError:
      return self.default_value

  def monitoring_v3_metric(self,
                           metric: Any,
                           labels: dict[str, Any] | None = None) -> Any:
    """Get the monitoring_v3 Metric."""
    metric.type = CUSTOM_METRIC_PREFIX + self.name

    if not labels:
      return metric

    for key, value in labels.items():
      metric.labels[key] = str(value)

    bot_name = environment.get_value('BOT_NAME', None)
    metric.labels['region'] = _get_region(bot_name)

    return metric

  def monitoring_v3_metric_descriptor(self, descriptor: Any) -> Any:
    """Get the monitoring_v3 MetricDescriptor."""
    descriptor.name = self.name
    descriptor.type = CUSTOM_METRIC_PREFIX + self.name
    descriptor.metric_kind = self.metric_kind
    descriptor.value_type = self.value_type
    descriptor.description = self.description

    for field in itertools.chain(DEFAULT_FIELDS, self.field_spec):
      label_descriptor = descriptor.labels.add()
      label_descriptor.key = field.name
      label_descriptor.value_type = field.value_type

    return descriptor

  def monitoring_v3_time_series(
      self, time_series: Any, labels: dict[str, Any] | None, start_time: float,
      end_time: float, value: Any) -> Any:
    """Get the TimeSeries corresponding to the metric."""
    self.monitoring_v3_metric(time_series.metric, labels)
    time_series.resource.CopyFrom(_monitored_resource)
    time_series.metric_kind = self.metric_kind
    time_series.value_type = self.value_type

    assert _TimeInterval is not None and _Point is not None
    interval = _TimeInterval()
    point = _Point(interval=interval)

    _time_to_timestamp(point.interval, 'start_time', start_time)
    _time_to_timestamp(point.interval, 'end_time', end_time)
    self._set_value(point.value, value)
    # Need to do this after setting interval because the values are copied to
    # time_series.
    time_series.points.append(point)

    return time_series


class _CounterMetric(Metric):
  """Counter metric."""

  @property
  def value_type(self) -> int:
    return metric_pb2.MetricDescriptor.ValueType.INT64  # pylint: disable=no-member

  @property
  def metric_kind(self) -> int:
    return metric_pb2.MetricDescriptor.MetricKind.CUMULATIVE  # pylint: disable=no-member

  @property
  def default_value(self) -> int:
    return 0

  def increment(self, labels: dict[str, Any] | None = None) -> None:
    self.increment_by(1, labels=labels)

  def increment_by(self,
                   count: int | float,
                   labels: dict[str, Any] | None = None) -> None:
    _metrics_store.increment(self, labels, count)

  def _set_value(self, point: Any, value: int) -> None:
    """Get Point."""
    point.int64_value = value


class _GaugeMetric(Metric):
  """Gauge metric."""

  @property
  def value_type(self) -> int:
    return metric_pb2.MetricDescriptor.ValueType.INT64  # pylint: disable=no-member

  @property
  def metric_kind(self) -> int:
    return metric_pb2.MetricDescriptor.MetricKind.GAUGE  # pylint: disable=no-member

  @property
  def default_value(self) -> int:
    return 0

  def set(self, value: int, labels: dict[str, Any] | None = None) -> None:
    _metrics_store.put(self, labels, value)

  def _set_value(self, point: Any, value: int) -> None:
    """Get Point."""
    point.int64_value = value


class _Bucketer:
  """Bucketer."""

  def __init__(self) -> None:
    self._lower_bounds: list[float] = []

  def bucket_for_value(self, value: float | int) -> int:
    """Get the bucket index for the given value."""
    return bisect.bisect(self._lower_bounds, value) - 1

  @property
  def num_buckets(self) -> int:
    return len(self._lower_bounds)


class FixedWidthBucketer(_Bucketer):
  """Fixed width bucketer."""

  def __init__(self, width: float | int, num_finite_buckets: int = 100) -> None:
    super().__init__()
    self.width: float | int = width
    self.num_finite_buckets: int = num_finite_buckets

    # [-Inf, 0), [0, width), [width, 2*width], ... , [n*width, Inf)
    self._lower_bounds = [float('-Inf')]
    self._lower_bounds.extend(
        [width * i for i in range(num_finite_buckets + 1)])


class GeometricBucketer(_Bucketer):
  """Geometric bucketer."""

  def __init__(self,
               growth_factor: float = 10**0.2,
               num_finite_buckets: int = 100,
               scale: float = 1.0) -> None:
    super().__init__()
    self.growth_factor: float = growth_factor
    self.num_finite_buckets: int = num_finite_buckets
    self.scale: float = scale

    # [-Inf, scale), [scale, scale*growth),
    # [scale*growth^i, scale*growth^(i+1)), ..., [scale*growth^n, Inf)
    self._lower_bounds = [float('-Inf')]
    self._lower_bounds.extend(
        [scale * growth_factor**i for i in range(num_finite_buckets + 1)])


class _Distribution:
  """Holds a distribution."""

  def __init__(self, bucketer: _Bucketer) -> None:
    self.bucketer: _Bucketer = bucketer
    self.buckets: list[int] = [0 for _ in range(bucketer.num_buckets)]
    self.sum: float | int = 0
    self.count: int = 0

  def add(self, value: float | int) -> '_Distribution':
    self.buckets[self.bucketer.bucket_for_value(value)] += 1
    self.count += 1
    self.sum += value
    return self

  __add__ = add

  def monitoring_v3_distribution(self, distribution: Any) -> None:
    """Set the monitoring_v3 Distribution value."""
    distribution.count = self.count
    if self.count:
      distribution.mean = float(self.sum) / self.count
    else:
      distribution.mean = 0.0

    if isinstance(self.bucketer, FixedWidthBucketer):
      distribution.bucket_options.linear_buckets.offset = 0
      distribution.bucket_options.linear_buckets.width = self.bucketer.width
      distribution.bucket_options.linear_buckets.num_finite_buckets = (
          self.bucketer.num_finite_buckets)
    else:
      assert isinstance(self.bucketer, GeometricBucketer)

      distribution.bucket_options.exponential_buckets.scale = (
          self.bucketer.scale)
      distribution.bucket_options.exponential_buckets.growth_factor = (
          self.bucketer.growth_factor)
      distribution.bucket_options.exponential_buckets.num_finite_buckets = (
          self.bucketer.num_finite_buckets)

    distribution.bucket_counts.extend(self.buckets)


class _CumulativeDistributionMetric(Metric):
  """Cumulative distribution metric."""

  def __init__(self,
               name: str,
               description: str,
               bucketer: _Bucketer | None = None,
               field_spec: Sequence[_Field] | None = None) -> None:
    super().__init__(name, description=description, field_spec=field_spec)
    self.bucketer: _Bucketer | None = bucketer

  @property
  def value_type(self) -> int:
    return metric_pb2.MetricDescriptor.ValueType.DISTRIBUTION  # pylint: disable=no-member

  @property
  def metric_kind(self) -> int:
    return metric_pb2.MetricDescriptor.MetricKind.CUMULATIVE  # pylint: disable=no-member

  @property
  def default_value(self) -> _Distribution:
    assert self.bucketer is not None
    return _Distribution(self.bucketer)

  def add(self, value: float | int,
          labels: dict[str, Any] | None = None) -> None:
    _metrics_store.increment(self, labels, value)

  def _set_value(self, point: Any, value: _Distribution) -> None:
    value.monitoring_v3_distribution(point.distribution_value)


# Global state.
_metrics_store: _MetricsStore = _MetricsStore()
_monitoring_v3_client: Any = None
_monitoring_daemon: _MonitoringDaemon | None = None
_preemption_poller: _PreemptionPoller | None = None
_monitored_resource: Any = None

# Add fields very conservatively here. There is a limit of 10 labels per metric
# descriptor, and metrics should be low in cardinality. That is, only add fields
# which have a small number of possible values.
DEFAULT_FIELDS: list[_Field] = [
    StringField('region'),
]


def check_module_loaded(module: Any) -> bool:
  """Used for mocking."""
  return module is not None


_F = TypeVar('_F', bound=Callable[..., Any])


def stub_unavailable(module: Any) -> Callable[[_F], _F]:
  """Decorator to stub out functions on failed imports."""

  def decorator(func: _F) -> _F:

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
      if check_module_loaded(module):
        return func(*args, **kwargs)

      return _MockMetric()

    return cast(_F, wrapper)

  return decorator


def _initialize_monitored_resource() -> None:
  """Monitored resources."""
  global _monitored_resource
  _monitored_resource = monitored_resource_pb2.MonitoredResource()  # pylint: disable=no-member

  # TODO(ochang): Use generic_node when that is available.
  _monitored_resource.type = 'gce_instance'

  # The project ID must be the same as the one we write metrics to, not the ID
  # where the instance lives.
  _monitored_resource.labels[
      'project_id'] = utils.get_application_id()  # type: ignore

  _monitored_resource.labels['instance_id'] = utils.get_instance_name()

  if compute_metadata.is_gce():
    # Returned in the form projects/{id}/zones/{zone}
    zone = compute_metadata.get('instance/zone').split('/')[-1]
    _monitored_resource.labels['zone'] = zone
  else:
    # Default zone for instances not on GCE.
    _monitored_resource.labels['zone'] = 'us-central1-f'


def _time_to_timestamp(interval: Any, attr: str,
                       time_seconds: float | int) -> None:
  """Convert result of time.time() to Timestamp."""
  seconds = int(time_seconds)
  nanos = int((time_seconds - seconds) * 10**9)
  timestamp = _Timestamp(seconds=seconds, nanos=nanos)
  setattr(interval, attr, timestamp)


def initialize() -> None:
  """Initialize if monitoring is enabled for this bot."""
  global _monitoring_v3_client
  global _monitoring_daemon
  global _preemption_poller

  if environment.get_value('LOCAL_DEVELOPMENT'):
    return

  if not local_config.ProjectConfig().get('monitoring.enabled'):
    return

  if check_module_loaded(monitoring_v3):
    assert monitoring_v3 is not None
    _initialize_monitored_resource()
    _monitoring_v3_client = monitoring_v3.MetricServiceClient(
        credentials=credentials.get_default()[0])
    _monitoring_daemon = _MonitoringDaemon(_flush_metrics,
                                           FLUSH_INTERVAL_SECONDS)
    _monitoring_daemon.start()

    if compute_metadata.is_preemptible():
      _preemption_poller = _PreemptionPoller(PREEMPTION_CHECK_INTERVAL)
      _preemption_poller.start()


def stop() -> None:
  """Stops monitoring and cleans up (only if monitoring is enabled)."""
  if _monitoring_daemon:
    _monitoring_daemon.stop()
  if _preemption_poller:
    _preemption_poller.stop()


def metrics_store() -> _MetricsStore:
  """Get the per-process metrics store."""
  return _metrics_store


def _get_region(bot_name: str | None) -> str:
  """Get bot region."""
  if not bot_name:
    return 'unknown'

  try:
    regions = local_config.MonitoringRegionsConfig()
  except errors.BadConfigError:
    return 'unknown'

  for pattern in regions.get('patterns', []):
    if re.match(pattern['pattern'], bot_name):
      return pattern['name']

  return 'unknown'


@stub_unavailable(monitoring_v3)
def CounterMetric(name: str,
                  description: str,
                  field_spec: Sequence[_Field] | None = None) -> _CounterMetric:
  """Build _CounterMetric."""
  return _CounterMetric(name, field_spec=field_spec, description=description)


@stub_unavailable(monitoring_v3)
def GaugeMetric(name: str,
                description: str,
                field_spec: Sequence[_Field] | None = None) -> _GaugeMetric:
  """Build _CounterMetric."""
  return _GaugeMetric(name, field_spec=field_spec, description=description)


@stub_unavailable(monitoring_v3)
def CumulativeDistributionMetric(name: str,
                                 description: str,
                                 bucketer: _Bucketer | None = None,
                                 field_spec: Sequence[_Field] | None = None
                                ) -> _CumulativeDistributionMetric:
  """Build _CounterMetric."""
  return _CumulativeDistributionMetric(
      name, description=description, bucketer=bucketer, field_spec=field_spec)

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
"""Measures wasted Cloud Monitoring bytes from unchanged _MetricsStore flushes.

ClusterFuzz's _MetricsStore flushes every stored metric every 10 minutes
without clearing entries that received no updates in that window. For
CUMULATIVE metrics (counters and cumulative distributions), an unchanged
re-emission appears in Cloud Monitoring as a consecutive data point with the
same interval.start_time and identical value (int64_value for counters,
distribution_value.count for distributions).

Usage:
  pipenv run python measure_wasted_metrics.py --project <gcp-project-id>
  pipenv run python measure_wasted_metrics.py --project <id> --hours 6
  pipenv run python measure_wasted_metrics.py --project <id> \\
      --metrics task/fuzz/fuzzer/total_time task/fuzz/session/duration
"""

import argparse
import concurrent.futures
import dataclasses
import datetime
import os
import sys
import time

# Mirror butler.py's bootstrap so src/ and src/third_party/ (including google
# namespace packages) are importable before loading ClusterFuzz modules.
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
os.environ['ROOT_DIR'] = _REPO_ROOT
os.environ['PYTHONIOENCODING'] = 'UTF-8'
os.environ['CLOUDSDK_PYTHON'] = sys.executable

sys.path.insert(0, os.path.join(_REPO_ROOT, 'src'))

from local.butler import guard

guard.check()

from clusterfuzz._internal.base import modules

modules.fix_module_search_paths()

from google.api import metric_pb2
from google.api_core import exceptions
from google.api_core import retry
from google.cloud import monitoring_v3

from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics

BYTES_PER_COUNTER_POINT = 8
BYTES_PER_DISTRIBUTION_POINT = 80

BYTES_PER_VALUE_TYPE = {
    metric_pb2.MetricDescriptor.ValueType.INT64: BYTES_PER_COUNTER_POINT,  # pylint: disable=no-member
    metric_pb2.MetricDescriptor.ValueType.DISTRIBUTION:  # pylint: disable=no-member
        BYTES_PER_DISTRIBUTION_POINT,
}

# Fetch enough history before window_start to cover at least one flush interval
# (10m) plus max upload retry deadline (5m) and margin, so the first point in
# the target window for each time series has its predecessor available.
DEFAULT_LOOKBACK_MINUTES = 20

_LIST_RETRY = retry.Retry(
    predicate=retry.if_exception_type((
        exceptions.Aborted,
        exceptions.DeadlineExceeded,
        exceptions.InternalServerError,
        exceptions.ResourceExhausted,
        exceptions.ServiceUnavailable,
    )),
    initial=2.0,
    maximum=60.0,
    multiplier=2.0,
    deadline=300.0,
)


@dataclasses.dataclass
class MetricStats:
  """Measurement results for a single cumulative metric."""
  name: str
  kind_label: str
  bytes_per_point: int
  total_points: int = 0
  wasted_points: int = 0
  active_series: int = 0
  out_of_order_points: int = 0
  not_found: bool = False
  error: str | None = None

  @property
  def total_bytes(self) -> int:
    return self.total_points * self.bytes_per_point

  @property
  def wasted_bytes(self) -> int:
    return self.wasted_points * self.bytes_per_point

  @property
  def waste_pct(self) -> float:
    if not self.total_points:
      return 0.0
    return (self.wasted_points / self.total_points) * 100.0


def _discover_cumulative_metrics(metric_filters=None):
  """Returns sorted cumulative Metric instances from monitoring_metrics.py."""
  if monitor.monitoring_v3 is None:
    raise RuntimeError(
        'google.cloud.monitoring_v3 failed to import; ensure third_party '
        'dependencies are installed.')

  by_name = {}
  attr_to_name = {}
  for attr_name in sorted(dir(monitoring_metrics)):
    obj = getattr(monitoring_metrics, attr_name)
    if not isinstance(obj, monitor.Metric):
      continue
    if (obj.metric_kind !=
        metric_pb2.MetricDescriptor.MetricKind.CUMULATIVE):  # pylint: disable=no-member
      continue
    if obj.value_type not in BYTES_PER_VALUE_TYPE:
      continue
    by_name[obj.name] = obj
    attr_to_name[attr_name] = obj.name

  if not metric_filters:
    return [by_name[name] for name in sorted(by_name)]

  selected = {}
  unknown = []
  for raw_filter in metric_filters:
    normalized = raw_filter.removeprefix(monitor.CUSTOM_METRIC_PREFIX)
    if normalized in by_name:
      selected[normalized] = by_name[normalized]
    elif raw_filter in attr_to_name:
      name = attr_to_name[raw_filter]
      selected[name] = by_name[name]
    else:
      unknown.append(raw_filter)

  if unknown:
    raise ValueError(
        f'Unknown or non-cumulative metric(s): {", ".join(unknown)}')

  return [selected[name] for name in sorted(selected)]


def _parse_utc_timestamp(value: str) -> int:
  """Parses an ISO-8601 UTC timestamp string into integer Unix seconds."""
  dt = datetime.datetime.fromisoformat(value)
  if dt.tzinfo is None:
    dt = dt.replace(tzinfo=datetime.timezone.utc)
  return int(dt.timestamp())


def _ts_to_ns(ts) -> int:
  """Converts a protobuf Timestamp to integer nanoseconds since epoch."""
  return ts.seconds * 1_000_000_000 + ts.nanos


def _extract_value(point_pb, is_distribution: bool) -> int:
  """Returns the cumulative scalar used to detect updates between flushes."""
  if is_distribution:
    # _Distribution.add() always increments count by 1, so count is unchanged
    # iff no new samples were added since the previous flush.
    return point_pb.value.distribution_value.count
  return point_pb.value.int64_value


def _measure_metric(client, project_name: str, metric: monitor.Metric,
                    query_start: int, window_start: int, window_end: int,
                    extra_filter: str | None) -> MetricStats:
  """Queries raw time series for one metric and counts wasted data points."""
  is_distribution = (
      metric.value_type ==
      metric_pb2.MetricDescriptor.ValueType.DISTRIBUTION)  # pylint: disable=no-member
  kind_label = 'dist' if is_distribution else 'counter'
  bytes_per_point = BYTES_PER_VALUE_TYPE[metric.value_type]
  stats = MetricStats(
      name=metric.name, kind_label=kind_label, bytes_per_point=bytes_per_point)

  metric_type = monitor.CUSTOM_METRIC_PREFIX + metric.name
  query_filter = f'metric.type="{metric_type}"'
  if extra_filter:
    query_filter = f'{query_filter} AND ({extra_filter})'

  interval = monitoring_v3.TimeInterval(
      start_time={'seconds': query_start},
      end_time={'seconds': window_end},
  )

  window_start_ns = window_start * 1_000_000_000
  window_end_ns = window_end * 1_000_000_000

  # Maps series_key -> (end_ns, start_ns, value) of the oldest point seen so
  # far for that series. ListTimeSeries returns points newest-to-oldest,
  # including across pages when a single time series spans multiple pages.
  oldest_seen_by_series = {}
  active_series_keys = set()

  try:
    results = client.list_time_series(
        request={
            'name': project_name,
            'filter': query_filter,
            'interval': interval,
            'view': monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        },
        retry=_LIST_RETRY,
    )

    for ts in results:
      ts_pb = monitoring_v3.TimeSeries.pb(ts)
      series_key = (
          tuple(sorted(ts_pb.metric.labels.items())),
          ts_pb.resource.type,
          tuple(sorted(ts_pb.resource.labels.items())),
      )
      newer = oldest_seen_by_series.get(series_key)

      for pt in ts_pb.points:
        end_ns = _ts_to_ns(pt.interval.end_time)
        start_ns = _ts_to_ns(pt.interval.start_time)
        val = _extract_value(pt, is_distribution)

        if newer is not None:
          newer_end_ns, newer_start_ns, newer_val = newer
          if end_ns == newer_end_ns:
            continue
          if end_ns > newer_end_ns:
            stats.out_of_order_points += 1
            continue

          if window_start_ns < newer_end_ns <= window_end_ns:
            if newer_start_ns == start_ns and newer_val == val:
              stats.wasted_points += 1

        if window_start_ns < end_ns <= window_end_ns:
          stats.total_points += 1
          active_series_keys.add(series_key)

        newer = (end_ns, start_ns, val)

      if newer is not None:
        oldest_seen_by_series[series_key] = newer
  except exceptions.NotFound:
    stats.not_found = True
  except Exception as err:
    stats.error = str(err)

  stats.active_series = len(active_series_keys)
  return stats


def _format_bytes(num_bytes: int) -> str:
  """Formats a byte count in human-readable binary units."""
  value = float(num_bytes)
  for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
    if value < 1024.0 or unit == 'TiB':
      if unit == 'B':
        return f'{int(value)} B'
      return f'{value:.2f} {unit}'
    value /= 1024.0
  return f'{num_bytes} B'


def _print_summary(results: list[MetricStats], project: str, window_start: int,
                   window_end: int, lookback_minutes: int):
  """Prints a per-metric and aggregate summary table to stdout."""
  start_str = datetime.datetime.fromtimestamp(
      window_start, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
  end_str = datetime.datetime.fromtimestamp(
      window_end, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
  duration_hours = (window_end - window_start) / 3600.0

  print(f'Project: {project}')
  print(f'Window:  {start_str} -> {end_str} ({duration_hours:.2f}h, '
        f'lookback={lookback_minutes}m)')
  print(f'Pricing: counter={BYTES_PER_COUNTER_POINT}B/pt, '
        f'distribution={BYTES_PER_DISTRIBUTION_POINT}B/pt')
  print()

  sorted_results = sorted(
      results, key=lambda r: (r.wasted_bytes, r.total_bytes, r.name),
      reverse=True)
  name_width = max(len('Metric'), max((len(r.name) for r in results),
                                      default=0))

  header = (f'{"Metric":<{name_width}}  {"Type":<7}  {"Total Pts":>12}  '
            f'{"Wasted Pts":>12}  {"Waste %":>7}  '
            f'{"Total Bytes":>14}  {"Wasted Bytes":>14}')
  print(header)
  print('-' * len(header))

  for stat in sorted_results:
    if stat.error:
      print(f'{stat.name:<{name_width}}  {stat.kind_label:<7}  '
            f'ERROR: {stat.error}')
      continue
    if stat.not_found:
      print(f'{stat.name:<{name_width}}  {stat.kind_label:<7}  (not found)')
      continue
    print(f'{stat.name:<{name_width}}  {stat.kind_label:<7}  '
          f'{stat.total_points:>12,}  {stat.wasted_points:>12,}  '
          f'{stat.waste_pct:>6.2f}%  {stat.total_bytes:>14,}  '
          f'{stat.wasted_bytes:>14,}')

  print('-' * len(header))

  valid = [r for r in results if not r.error]
  total_points = sum(r.total_points for r in valid)
  wasted_points = sum(r.wasted_points for r in valid)
  total_bytes = sum(r.total_bytes for r in valid)
  wasted_bytes = sum(r.wasted_bytes for r in valid)
  waste_pct = (wasted_points / total_points * 100.0) if total_points else 0.0

  print(f'{"TOTAL":<{name_width}}  {"all":<7}  '
        f'{total_points:>12,}  {wasted_points:>12,}  '
        f'{waste_pct:>6.2f}%  {total_bytes:>14,}  '
        f'{wasted_bytes:>14,}')
  print()

  for kind_label in ('counter', 'dist'):
    subset = [r for r in valid if r.kind_label == kind_label]
    sub_total_pts = sum(r.total_points for r in subset)
    sub_wasted_pts = sum(r.wasted_points for r in subset)
    sub_total_bytes = sum(r.total_bytes for r in subset)
    sub_wasted_bytes = sum(r.wasted_bytes for r in subset)
    sub_pct = (
        sub_wasted_pts / sub_total_pts * 100.0) if sub_total_pts else 0.0
    label = 'Counters' if kind_label == 'counter' else 'Distributions'
    print(f'{label:<14}: {sub_wasted_pts:,} / {sub_total_pts:,} pts wasted '
          f'({sub_pct:.2f}%), {_format_bytes(sub_wasted_bytes)} / '
          f'{_format_bytes(sub_total_bytes)} '
          f'({sub_wasted_bytes:,} B wasted)')

  bytes_waste_pct = (wasted_bytes / total_bytes * 100.0) if total_bytes else 0.0
  print(f'{"Overall":<14}: {wasted_points:,} / {total_points:,} pts wasted '
        f'({waste_pct:.2f}%), {_format_bytes(wasted_bytes)} / '
        f'{_format_bytes(total_bytes)} ({bytes_waste_pct:.2f}% of bytes, '
        f'{wasted_bytes:,} B wasted)')

  out_of_order = [r for r in valid if r.out_of_order_points]
  if out_of_order:
    print()
    print('WARNING: Out-of-order points skipped for:')
    for stat in out_of_order:
      print(f'  {stat.name}: {stat.out_of_order_points}')


def _parse_args():
  """Parses command-line arguments."""
  parser = argparse.ArgumentParser(
      description=(
          'Measure wasted Cloud Monitoring data points and bytes emitted by '
          'unchanged cumulative metrics in ClusterFuzz _MetricsStore.'))
  parser.add_argument(
      '--project',
      required=True,
      help='GCP project ID to query Cloud Monitoring time series from.')
  parser.add_argument(
      '--hours',
      type=float,
      default=24.0,
      help='Hours before --end-time to measure (ignored if --start-time is '
      'set). Default: 24.')
  parser.add_argument(
      '--start-time',
      help='Optional ISO-8601 UTC start time (e.g. 2026-11-17T00:00:00Z).')
  parser.add_argument(
      '--end-time',
      help='Optional ISO-8601 UTC end time (default: now).')
  parser.add_argument(
      '--lookback-minutes',
      type=int,
      default=DEFAULT_LOOKBACK_MINUTES,
      help='Minutes before start-time fetched for predecessor context. '
      f'Default: {DEFAULT_LOOKBACK_MINUTES}.')
  parser.add_argument(
      '--metrics',
      nargs='+',
      help='Optional subset of metrics to measure (metric name, full '
      'custom.googleapis.com/... type, or monitoring_metrics constant name).')
  parser.add_argument(
      '--extra-filter',
      help='Optional additional Cloud Monitoring filter expression ANDed with '
      'the metric.type filter.')
  parser.add_argument(
      '--workers',
      type=int,
      default=4,
      help='Number of concurrent worker threads across metrics. Default: 4.')
  return parser.parse_args()


def main():
  args = _parse_args()

  window_end = (
      _parse_utc_timestamp(args.end_time) if args.end_time else int(time.time())
  )
  if args.start_time:
    window_start = _parse_utc_timestamp(args.start_time)
  else:
    if args.hours <= 0:
      raise ValueError('--hours must be positive.')
    window_start = window_end - int(args.hours * 3600)

  if window_start >= window_end:
    raise ValueError('start-time must be strictly earlier than end-time.')
  if args.lookback_minutes < 0:
    raise ValueError('--lookback-minutes must be non-negative.')

  query_start = window_start - args.lookback_minutes * 60
  metrics = _discover_cumulative_metrics(args.metrics)
  if not metrics:
    print('No cumulative metrics found to measure.')
    return 0

  client = monitoring_v3.MetricServiceClient()
  project_name = client.common_project_path(args.project)

  results = []
  total_metrics = len(metrics)
  workers = max(1, min(args.workers, total_metrics))

  with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
    future_to_metric = {
        executor.submit(_measure_metric, client, project_name, metric,
                        query_start, window_start, window_end,
                        args.extra_filter): metric
        for metric in metrics
    }
    completed = 0
    for future in concurrent.futures.as_completed(future_to_metric):
      stat = future.result()
      results.append(stat)
      completed += 1
      sys.stderr.write(
          f'[{completed}/{total_metrics}] {stat.name}: '
          f'{stat.wasted_points:,}/{stat.total_points:,} pts wasted\n')
      sys.stderr.flush()

  _print_summary(results, args.project, window_start, window_end,
                 args.lookback_minutes)
  return 0


if __name__ == '__main__':
  sys.exit(main())

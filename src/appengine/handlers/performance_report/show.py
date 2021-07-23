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
"""Fuzzer performance report handler."""

import datetime
import json
import logging
import os
import urllib.parse

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import fuzzer_logs
from clusterfuzz._internal.metrics import fuzzer_stats
from handlers import base_handler
from handlers.performance_report import constants
from handlers.performance_report import performance_analyzer
from libs import access
from libs import handler
from libs import helpers


def _build_rows_and_columns(performance_report):
  """Build table's rows and columns for display."""
  # Build the columns.
  cols = []
  for column in constants.DISPLAY_COLUMNS:
    label = (
        column['title'] +
        '<paper-tooltip>%s</paper-tooltip>' % column['tooltip'])
    cols.append({'label': label, 'type': 'string'})

  # Build the rows.
  rows = []
  for issue in performance_report['issues']:
    rows_data = []
    for column in constants.DISPLAY_COLUMNS:
      rows_data.append({'v': issue[column['name']]})
    rows.append({'c': rows_data})

  table_data = {'cols': cols, 'rows': rows}
  return table_data


def _get_link_html(directory_path, relative_path):
  """Return html link for viewing a particular file on GCS."""
  filename = os.path.basename(relative_path)
  timestamp, extension = os.path.splitext(filename)
  if extension != fuzzer_logs.LOG_EXTENSION:
    return 'Invalid!'

  try:
    # Make sure that timestamp is valid.
    datetime.datetime.strptime(timestamp, fuzzer_logs.TIME_FORMAT)
  except Exception:
    # Invalid timestamp, can't create link. Bail out.
    return 'Invalid!'

  link_path = '%s/%s' % (directory_path, relative_path)
  link_name = filename
  link_url = '/gcs-redirect?%s' % urllib.parse.urlencode({'path': link_path})
  # TODO(mmoroz): build links and other markup things in polymer.
  return '<a href="{link_url}">{link_name}</a>'.format(
      link_url=link_url, link_name=link_name)


def _get_performance_features(fuzzer_name, job_type, datetime_start,
                              datetime_end):
  """Get raw performance features stored in BigQuery."""
  query_fields = [
      fuzzer_stats.QueryField(fuzzer_stats.TestcaseQuery.ALIAS, column, None)
      for column in constants.QUERY_COLUMNS
  ]

  # TODO(mmoroz): the query should be possible for datetime as well object.
  query = fuzzer_stats.TestcaseQuery(
      fuzzer_name=fuzzer_name,
      job_types=[job_type],
      query_fields=query_fields,
      group_by=fuzzer_stats.QueryGroupBy.GROUP_BY_NONE,
      date_start=datetime_start.date(),
      date_end=datetime_end.date())

  client = big_query.Client()

  try:
    result = client.query(query=query.build())
  except Exception as e:
    logging.error('Exception during BigQuery request: %s\n', str(e))
    raise helpers.EarlyExitException('Internal error.', 500)

  if not result.rows:
    raise helpers.EarlyExitException('No stats.', 404)

  return result


def _get_performance_report(fuzzer_name, job_type, performance_report_data):
  """Return performance report."""
  bucket_name = data_handler.get_value_from_job_definition_or_environment(
      job_type, 'FUZZ_LOGS_BUCKET')

  # Load performance data as JSON.
  performance_report = json.loads(performance_report_data)

  # Get logs directory path containing the analyzed logs.
  logs_directory = fuzzer_logs.get_logs_directory(bucket_name, fuzzer_name,
                                                  job_type)

  # Add other display metadata in report.
  for issue in performance_report['issues']:
    # Linkify the examples column.
    # TODO(mmoroz): build this in polymer using dom-repeat.
    issue['examples'] = '<br/>'.join([
        _get_link_html(logs_directory, log_relative_path)
        for log_relative_path in issue['examples']
    ])

    # Add the solutions column explicitly.
    issue['solutions'] = constants.ISSUE_TYPE_SOLUTIONS_MAP[issue['type']]

  return performance_report


def _get_performance_report_data(fuzzer_name, job_type, logs_date):
  """Return performance report data."""
  # Current version works on daily basis the same way as the old version.
  if logs_date == 'latest':
    # Use yesterday's date by UTC to analyze yesterday's fuzzer runs.
    date_start = datetime.datetime.utcnow().date() - datetime.timedelta(days=1)
  else:
    try:
      date_start = datetime.datetime.strptime(logs_date, '%Y-%m-%d').date()
    except ValueError:
      logging.warning('Wrong date format passed to performance report: %s\n',
                      logs_date)
      raise helpers.EarlyExitException('Wrong date format.', 400)

  datetime_start = datetime.datetime.combine(date_start, datetime.time.min)
  datetime_end = datetime_start + datetime.timedelta(days=1)

  features = _get_performance_features(fuzzer_name, job_type, datetime_start,
                                       datetime_end)

  return features, date_start


class Handler(base_handler.Handler):
  """Performance report handler."""

  @handler.get(handler.HTML)
  def get(self, fuzzer_name=None, job_type=None, logs_date=None):
    """Handle a GET request."""
    if not fuzzer_name:
      raise helpers.EarlyExitException('Fuzzer name cannot be empty.', 400)

    if not job_type:
      raise helpers.EarlyExitException('Job type cannot be empty.', 400)

    if not logs_date:
      raise helpers.EarlyExitException('Logs Date cannot be empty.', 400)

    if not access.has_access(fuzzer_name=fuzzer_name, job_type=job_type):
      raise helpers.AccessDeniedException()

    performance_features, date = _get_performance_report_data(
        fuzzer_name, job_type, logs_date)

    performance_data = performance_features.rows

    analyzer = performance_analyzer.LibFuzzerPerformanceAnalyzer()

    # It is possible to break the analysis by requesting outdated stats.
    try:
      total_time = sum(row['actual_duration'] for row in performance_data)
      performance_scores, affected_runs_percents, examples = (
          analyzer.analyze_stats(performance_data))
    except (KeyError, TypeError, ValueError) as e:
      logging.error('Exception during performance analysis: %s\n', str(e))
      raise helpers.EarlyExitException(
          'Cannot analyze performance for the requested time period.', 404)

    # Build performance analysis result.
    performance_issues = analyzer.get_issues(performance_scores,
                                             affected_runs_percents, examples)

    performance_report = performance_analyzer.generate_report(
        performance_issues, fuzzer_name, job_type)

    report = _get_performance_report(fuzzer_name, job_type, performance_report)

    result = {
        'info': {
            'date': str(date),
            'fuzzer_name': report['fuzzer_name'],
            'fuzzer_runs': performance_features.total_count,
            'job_type': report['job_type'],
            'table_data': _build_rows_and_columns(report),
            'total_time': str(datetime.timedelta(seconds=total_time)),
        }
    }
    return self.render('performance-report.html', result)

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
"""Fuzzer statistics handler."""

import datetime
import html
import re
import urllib.parse

from flask import request
from googleapiclient.errors import HttpError
import six
import yaml

from clusterfuzz._internal.base import external_users
from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import access
from libs import handler
from libs import helpers

# Old fuzzer stats don't change, we could cache forever and it would never go
# stale. Since stats can get pretty large and probably aren't used much the day
# after first accessed, use a TTL reflecting this.
MEMCACHE_OLD_TTL_IN_SECONDS = 24 * 60 * 60

# New fuzzer stats change, and aren't as likely to be reaccessed, don't cache
# for very long.
MEMCACHE_TODAY_TTL_IN_SECONDS = 30 * 60


class QueryField(object):
  """Wrapped fuzzer_stats.QueryField with extra metadata."""

  def __init__(self, field, results_index, field_type, bigquery_type):
    self.field = field
    self.results_index = results_index
    self.field_type = field_type
    self.bigquery_type = bigquery_type.lower()


class BuiltinField(object):
  """Wrapped fuzzer_stats.BuiltinField with extra metadata."""

  def __init__(self, spec, field):
    self.spec = spec
    self.field = field


def _bigquery_type_to_charts_type(typename):
  """Convert bigquery type to charts type."""
  typename = typename.lower()
  if typename in ('integer', 'float'):
    return 'number'

  if typename == 'timestamp':
    return 'date'

  return 'string'


def _python_type_to_charts_type(type_value):
  """Convert bigquery type to charts type."""
  if type_value in (int, float):
    return 'number'

  if type_value == datetime.date:
    return 'date'

  return 'string'


def _parse_date(date_str):
  """Parse YYYY-MM-DD."""
  if not date_str:
    return None

  pattern = re.compile(r'^(\d{4})-(\d{2})-(\d{2})$')
  match = pattern.match(date_str)
  if not match:
    return None

  year, month, day = (int(val) for val in match.groups())
  return datetime.date(year, month, day)


def _parse_stats_column_fields(results, stats_columns, group_by, fuzzer, jobs):
  """Parse stats columns."""
  result = []
  columns = fuzzer_stats.parse_stats_column_fields(stats_columns)

  # Insert first column (group by)
  group_by_field_name = fuzzer_stats.group_by_to_field_name(group_by)
  columns.insert(0, fuzzer_stats.QueryField('j', group_by_field_name, None))

  contexts = {}

  for column in columns:
    if isinstance(column, fuzzer_stats.QueryField):
      key = '%s_%s' % (column.table_alias, column.select_alias)

      for i, field_info in enumerate(results['schema']['fields']):
        # the 'name' field could either be "prefix_fieldname" or simply
        # "fieldname"
        if (field_info['name'] == column.select_alias or
            field_info['name'] == key):
          result.append(
              QueryField(column, i,
                         _bigquery_type_to_charts_type(field_info['type']),
                         field_info['type']))
          break
    elif isinstance(column, fuzzer_stats.BuiltinFieldSpecifier):
      # Builtin field.
      # Create new context if it does not exist.
      field_class = column.field_class()
      if not field_class:
        continue

      context_class = field_class.CONTEXT_CLASS
      context = contexts.setdefault(context_class, context_class(fuzzer, jobs))
      result.append(BuiltinField(column, column.create(context)))

  return result


def _parse_group_by(group_by):
  """Parse group_by value."""
  if group_by == 'by-day':
    return fuzzer_stats.QueryGroupBy.GROUP_BY_DAY
  if group_by == 'by-time':
    return fuzzer_stats.QueryGroupBy.GROUP_BY_TIME
  if group_by == 'by-revision':
    return fuzzer_stats.QueryGroupBy.GROUP_BY_REVISION
  if group_by == 'by-job':
    return fuzzer_stats.QueryGroupBy.GROUP_BY_JOB
  if group_by == 'by-fuzzer':
    return fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER

  return None


def _get_fuzzer_or_engine(name):
  """Return fuzzer entity, or engine this target is part of."""
  fuzz_target = data_handler.get_fuzz_target(name)
  if fuzz_target:
    name = fuzz_target.engine

  return data_types.Fuzzer.query(data_types.Fuzzer.name == name).get()


def _do_bigquery_query(query):
  """Return results from BigQuery."""
  logs.log(query)
  client = big_query.Client()

  try:
    results = client.raw_query(query, max_results=10000)
  except HttpError as e:
    raise helpers.EarlyExitException(str(e), 500)

  if 'rows' not in results:
    raise helpers.EarlyExitException('No stats.', 404)

  return results


def _parse_stats_column_descriptions(stats_column_descriptions):
  """Parse stats column descriptions."""
  if not stats_column_descriptions:
    return {}

  try:
    result = yaml.safe_load(stats_column_descriptions)
    for key, value in six.iteritems(result):
      result[key] = html.escape(value)

    return result
  except yaml.parser.ParserError:
    logs.log_error('Failed to parse stats column descriptions.')
    return {}


def _build_columns(result, columns):
  """Build columns."""
  for column in columns:
    if isinstance(column, QueryField):
      result['cols'].append({
          'label': column.field.select_alias,
          'type': column.field_type,
      })
    elif isinstance(column, BuiltinField):
      result['cols'].append({
          'label': column.spec.alias or column.spec.name,
          'type': _python_type_to_charts_type(column.field.VALUE_TYPE),
      })


def _try_cast(cell, value_str, cast_function, default_value):
  """Try casting the value_str into cast_function."""
  try:
    cell['v'] = cast_function(value_str)
  except (ValueError, TypeError):
    cell['v'] = default_value
    cell['f'] = '--'


# FIXME: Break logic in this function into simpler helper functions.
def _build_rows(result, columns, rows, group_by):
  """Build rows."""
  for row in rows:
    row_data = []
    first_column_value = None
    for column in columns:
      cell = {}
      if isinstance(column, QueryField):
        value = row['f'][column.results_index]['v']

        if column.field.select_alias == 'time':
          timestamp = float(value)
          time = datetime.datetime.utcfromtimestamp(timestamp)
          first_column_value = first_column_value or time
          cell['v'] = 'Date(%d, %d, %d, %d, %d, %d)' % (
              time.year, time.month - 1, time.day, time.hour, time.minute,
              time.second)
        elif column.field.select_alias == 'date':
          timestamp = float(value)
          date = datetime.datetime.utcfromtimestamp(timestamp).date()
          first_column_value = first_column_value or date
          cell['v'] = 'Date(%d, %d, %d)' % (date.year, date.month - 1, date.day)
        elif column.bigquery_type == 'integer':
          _try_cast(cell, value, int, 0)
        elif column.bigquery_type == 'float':
          # Round all float values to single digits.
          _try_cast(cell, value, lambda s: round(float(s), 1), 0.0)
        else:
          cell['v'] = value

        first_column_value = first_column_value or cell['v']
      elif isinstance(column, BuiltinField):
        data = column.field.get(group_by, first_column_value)
        if data:
          formatted_value = data.value
          if data.link:
            link = (
                _get_cloud_storage_link(data.link)
                if data.link.startswith('gs://') else data.link)
            formatted_value = '<a href="%s">%s</a>' % (link, data.value)

          if data.sort_key is not None:
            cell['v'] = data.sort_key
          else:
            cell['v'] = data.value

          if data.sort_key is not None or data.link:
            cell['f'] = formatted_value
        else:
          cell['v'] = ''
          cell['f'] = '--'

      row_data.append(cell)

    result['rows'].append({'c': row_data})


def _get_cloud_storage_link(bucket_path):
  """Return a clickable link to a cloud storage file given the bucket path."""
  return '/gcs-redirect?' + urllib.parse.urlencode({'path': bucket_path})


def _get_filter_from_job(job):
  """Creates a job filter from |job|."""
  return [str(job)] if job else None


def build_results(fuzzer, jobs, group_by, date_start, date_end):
  """Wrapper around the caching wrappers for _build_results. Decides which of
  those wrappers to call based on how long query should be cached for."""
  datetime_end = _parse_date(date_end)
  if not datetime_end:
    raise helpers.EarlyExitException('Missing end date.', 400)

  if datetime_end < utils.utcnow().date():
    logs.log('Building results for older stats %s %s %s %s %s.' %
             (fuzzer, jobs, group_by, date_start, date_end))

    return _build_old_results(fuzzer, jobs, group_by, date_start, date_end)

  logs.log('Building results for stats including today %s %s %s %s %s.' %
           (fuzzer, jobs, group_by, date_start, date_end))

  return _build_todays_results(fuzzer, jobs, group_by, date_start, date_end)


@memoize.wrap(memoize.Memcache(MEMCACHE_TODAY_TTL_IN_SECONDS))
def _build_todays_results(fuzzer, jobs, group_by, date_start, date_end):
  """Wrapper around _build_results that is intended for use by queries where
  date_end is today. Caches results for 15 minutes."""
  return _build_results(fuzzer, jobs, group_by, date_start, date_end)


@memoize.wrap(memoize.Memcache(MEMCACHE_OLD_TTL_IN_SECONDS))
def _build_old_results(fuzzer, jobs, group_by, date_start, date_end):
  """Wrapper around _build_results that is intended for use by queries where
  date_end is before today. Caches results for 24 hours."""
  return _build_results(fuzzer, jobs, group_by, date_start, date_end)


def _build_results(fuzzer, jobs, group_by, date_start, date_end):
  """Build results."""
  date_start = _parse_date(date_start)
  date_end = _parse_date(date_end)

  if not fuzzer or not group_by or not date_start or not date_end:
    raise helpers.EarlyExitException('Missing params.', 400)

  fuzzer_entity = _get_fuzzer_or_engine(fuzzer)
  if not fuzzer_entity:
    raise helpers.EarlyExitException('Fuzzer not found.', 404)

  if fuzzer_entity.stats_columns:
    stats_columns = fuzzer_entity.stats_columns
  else:
    stats_columns = fuzzer_stats.JobQuery.DEFAULT_FIELDS

  group_by = _parse_group_by(group_by)
  if group_by is None:
    raise helpers.EarlyExitException('Invalid grouping.', 400)

  table_query = fuzzer_stats.TableQuery(fuzzer, jobs, stats_columns, group_by,
                                        date_start, date_end)
  results = _do_bigquery_query(table_query.build())

  is_timeseries = group_by == fuzzer_stats.QueryGroupBy.GROUP_BY_TIME
  result = {
      'cols': [],
      'rows': [],
      'column_descriptions':
          _parse_stats_column_descriptions(
              fuzzer_entity.stats_column_descriptions),
      'is_timeseries':
          is_timeseries
  }

  columns = _parse_stats_column_fields(results, stats_columns, group_by, fuzzer,
                                       jobs)

  # If we are grouping by time and plotting graphs, skip builtin columns.
  if is_timeseries:
    columns = [c for c in columns if not isinstance(c, BuiltinField)]

  _build_columns(result, columns)
  _build_rows(result, columns, results['rows'], group_by)
  return result


def _get_date(date_value, days_ago):
  """Returns |date_value| if it is not empty otherwise returns the date
    |days_ago| number of days ago."""
  if date_value:
    return date_value

  date_datetime = utils.utcnow() - datetime.timedelta(days=days_ago)
  return date_datetime.strftime('%Y-%m-%d')


class Handler(base_handler.Handler):
  """Fuzzer stats main page handler."""

  # pylint: disable=unused-argument
  @handler.unsupported_on_local_server
  @handler.get(handler.HTML)
  def get(self, extra=None):
    """Handle a GET request."""
    if not access.has_access():
      # User is an external user of ClusterFuzz (eg: non-Chrome dev who
      # submitted a fuzzer or someone with a project in OSS-Fuzz).
      user_email = helpers.get_user_email()
      fuzzers_list = external_users.allowed_fuzzers_for_user(
          user_email, include_from_jobs=True, include_parents=True)
      if not fuzzers_list:
        # User doesn't actually have access to any fuzzers.
        raise helpers.AccessDeniedException(
            "You don't have access to any fuzzers.")

    return self.render('fuzzer-stats.html', {})


class LoadFiltersHandler(base_handler.Handler):
  """Load filters handler."""

  @handler.unsupported_on_local_server
  @handler.get(handler.HTML)
  def get(self):
    """Handle a GET request."""
    project = request.get('project')

    if access.has_access():
      # User is an internal user of ClusterFuzz (eg: ClusterFuzz developer).

      # Show all projects in the list, since this allows user to pick another
      # project as needed.
      projects_list = data_handler.get_all_project_names()

      # Filter fuzzers and job list if a project is provided.
      fuzzers_list = (
          data_handler.get_all_fuzzer_names_including_children(
              include_parents=True, project=project))
      jobs_list = data_handler.get_all_job_type_names(project=project)
    else:
      # User is an external user of ClusterFuzz (eg: non-Chrome dev who
      # submitted a fuzzer or someone with a project in OSS-Fuzz).
      user_email = helpers.get_user_email()

      # TODO(aarya): Filter fuzzer and job if |project| is provided.
      fuzzers_list = sorted(
          external_users.allowed_fuzzers_for_user(
              user_email, include_from_jobs=True, include_parents=True))
      if not fuzzers_list:
        # User doesn't actually have access to any fuzzers.
        raise helpers.AccessDeniedException(
            "You don't have access to any fuzzers.")

      jobs_list = sorted(external_users.allowed_jobs_for_user(user_email))
      projects_list = sorted(
          {data_handler.get_project_name(job) for job in jobs_list})

    result = {
        'projects': projects_list,
        'fuzzers': fuzzers_list,
        'jobs': jobs_list,
    }
    return self.render_json(result)


class LoadHandler(base_handler.Handler):
  """Load handler."""

  def _check_user_access_and_get_job_filter(self, fuzzer, job):
    """Check whether the current user has access to stats for the fuzzer or job.
    Returns a job filter that should be applied to the query."""
    access_by_fuzzer_or_job = access.has_access(
        fuzzer_name=fuzzer, job_type=job)
    if access_by_fuzzer_or_job:
      # User has full access to the fuzzer, or the specified job.
      # None means no filters => all jobs.
      return _get_filter_from_job(job)

    if not job:
      # Job not specified and user doesn't have full access to the fuzzer. Check
      # if the user has any allowed jobs and use that as a filter.
      allowed_jobs = external_users.allowed_jobs_for_user(
          helpers.get_user_email())
      if allowed_jobs:
        return allowed_jobs

    raise helpers.AccessDeniedException()

  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    """Handle a POST request."""
    fuzzer = request.get('fuzzer')
    job = request.get('job')
    group_by = request.get('group_by')

    # If date_start is "": because the front end defaults to using a
    # start_date 7 days ago, do the same.
    date_start = _get_date(request.get('date_start'), 7)
    # If date_end is "": don't get today's stats as they may not be
    # available, use yesterdays (as the front end does by default).
    date_end = _get_date(request.get('date_end'), 1)

    job_filter = self._check_user_access_and_get_job_filter(fuzzer, job)
    return self.render_json(
        build_results(fuzzer, job_filter, group_by, date_start, date_end))


class PreloadHandler(base_handler.Handler):
  """Handler for the infrequent task of loading results for expensive stats
  queries that are commonly accessed into the cache."""

  def _get_fuzzer_job_filters(self):
    """Return list of fuzzer-job filter tuples."""
    fuzzer_job_filters = []
    for fuzzer_name in data_types.BUILTIN_FUZZERS:
      fuzzer = data_types.Fuzzer.query(
          data_types.Fuzzer.name == fuzzer_name).get()

      for job in fuzzer.jobs:
        fuzzer_job_filters.append((fuzzer_name, _get_filter_from_job(job)))

      # None job is explicitly added for fuzzer query across all jobs.
      fuzzer_job_filters.append((fuzzer_name, _get_filter_from_job(None)))

    return fuzzer_job_filters

  @handler.cron()
  def get(self):
    """Handle a GET request."""
    date_start = _get_date(None, 7)
    date_end = _get_date(None, 1)

    for fuzzer, job_filter in self._get_fuzzer_job_filters():
      group_by = 'by-fuzzer'
      try:
        build_results(fuzzer, job_filter, group_by, date_start, date_end)
      except Exception as e:
        if 'No stats.' not in repr(e):
          logs.log_error('Failed to preload %s %s %s %s %s.' %
                         (fuzzer, job_filter, group_by, date_start, date_end))

      if not job_filter:
        # Group by job only makes sense for queries that do not specify job.
        group_by = 'by-job'
        try:
          build_results(fuzzer, job_filter, group_by, date_start, date_end)
        except Exception as e:
          if 'No stats.' not in repr(e):
            logs.log_error('Failed to preload %s %s %s %s %s.' %
                           (fuzzer, job_filter, group_by, date_start, date_end))


class RefreshCacheHandler(base_handler.Handler):
  """Refresh cache."""

  @handler.cron()
  def get(self):
    """Handle a GET request."""
    fuzzer_logs_context = fuzzer_stats.FuzzerRunLogsContext()
    fuzz_targets = data_handler.get_fuzz_targets()

    # Cache child fuzzer -> logs bucket mappings.
    for fuzz_target in fuzz_targets:
      # pylint: disable=protected-access,unexpected-keyword-arg
      fuzzer_logs_context._get_logs_bucket_from_fuzzer(
          fuzz_target.fully_qualified_name(), __memoize_force__=True)

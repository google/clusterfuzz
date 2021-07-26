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
"""Handler for the crash stats page."""

import json

from flask import request

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import crash_stats as crash_stats_common
from handlers import base_handler
from libs import crash_access
from libs import crash_stats
from libs import filters
from libs import handler
from libs import helpers

PAGE_SIZE = 10
DEFAULT_DAYS_FOR_BY_HOURS = 3
DEFAULT_DAYS_FOR_BY_DAYS = 7


class FuzzerFilter(filters.Filter):
  """Filter for fuzzer."""

  def add(self, query, params):
    """Set query according to fuzzer param."""
    value = params.get('fuzzer', '')
    if filters.is_empty(value):
      return

    if data_handler.is_fuzzing_engine(value):
      query.filter('parent_fuzzer_name', value)
    else:
      query.filter('fuzzer_name', value)


class PlatformFilter(filters.Filter):
  """Filter for platform."""

  def add(self, query, params):
    """Set query according to platform param."""
    value = params.get('platform', '')
    if filters.is_empty(value):
      return

    if value == 'android':
      query.filter('parent_platform', value)
    else:
      query.filter('platform', value)


class TimeFilter(filters.Filter):
  """Filter for start and end hour."""

  def add(self, query, params):
    """Set query according to end and hours params."""
    if 'end' in params:
      end = helpers.cast(params['end'], int, "'end' must be an integer")
    else:
      end = crash_stats_common.get_max_hour()

    block = params.get('block', 'day')

    if 'days' in params:
      days = helpers.cast(params['days'], int, "'days' must be an integer")
    else:
      days = (
          DEFAULT_DAYS_FOR_BY_HOURS
          if block == 'hour' else DEFAULT_DAYS_FOR_BY_DAYS)

    params['end'] = str(end)
    params['days'] = str(days)
    params['block'] = str(block)

    query.set_time_params(end, days, block)


class KeywordFilter(filters.Filter):
  """Filter for keyword."""

  def add(self, query, params):
    """Set query according to search param."""
    value = params.get('q', '')
    if filters.is_empty(value):
      return

    for keyword in value.split(' '):
      query.raw_filter(
          '(LOWER(crash_state) LIKE %s OR LOWER(crash_type) LIKE %s)' %
          (json.dumps('%%%s%%' % keyword.lower()),
           json.dumps('%%%s%%' % keyword.lower())))


GROUP_FILTERS = [
    filters.Boolean('is_new', 'new'),
]

FILTERS = [
    TimeFilter(),
    filters.Boolean('security_flag', 'security'),
    filters.Boolean('reproducible_flag', 'reproducible'),
    filters.String('job_type', 'job'),
    filters.String('project', 'project'),
    FuzzerFilter(),
    PlatformFilter(),
    KeywordFilter(),
]


def query_testcase(project_name, crash_type, crash_state, security_flag,
                   is_open):
  """Start a query for an associated testcase."""
  return data_types.Testcase.query(
      data_types.Testcase.project_name == project_name,
      data_types.Testcase.crash_type == crash_type,
      data_types.Testcase.crash_state == crash_state,
      data_types.Testcase.security_flag == security_flag,
      data_types.Testcase.open == is_open,
      ndb_utils.is_false(data_types.Testcase.is_a_duplicate_flag)).order(
          -data_types.Testcase.timestamp).iter(
              limit=1, projection=[
                  'bug_information',
                  'group_bug_information',
              ])


def attach_testcases(rows):
  """Attach testcase to each crash."""
  testcases = {}
  for index, row in enumerate(rows):
    testcases[index] = {
        'open_testcase':
            query_testcase(
                project_name=row['projectName'],
                crash_type=row['crashType'],
                crash_state=row['crashState'],
                security_flag=row['isSecurity'],
                is_open=True),
        'closed_testcase':
            query_testcase(
                project_name=row['projectName'],
                crash_type=row['crashType'],
                crash_state=row['crashState'],
                security_flag=row['isSecurity'],
                is_open=False)
    }

  for index, row in enumerate(rows):
    testcase = (list(testcases[index]['open_testcase']) or
                list(testcases[index]['closed_testcase']) or [None])[0]
    if testcase:
      testcase = {
          'id': testcase.key.id(),
          'issueNumber': testcase.bug_information,
          'groupIssueNumber': testcase.group_bug_information
      }
    row['testcase'] = testcase


def get_result():
  """Get the result for the crash stats page."""
  params = dict(request.iterparams())
  page = helpers.cast(request.get('page') or 1, int, "'page' is not an int.")
  group_by = params.get('group', 'platform')
  params['group'] = group_by
  sort_by = params.get('sort', 'total_count')
  params['sort'] = sort_by
  params['number'] = params.get('number', 'count')

  # Conditions for individual records.
  query = crash_stats.Query()
  query.group_by = group_by
  query.sort_by = sort_by
  crash_access.add_scope(query, params, 'security_flag', 'job_type',
                         'fuzzer_name')
  filters.add(query, params, FILTERS)

  # Conditions after grouping.
  group_query = crash_stats.Query()
  filters.add(group_query, params, GROUP_FILTERS)

  try:
    total_count, rows = crash_stats.get(
        query=query,
        group_query=group_query,
        offset=(page - 1) * PAGE_SIZE,
        limit=PAGE_SIZE)
  except ValueError:
    raise helpers.EarlyExitException('Invalid filters', 400)

  attach_testcases(rows)

  helpers.log('CrashStats', helpers.VIEW_OPERATION)

  result = {
      'totalPages': (total_count // PAGE_SIZE) + 1,
      'page': page,
      'pageSize': PAGE_SIZE,
      'items': rows,
      'totalCount': total_count
  }
  return result, params


def get_all_platforms():
  """Get all platforms including parent platform."""
  items = data_types.Testcase.query(
      projection=[data_types.Testcase.platform], distinct=True)

  return sorted(
      list(
          set([item.platform.lower() for item in items if item.platform] +
              ['android'])))


class Handler(base_handler.Handler):
  """Handler that gets the crash stats when user first lands on the page."""

  @handler.get(handler.HTML)
  @handler.unsupported_on_local_server
  def get(self):
    """Get and render the crash stats in HTML."""
    result, params = get_result()
    field_values = {
        'fuzzers':
            data_handler.get_all_fuzzer_names_including_children(
                include_parents=True),
        'jobs':
            data_handler.get_all_job_type_names(),
        'platforms':
            get_all_platforms(),
        'projects':
            data_handler.get_all_project_names(),
        'minHour':
            crash_stats_common.get_min_hour(),
        'maxHour':
            crash_stats_common.get_max_hour()
    }
    return self.render('crash-stats.html', {
        'result': result,
        'fieldValues': field_values,
        'params': params
    })


class JsonHandler(base_handler.Handler):
  """Handler that gets the crash stats when user interacts with the page."""

  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    """Get and render the crash stats in JSON."""
    result, _ = get_result()
    return self.render_json(result)

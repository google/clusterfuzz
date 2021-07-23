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
"""Handler for the regression page."""

import json

from flask import request

from clusterfuzz._internal.google_cloud_utils import big_query
from handlers import base_handler
from libs import crash_access
from libs import filters
from libs import handler
from libs import helpers
from libs.query import big_query_query

PAGE_SIZE = 30

SQL = """
WITH
  # Deduplicate rows for the same testcase.
  unique_rows AS (
    SELECT
      testcase_id,
      ARRAY_AGG(crash_type)[OFFSET(0)] AS crash_type,
      ARRAY_AGG(crash_state)[OFFSET(0)] AS crash_state,
      ARRAY_AGG(security_flag)[OFFSET(0)] AS security_flag,
      ARRAY_AGG({prefix}_range_start)[OFFSET(0)] AS {prefix}_range_start,
      ARRAY_AGG({prefix}_range_end)[OFFSET(0)] AS {prefix}_range_end,
      ARRAY_AGG(created_at)[OFFSET(0)] AS created_at
    FROM main.{table_id}
    WHERE {where_clause}
    GROUP BY testcase_id
    ORDER BY created_at DESC
  )

SELECT
  crash_type, crash_state, security_flag,
  COUNT(testcase_id) AS count,
  ARRAY_AGG(STRUCT(
    testcase_id,
    {prefix}_range_start AS range_start,
    {prefix}_range_end AS range_end,
    created_at
  )) AS testcases
FROM unique_rows
GROUP BY crash_type, crash_state, security_flag
ORDER BY count DESC
"""


class RevisionFilter(filters.Filter):
  """Filter for revision."""

  def add(self, query, params):
    """Set query according to revision and type params."""
    if not params.get('revision'):
      raise helpers.EarlyExitException('Please specify the revision.', 400)

    prefix = params['type']
    revision = helpers.cast(params['revision'], int,
                            "'revision' must be an integer")
    query.raw_filter('{prefix}_range_start < {revision} AND '
                     '{revision} <= {prefix}_range_end'.format(
                         revision=json.dumps(revision), prefix=prefix))


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


class IncludeZeroFilter(filters.Filter):
  """Filter for including a range starting with 0."""

  def add(self, query, params):
    """Set query based on if range should include 0 or not."""
    value = params.get('includeZero', False)
    prefix = params['type']

    if not value:
      query.raw_filter('{prefix}_range_start > 0'.format(prefix=prefix))


class TypeFilter(filters.Filter):
  """Filter for type."""

  def add(self, query, params):  # pylint: disable=unused-argument
    """Validate type param is either regression or fixed."""
    value = params.get('type', 'regression')

    if value not in ['fixed', 'regression']:
      raise helpers.EarlyExitException(
          "'type' can only be either 'fixed' or 'regression'.", 400)


FILTERS = [
    TypeFilter(),
    RevisionFilter(),
    KeywordFilter(),
    IncludeZeroFilter(),
]


def get(params, query, offset, limit):
  """Get the data from BigQuery."""
  sql = SQL.format(
      table_id='%ss' % params['type'],
      where_clause=query.get_where_clause(),
      prefix=params['type'],
      offset=offset,
      limit=limit)
  client = big_query.Client()
  result = client.query(query=sql, offset=offset, limit=limit)
  return result.rows, result.total_count


def get_result():
  """Get the result for the crash stats page."""
  params = dict(request.iterparams())
  params['type'] = params.get('type', 'regression')
  page = helpers.cast(request.get('page') or 1, int, "'page' is not an int.")

  is_revision_empty = 'revision' not in params

  query = big_query_query.Query()
  crash_access.add_scope(query, params, 'security_flag', 'job_type',
                         'fuzzer_name')

  if is_revision_empty:
    total_count = 0
    rows = []
  else:
    filters.add(query, params, FILTERS)
    rows, total_count = get(
        params=params,
        query=query,
        offset=(page - 1) * PAGE_SIZE,
        limit=PAGE_SIZE)
    helpers.log('Regression', helpers.VIEW_OPERATION)

  result = {
      'totalPages': (total_count // PAGE_SIZE) + 1,
      'page': page,
      'pageSize': PAGE_SIZE,
      'items': rows,
      'totalCount': total_count,
      'isRevisionEmpty': is_revision_empty
  }
  return result, params


class Handler(base_handler.Handler):
  """Handler that lists testcases whose regression range contains a revision."""

  @handler.unsupported_on_local_server
  @handler.get(handler.HTML)
  def get(self):
    """Get and render the commit range in HTML."""
    result, params = get_result()
    return self.render('commit_range.html', {
        'result': result,
        'params': params
    })


class JsonHandler(base_handler.Handler):
  """JSON handler used for dynamic updates of commit ranges."""

  # See: https://bugs.chromium.org/p/chromium/issues/detail?id=760669
  @handler.post(handler.JSON, handler.JSON)
  @handler.oauth
  @handler.allowed_cors
  def post(self):
    """Get and render the commit range in JSON."""
    result, params = get_result()
    result['params'] = params
    return self.render_json(result)

  @handler.allowed_cors
  def options(self):
    """Responds with CORS headers."""
    return ''

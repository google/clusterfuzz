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
"""Common functionality for Crash Stats cron job, backend, and frontend."""

import datetime
import json
import math

from datastore import data_types
from google_cloud_utils import big_query
from system import environment

SQL = """
WITH
  # Deduplicate rows in case build_crash_stats runs twice on the same hour.
  uniqueRows AS (
    SELECT
      crash_type, crash_state, security_flag, hour, parent_fuzzer_name,
      fuzzer_name, job_type, revision, parent_platform, platform, project,
      MAX(count) AS count,
      MAX(min_crash_time_in_ms) AS min_crash_time_in_ms,
      MAX(max_crash_time_in_ms) AS max_crash_time_in_ms,
      MAX(sum_crash_time_in_ms) AS sum_crash_time_in_ms,
      MAX(sum_square_crash_time_in_ms) AS sum_square_crash_time_in_ms,
      LOGICAL_OR(new_flag) AS new_flag,
      LOGICAL_OR(reproducible_flag) AS reproducible_flag
    FROM main.crash_stats
    WHERE {where_clause}
    GROUP BY
      crash_type, crash_state, security_flag, hour, parent_fuzzer_name,
      fuzzer_name, job_type, revision, parent_platform, platform, project
  ),
  groupByFieldAndIndex AS (
    SELECT
      project, crash_type, crash_state, security_flag, {group_by},
      CAST(FLOOR((hour - {remainder}) / {time_span}) AS INT64) as index,
      SUM(count) AS count,
      MIN(min_crash_time_in_ms) AS min_crash_time_in_ms,
      MAX(max_crash_time_in_ms) AS max_crash_time_in_ms,
      SUM(sum_crash_time_in_ms) AS sum_crash_time_in_ms,
      SUM(sum_square_crash_time_in_ms) AS sum_square_crash_time_in_ms,
      LOGICAL_OR(new_flag) AS is_new,
      LOGICAL_OR(reproducible_flag) AS is_reproducible
    FROM uniqueRows
    GROUP BY
      project, crash_type, crash_state, security_flag, {group_by}, index
    ORDER BY {group_by} ASC, index DESC
  ),
  groupByIndex AS (
    SELECT
      SUM(count) AS total_count, index
    FROM groupByFieldAndIndex
    GROUP BY index
  ),
  withTotal AS (
    SELECT *
    FROM groupByFieldAndIndex LEFT OUTER JOIN groupByIndex
    USING (index)
  ),
  groupByField AS (
    SELECT
      project, crash_type, crash_state, security_flag,
      CAST({group_by} AS STRING) AS {group_by},
      SUM(count) AS total_count,
      MIN(min_crash_time_in_ms) AS min_crash_time_in_ms,
      MAX(max_crash_time_in_ms) AS max_crash_time_in_ms,
      SUM(sum_crash_time_in_ms) AS sum_crash_time_in_ms,
      SUM(sum_square_crash_time_in_ms) AS sum_square_crash_time_in_ms,
      LOGICAL_OR(is_new) AS is_new,
      LOGICAL_OR(is_reproducible) AS is_reproducible,
      MIN(index) AS first_index,
      ARRAY_AGG(STRUCT(
        index,
        is_new,
        CAST(((count / withTotal.total_count) * 100) AS INT64) AS percent,
        count AS count
      )) AS indices
    FROM withTotal
    GROUP BY
      project, crash_type, crash_state, security_flag, {group_by}
    ORDER BY {sort_by} DESC, total_count DESC
  )

SELECT
  project, crash_type, crash_state, security_flag,
  SUM(total_count) AS total_count,
  MIN(min_crash_time_in_ms) AS min_crash_time_in_ms,
  MAX(max_crash_time_in_ms) AS max_crash_time_in_ms,
  SUM(sum_crash_time_in_ms) AS sum_crash_time_in_ms,
  SUM(sum_square_crash_time_in_ms) AS sum_square_crash_time_in_ms,
  LOGICAL_OR(is_new) AS is_new,
  LOGICAL_OR(is_reproducible) AS is_reproducible,
  MIN(first_index) AS first_index,
  ARRAY_AGG(STRUCT({group_by} AS name, indices)) AS `groups`
FROM groupByField
GROUP BY
  project, crash_type, crash_state, security_flag
{group_having_clause}
ORDER BY {sort_by} DESC, total_count DESC
"""


def get_remainder_for_index(true_end, time_span):
  """Get remainder. This should be tested together with
    convert_index_to_hour."""
  # The remainder needs +1 because the cut-off is at the end of true_end.
  # For example, if the true_end is 49, the 1st day is 2 to 25 and the
  # 2nd day is 26, to 49.
  return (true_end % time_span) + 1


def convert_index_to_hour(index, time_span, remainder):
  """Convert index to hour."""
  # This needs -1 because the end hour is inclusive. For example, if the period
  # represents [2, 26), the end hour is 25.
  #
  # Index is added 1 because, in our SQL, we subtract the remainder, divide,
  # and floor. So, in order to get the original hour, we need to add 1 to the
  # index.
  return ((index + 1) * time_span) + remainder - 1


def get(end, days, block, group_by, where_clause, group_having_clause, sort_by,
        offset, limit):
  """Query from BigQuery given the params."""
  if where_clause:
    where_clause = '(%s) AND ' % where_clause

  start = end - (days * 24) + 1

  where_clause += '(hour BETWEEN %d AND %d) AND ' % (start, end)
  where_clause += ('(_PARTITIONTIME BETWEEN TIMESTAMP_TRUNC("%s", DAY) '
                   'AND TIMESTAMP_TRUNC("%s", DAY))' %
                   (get_datetime(start).strftime('%Y-%m-%d'),
                    get_datetime(end).strftime('%Y-%m-%d')))

  time_span = 1 if block == 'hour' else 24
  remainder = get_remainder_for_index(end, time_span)

  if group_having_clause:
    group_having_clause = 'HAVING ' + group_having_clause

  if (not big_query.VALID_FIELD_NAME_REGEX.match(group_by) or
      not big_query.VALID_FIELD_NAME_REGEX.match(sort_by)):
    raise ValueError('Invalid group_by or sort_by')

  sql = SQL.format(
      time_span=time_span,
      remainder=remainder,
      group_by=group_by,
      where_clause=where_clause,
      group_having_clause=group_having_clause,
      sort_by=sort_by)

  client = big_query.Client()
  result = client.query(query=sql, offset=offset, limit=limit)

  items = []
  for row in result.rows:
    avg_crash_time_in_ms = row['sum_crash_time_in_ms'] // row['total_count']

    for group in row['groups']:
      for index in group['indices']:
        index['hour'] = convert_index_to_hour(index['index'], time_span,
                                              remainder)

    items.append({
        'projectName': row['project'],
        'crashType': row['crash_type'],
        'crashState': row['crash_state'],
        'isSecurity': row['security_flag'],
        'isReproducible': row['is_reproducible'],
        'isNew': row['is_new'],
        'totalCount': row['total_count'],
        'crashTime': {
            'min':
                row['min_crash_time_in_ms'],
            'max':
                row['max_crash_time_in_ms'],
            'avg':
                avg_crash_time_in_ms,
            'std':
                math.sqrt(
                    (row['sum_square_crash_time_in_ms'] // row['total_count']) -
                    (avg_crash_time_in_ms * avg_crash_time_in_ms))
        },
        'groups': row['groups'],
        'days': days,
        'block': block,
        'end': end + 1  # Convert to UI's end.
    })
  return result.total_count, items


def get_datetime(hours):
  """Get datetime obj from hours from epoch."""
  return datetime.datetime.utcfromtimestamp(hours * 60 * 60)


def _get_first_or_last_successful_hour(is_last):
  """Get the first successful hour."""
  order = data_types.BuildCrashStatsJobHistory.end_time_in_hours
  if is_last:
    order = -order

  item = data_types.BuildCrashStatsJobHistory.query().order(order).get()
  if not item:
    return None

  return item.end_time_in_hours


def get_last_successful_hour():
  """Get the last hour that ran successfully. We want to run the next hour."""
  return _get_first_or_last_successful_hour(is_last=True)


def get_min_hour():
  """Get the first hour that ran successfully (for the date-time picker)."""
  hour = _get_first_or_last_successful_hour(is_last=False)

  # `hour` is None when we haven't run build_crash_stats at all.
  # Therefore, there's no crash stats data.
  #
  # On the UI, the date-time picker choose a point of time. Therefore,
  # if we choose, say, 3pm, this means we want the crash stats until 2:59pm.
  # Therefore, we need to increment by 1.
  return (hour or 0) + 1


def get_max_hour():
  """Get the last hour that can be selected by the date-time picker."""
  hour = get_last_successful_hour()

  # `hour` is None when we haven't run build_crash_stats at all.
  # Therefore, there's no crash stats data.
  #
  # On the UI, the date-time picker choose a point of time. Therefore,
  # if we choose, say, 3pm, this means we want the crash stats until 2:59pm.
  # Therefore, we need to increment by 1.
  return (hour or 0) + 1


@environment.local_noop
def get_last_crash_time(testcase):
  """Return timestamp for last crash with same crash params as testcase."""
  client = big_query.Client()

  where_clause = ('crash_type = {crash_type} AND '
                  'crash_state = {crash_state} AND '
                  'security_flag = {security_flag} AND '
                  'project = {project}').format(
                      crash_type=json.dumps(testcase.crash_type),
                      crash_state=json.dumps(testcase.crash_state),
                      security_flag=json.dumps(testcase.security_flag),
                      project=json.dumps(testcase.project_name),
                  )

  sql = """
SELECT hour
FROM main.crash_stats
WHERE {where_clause}
ORDER by hour DESC
LIMIT 1
""".format(where_clause=where_clause)

  result = client.query(query=sql)
  if result and result.rows:
    return get_datetime(result.rows[0]['hour'])

  return None

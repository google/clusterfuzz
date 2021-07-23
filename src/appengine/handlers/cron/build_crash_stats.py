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
"""A cron handler that builds data_types.CrashStatistic.

Given `end_hour`, we build the aggregated row for the end hour.

The rows are aggregated by crash_signature, fuzzer_name, job_type, platform,
revision, and project.

Here's how it works:
1. Get the latest end_hour, so that we can run the next one.
2. Send query to BigQuery and tell BigQuery to insert the result to a specific
  table.
3. Poll the result.
4. Store the end_hour.
"""

import datetime
import json
import logging
import time

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import crash_stats
from handlers import base_handler
from libs import handler

# After insertion, it takes a few seconds for a record to show up.
# We give it a few minutes.
#
# We add one hour because our hour spans from 0 minutes to 59 minutes.
BIGQUERY_INSERTION_DELAY = datetime.timedelta(hours=1, minutes=2)

# The template for job ids. Running on a already-run hour is fine to certain
# degree. We de-dup when reading.
JOB_ID_TEMPLATE = 'build_crash_stats_test_{unique_number}'

TIMEOUT = 2 * 60

SQL = """
SELECT
    COUNT(*) as count,
    crash_type, crash_state, security_flag, parent_fuzzer_name, fuzzer_name,
    job_type, revision, platform, project, reproducible_flag,
    IF(STARTS_WITH(platform, 'android'), 'android', '') AS parent_platform,
    CAST(FLOOR(UNIX_SECONDS(created_at) / 3600) AS INT64) as hour,
    MIN(crash_time_in_ms) AS min_crash_time_in_ms,
    MAX(crash_time_in_ms) AS max_crash_time_in_ms,
    SUM(crash_time_in_ms) AS sum_crash_time_in_ms,
    CAST(SUM(POW(crash_time_in_ms, 2)) AS INT64) AS sum_square_crash_time_in_ms,
    ANY_VALUE(new_flag=True) AS new_flag
FROM main.crashes
WHERE
  CAST(FLOOR(UNIX_SECONDS(created_at) / 3600) AS INT64) = {end_hour} AND
  _PARTITIONTIME = TIMESTAMP_TRUNC('{end_date}', DAY)
GROUP BY
  crash_type, crash_state, security_flag, parent_fuzzer_name, fuzzer_name,
  job_type, revision, parent_platform, platform, project, hour,
  reproducible_flag
"""


class TooEarlyException(Exception):
  """The end hour is too early according to BIGQUERY_INSERTION_DELAY."""


def get_start_hour():
  """Get the start hour from the first crash."""
  client = big_query.Client()

  sql = """
SELECT min(CAST(FLOOR(UNIX_SECONDS(created_at) / 3600) AS INT64)) as min_hour
FROM main.crashes
"""

  result = client.query(query=sql)
  if result and result.rows:
    return result.rows[0]['min_hour']

  return 0


def get_last_successful_hour_or_start_hour():
  """Get the last hour that ran successfully or the start hour."""
  last_hour = crash_stats.get_last_successful_hour()
  if last_hour:
    return last_hour

  return get_start_hour()


def get_next_end_hour():
  """Get the next end hour. If it's too early to compute data for the next end
    hour, return None."""
  last_successful_hour = get_last_successful_hour_or_start_hour()
  if not last_successful_hour:
    # No crashes seen, too early to start building stats.
    raise TooEarlyException()

  next_end_hour = last_successful_hour + 1

  next_datetime = crash_stats.get_datetime(next_end_hour)
  if (utils.utcnow() - next_datetime) <= BIGQUERY_INSERTION_DELAY:
    raise TooEarlyException()

  return next_end_hour


def make_request(client, job_id, end_hour):
  """Make a request to BigQuery to build crash stats."""
  table_id = (
      'crash_stats$%s' % crash_stats.get_datetime(end_hour).strftime('%Y%m%d'))

  sql = SQL.format(
      end_hour=end_hour,
      end_date=(crash_stats.get_datetime(end_hour).strftime('%Y-%m-%d')))
  logging.info('TableID: %s\nJobID: %s\nSQL: %s', table_id, job_id, sql)

  client.insert_from_query(
      dataset_id='main', table_id=table_id, job_id=job_id, query=sql)


def build(end_hour):
  """Build crash stats for the end hour."""
  logging.info('Started building crash stats for %s.',
               crash_stats.get_datetime(end_hour))
  job_id = JOB_ID_TEMPLATE.format(unique_number=int(time.time()))

  client = big_query.Client()
  make_request(client, job_id, end_hour)

  start_time = time.time()
  while (time.time() - start_time) < TIMEOUT:
    time.sleep(10)

    result = client.get_job(job_id)
    logging.info('Checking %s', json.dumps(result))

    if result['status']['state'] == 'DONE':
      if result['status'].get('errors'):
        raise Exception(json.dumps(result))
      return

  raise Exception('Building crash stats exceeded %d seconds.' % TIMEOUT)


def build_if_needed():
  """Get the next end hour and decide whether to execute build(). If build()
    succeeds, then record the next end hour."""
  try:
    end_hour = get_next_end_hour()
    build(end_hour)

    job_history = data_types.BuildCrashStatsJobHistory()
    job_history.end_time_in_hours = end_hour
    job_history.put()
    logging.info('CrashStatistics for end_hour=%s is built successfully',
                 crash_stats.get_datetime(end_hour))
    return end_hour
  except TooEarlyException:
    logging.info("Skip building crash stats because it's too early.")

  return None


class Handler(base_handler.Handler):
  """Handler for building data_types.CrashsStats2."""

  @handler.cron()
  def get(self):
    """Process a GET request from a cronjob."""
    end_hour = build_if_needed()
    return 'OK (end_hour=%s)' % end_hour

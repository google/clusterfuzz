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
"""BigQuery client. We cannot use gcloud's BigQuery client
  because it requires oauth2client 4.0.0. But our appengine requires
  oauth2client 1.4.2. Therefore, we implement our own BigQuery client."""

import collections
import datetime
import time

from googleapiclient import discovery

from base import retry
from base import utils
from config import local_config
from google_cloud_utils import credentials
from metrics import logs
from system import environment

REQUEST_TIMEOUT = 60
QUERY_TIMEOUT = 5 * 60
QUERY_MAX_RESULTS = 10000
QUERY_RETRY_COUNT = 3
QUERY_RETRY_DELAY = 3


@retry.wrap(
    retries=QUERY_RETRY_COUNT,
    delay=QUERY_RETRY_DELAY,
    function='google_cloud_utils.big_query.get_api_client')
def get_api_client():
  """Return an api client for bigquery."""
  return discovery.build(
      'bigquery',
      'v2',
      cache_discovery=False,
      credentials=credentials.get_default()[0])


def get_bucket():
  """Return bucket for bigquery stats."""
  return local_config.ProjectConfig().get('bigquery.bucket')


def cast(value, field):
  """Cast value to appropriate type."""
  if value is None:
    return None

  if field['type'] in {'INTEGER', 'INT64'}:
    return int(value)
  elif field['type'] in {'FLOAT', 'FLOAT64'}:
    return float(value)
  elif field['type'] in {'BOOLEAN', 'BOOL'}:
    return value == 'true'
  elif field['type'] in {'STRING'}:
    return value
  elif field['type'] in {'TIMESTAMP'}:
    return datetime.datetime.utcfromtimestamp(float(value))
  elif field['type'] in {'RECORD'}:
    return convert_row(value, field['fields'])
  else:
    raise Exception('The type %s is unsupported.' % field['type'])


def convert_row(raw_row, fields):
  """Convert a single raw row (from BigQuery) to a dict."""
  row = {}

  for index, raw_value in enumerate(raw_row['f']):
    field = fields[index]
    if field['mode'] == 'REPEATED':
      row[field['name']] = []
      for item in raw_value['v']:
        row[field['name']].append(cast(item['v'], field))
    else:
      row[field['name']] = cast(raw_value['v'], field)

  return row


def convert(result):
  """Convert a query result into an array of dicts, each of which represents
    a row."""
  fields = result['schema']['fields']
  rows = []

  for raw_row in result.get('rows', []):
    rows.append(convert_row(raw_row, fields))

  return rows


@environment.local_noop
def write_range(table_id, testcase, range_name, start, end):
  """Write a range to BigQuery. This is applicable for regression and fixed
    ranges."""
  client = Client(dataset_id='main', table_id=table_id)
  result = client.insert([
      Insert(
          row={
              'testcase_id': str(testcase.key.id()),
              'crash_type': testcase.crash_type,
              'crash_state': testcase.crash_state,
              'security_flag': testcase.security_flag,
              'parent_fuzzer_name': testcase.fuzzer_name,
              'fuzzer_name': testcase.overridden_fuzzer_name,
              'job_type': testcase.job_type,
              'created_at': int(time.time()),
              ('%s_range_start' % range_name): int(start),
              ('%s_range_end' % range_name): int(end),
          },
          insert_id='%s:%s:%s' % (testcase.key.id(), start, end))
  ])

  for error in result.get('insertErrors', []):
    logs.log_error(
        ("Ignoring error writing the testcase's %s range (%s) to "
         'BigQuery.' % (range_name, testcase.key.id())),
        exception=Exception(error))


def _get_max_results(max_results, limit, count_so_far):
  """Get an appropriate max_results."""
  # limit is None means we get every record (no limit).
  if limit is None:
    return max_results

  return min(max_results, limit - count_so_far)


Insert = collections.namedtuple('Insert', ['row', 'insert_id'])
QueryResult = collections.namedtuple('QueryResult', ['rows', 'total_count'])


class Client(object):
  """BigQuery client."""

  def __init__(self, dataset_id=None, table_id=None):
    self.project_id = utils.get_application_id()
    self.dataset_id = dataset_id
    self.table_id = table_id

    self.client = get_api_client()

  @retry.wrap(
      retries=QUERY_RETRY_COUNT,
      delay=QUERY_RETRY_DELAY,
      function='google_cloud_utils.big_query.Client.raw_query')
  def raw_query(self, query, max_results):
    # pylint: disable=line-too-long
    """Perform a query and return result.

    Args:
      query: the query string.
      timeout: the timout in seconds.
      max_results: the number of rows per response. The response cannot exceed
        10MB.
      use_legacy_sql: whether or not the query is of the legacy sql.

    Returns:
      A json explained here:
      https://cloud.google.com/bigquery/docs/reference/rest/v2/jobs/query
    """
    body = {
        'query': query,
        'timeoutMs': REQUEST_TIMEOUT * 1000,
        'useLegacySql': False,
        'maxResults': max_results
    }

    return self.client.jobs().query(
        projectId=self.project_id, body=body).execute()

  @retry.wrap(
      retries=QUERY_RETRY_COUNT,
      delay=QUERY_RETRY_DELAY,
      function='google_cloud_utils.big_query.Client.get_query_results')
  def get_query_results(self, job_id, page_token, start_index, max_results):
    # pylint: disable=line-too-long
    """Perform a query and return result.

    Args:
      query: the query string.
      job_id: the job id from query's response.
      page_token: the page token from the previous query's response.
      max_results: the number of rows per response. The response cannot exceed
        10MB.

    Returns:
      A json explained here:
      https://cloud.google.com/bigquery/docs/reference/rest/v2/jobs/getQueryResults
    """
    return self.client.jobs().getQueryResults(
        projectId=self.project_id,
        jobId=job_id,
        timeoutMs=REQUEST_TIMEOUT * 1000,
        maxResults=max_results,
        startIndex=start_index,
        pageToken=page_token).execute()

  def wait_for_completion(self, job_id, offset, max_results, start_time,
                          timeout):
    """Wait for job completion and return the first page."""
    while True:
      result = self.get_query_results(
          job_id=job_id,
          page_token=None,
          start_index=offset,
          max_results=max_results)

      if result['jobComplete']:
        return result

      if (time.time() - start_time) > timeout:
        raise Exception(
            "Timeout: the query doesn't finish within %d seconds." % timeout)
      time.sleep(1)

  def query(self,
            query,
            timeout=QUERY_TIMEOUT,
            max_results=QUERY_MAX_RESULTS,
            offset=0,
            limit=None):
    """Performs a query and returns an array of dicts."""
    rows = []
    start_time = time.time()

    result = self.raw_query(query, max_results=0)

    result = self.wait_for_completion(
        job_id=result['jobReference']['jobId'],
        offset=offset,
        max_results=_get_max_results(max_results, limit, 0),
        start_time=start_time,
        timeout=timeout)

    # totalRows is only present after the job completed successfully.
    total_count = int(result['totalRows'])

    while len(rows) < limit or limit < 0:
      rows += convert(result)

      if result['jobComplete'] and 'pageToken' not in result:
        total_count = int(result['totalRows'])
        break

      result = self.get_query_results(
          job_id=result['jobReference']['jobId'],
          page_token=result.get('pageToken'),
          start_index=0,
          max_results=_get_max_results(max_results, limit, len(rows)))

    return QueryResult(rows=rows, total_count=total_count)

  @retry.wrap(
      retries=QUERY_RETRY_COUNT,
      delay=QUERY_RETRY_DELAY,
      function='google_cloud_utils.big_query.Client.get_job')
  def get_job(self, job_id):
    # pylint: disable=line-too-long
    """Get the job.

    Args:
      job_id: the job id.

    Returns:
      A json explained here:
      https://cloud.google.com/bigquery/docs/reference/rest/v2/jobs#configuration.query
    """
    return self.client.jobs().get(
        projectId=self.project_id, jobId=job_id).execute()

  @environment.local_noop
  @retry.wrap(
      retries=QUERY_RETRY_COUNT,
      delay=QUERY_RETRY_DELAY,
      function='google_cloud_utils.big_query.Client.insert_from_query')
  def insert_from_query(self, dataset_id, table_id, job_id, query):
    # pylint: disable=line-too-long
    """Insert rows to the table from a query.

    Args:
      dataset_id: the destination dataset id.
      table_id: the desitnation table id.
      job_id: the uniquely identified job id (used for preventing redundant
        job).
      query: the query that generates rows.

    Returns:
      A json explained here:
      https://cloud.google.com/bigquery/docs/reference/rest/v2/jobs#configuration.query
    """
    return self.client.jobs().insert(
        projectId=self.project_id,
        body={
            'configuration': {
                'query': {
                    'query': query,
                    'allowLargeResults': True,
                    'destinationTable': {
                        'projectId': self.project_id,
                        'datasetId': dataset_id,
                        'tableId': table_id
                    },
                    'useLegacySql': False,
                    'writeDisposition': 'WRITE_APPEND'
                }
            },
            'jobReference': {
                'jobId': job_id,
                'projectId': self.project_id
            }
        }).execute()

  @environment.local_noop
  @retry.wrap(
      retries=QUERY_RETRY_COUNT,
      delay=QUERY_RETRY_DELAY,
      function='google_cloud_utils.big_query.Client.insert')
  def insert(self, inserts):
    # pylint: disable=line-too-long
    """Insert multiple rows.

    Args:
      inserts: a list of Inserts, each of which represents a row.

    Returns:
      A json explained here:
      https://cloud.google.com/bigquery/docs/reference/rest/v2/tabledata/insertAll
    """
    inserted_rows = []
    for insert in inserts:
      inserted_rows.append({'json': insert.row, 'insertId': insert.insert_id})

    body = {'kind': 'bigquery#tableDataInsertAllRequest', 'rows': inserted_rows}
    return self.client.tabledata().insertAll(
        projectId=self.project_id,
        datasetId=self.dataset_id,
        tableId=self.table_id,
        body=body).execute()

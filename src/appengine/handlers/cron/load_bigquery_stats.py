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
"""Handler used for loading bigquery data."""

from concurrent.futures import ThreadPoolExecutor
import datetime
import random
import string
import time

from googleapiclient.errors import HttpError
import httplib2

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.metrics import fuzzer_stats_schema
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler

STATS_KINDS = [fuzzer_stats.JobRun, fuzzer_stats.TestcaseRun]

NUM_THREADS = 4
NUM_RETRIES = 2
RETRY_SLEEP_TIME = 5
POLL_INTERVAL = 5

# Ignore the repeated uppercase digits.
_HEX_DIGITS = string.hexdigits[:-6]


class Handler(base_handler.Handler):
  """Cron handler for loading bigquery stats."""

  def _utc_now(self):
    """Return datetime.datetime.utcnow()."""
    return datetime.datetime.utcnow()

  def _execute_insert_request(self, request):
    """Executes a table/dataset insert request, retrying on transport errors."""
    for i in range(NUM_RETRIES + 1):
      try:
        request.execute()
        return True
      except HttpError as e:
        if e.resp.status == 409:
          # Already exists.
          return True

        logs.log_error('Failed to insert table/dataset.')
        return False
      except httplib2.HttpLib2Error:
        # Transport error.
        time.sleep(random.uniform(0, (1 << i) * RETRY_SLEEP_TIME))
        continue

    logs.log_error('Failed to insert table/dataset.')
    return False

  def _create_dataset_if_needed(self, bigquery, dataset_id):
    """Create a new dataset if necessary."""
    project_id = utils.get_application_id()
    dataset_body = {
        'datasetReference': {
            'datasetId': dataset_id,
            'projectId': project_id,
        },
    }
    dataset_insert = bigquery.datasets().insert(
        projectId=project_id, body=dataset_body)

    return self._execute_insert_request(dataset_insert)

  def _create_table_if_needed(self, bigquery, dataset_id, table_id, schema):
    """Create a new table if needed."""
    project_id = utils.get_application_id()
    table_body = {
        'tableReference': {
            'datasetId': dataset_id,
            'projectId': project_id,
            'tableId': table_id,
        },
        'timePartitioning': {
            'type': 'DAY',
        },
    }

    if schema is not None:
      table_body['schema'] = schema

    table_insert = bigquery.tables().insert(
        projectId=project_id, datasetId=dataset_id, body=table_body)
    return self._execute_insert_request(table_insert)

  def _poll_completion(self, bigquery, project_id, job_id):
    """Poll for completion."""
    response = bigquery.jobs().get(
        projectId=project_id, jobId=job_id).execute(num_retries=NUM_RETRIES)
    while response['status']['state'] == 'RUNNING':
      response = bigquery.jobs().get(
          projectId=project_id, jobId=job_id).execute(num_retries=NUM_RETRIES)
      time.sleep(POLL_INTERVAL)

    return response

  def _load_data(self, fuzzer):
    """Load yesterday's stats into BigQuery."""
    bigquery = big_query.get_api_client()
    project_id = utils.get_application_id()

    yesterday = (self._utc_now().date() - datetime.timedelta(days=1))
    date_string = yesterday.strftime('%Y%m%d')
    timestamp = utils.utc_date_to_timestamp(yesterday)

    dataset_id = fuzzer_stats.dataset_name(fuzzer)
    if not self._create_dataset_if_needed(bigquery, dataset_id):
      return

    for kind in STATS_KINDS:
      kind_name = kind.__name__
      table_id = kind_name

      if kind == fuzzer_stats.TestcaseRun:
        schema = fuzzer_stats_schema.get(fuzzer)
      else:
        schema = kind.SCHEMA

      if not schema:
        continue

      if not self._create_table_if_needed(bigquery, dataset_id, table_id,
                                          schema):
        continue

      gcs_path = fuzzer_stats.get_gcs_stats_path(kind_name, fuzzer, timestamp)
      # Shard loads by prefix to avoid causing BigQuery to run out of memory.
      first_write = True
      for prefix in _HEX_DIGITS:
        load = {
            'destinationTable': {
                'projectId': project_id,
                'tableId': table_id + '$' + date_string,
                'datasetId': dataset_id,
            },
            'schemaUpdateOptions': ['ALLOW_FIELD_ADDITION',],
            'sourceFormat':
                'NEWLINE_DELIMITED_JSON',
            'sourceUris': ['gs:/' + gcs_path + prefix + '*.json'],
            # Truncate on the first shard, then append the rest.
            'writeDisposition':
                'WRITE_TRUNCATE' if first_write else 'WRITE_APPEND',
            'schema':
                schema,
        }

        job_body = {
            'configuration': {
                'load': load,
            },
        }

        try:
          logs.log("Uploading job to BigQuery.", job_body=job_body)

          request = bigquery.jobs().insert(projectId=project_id, body=job_body)
          load_response = request.execute(num_retries=NUM_RETRIES)
          job_id = load_response['jobReference']['jobId']
          logs.log(f'Load job id: {job_id}')

          response = self._poll_completion(bigquery, project_id, job_id)
          logs.log('Completed load: %s' % response)
          errors = response['status'].get('errors')
          if errors:
            logs.log_error(
                f'Failed load for {job_id} with errors: {str(errors)})')
          else:
            # Successful write. Subsequent writes should be WRITE_APPEND.
            first_write = False
        except Exception as e:
          # Log exception here as otherwise it gets lost in the thread pool
          # worker.
          logs.log_error(f'Failed to load: {str(e)}')

  @handler.cron()
  def get(self):
    """Load bigquery stats from GCS."""
    if not big_query.get_bucket():
      logs.log_error('Loading stats to BigQuery failed: missing bucket name.')
      return

    thread_pool = ThreadPoolExecutor(max_workers=NUM_THREADS)

    # Retrieve list of fuzzers before iterating them, since the query can expire
    # as we create the load jobs.
    for fuzzer in list(data_types.Fuzzer.query()):
      logs.log('Loading stats to BigQuery for %s.' % fuzzer.name)
      thread_pool.submit(self._load_data, fuzzer.name)

    thread_pool.shutdown(wait=True)

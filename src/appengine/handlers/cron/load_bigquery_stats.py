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

import datetime
import random
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

NUM_RETRIES = 2
RETRY_SLEEP_TIME = 5


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

  def _create_table_if_needed(self, bigquery, dataset_id, table_id):
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

    table_insert = bigquery.tables().insert(
        projectId=project_id, datasetId=dataset_id, body=table_body)
    return self._execute_insert_request(table_insert)

  def _load_data(self, bigquery, fuzzer):
    """Load yesterday's stats into BigQuery."""
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
      if not self._create_table_if_needed(bigquery, dataset_id, table_id):
        continue

      if kind == fuzzer_stats.TestcaseRun:
        schema = fuzzer_stats_schema.get(fuzzer)
      else:
        schema = kind.SCHEMA

      gcs_path = fuzzer_stats.get_gcs_stats_path(kind_name, fuzzer, timestamp)
      load = {
          'destinationTable': {
              'projectId': project_id,
              'tableId': table_id + '$' + date_string,
              'datasetId': dataset_id,
          },
          'schemaUpdateOptions': ['ALLOW_FIELD_ADDITION',],
          'sourceFormat': 'NEWLINE_DELIMITED_JSON',
          'sourceUris': ['gs:/' + gcs_path + '*.json'],
          'writeDisposition': 'WRITE_TRUNCATE',
      }
      if schema is not None:
        load['schema'] = schema

      job_body = {
          'configuration': {
              'load': load,
          },
      }

      logs.log("Uploading job to BigQuery.", job_body=job_body)
      request = bigquery.jobs().insert(projectId=project_id, body=job_body)
      response = request.execute()

      # We cannot really check the response here, as the query might be still
      # running, but having a BigQuery jobId in the log would make our life
      # simpler if we ever have to manually check the status of the query.
      # See https://cloud.google.com/bigquery/docs/reference/rest/v2/jobs/query.
      logs.log('Response from BigQuery: %s' % response)

  @handler.cron()
  def get(self):
    """Load bigquery stats from GCS."""
    if not big_query.get_bucket():
      logs.log_error('Loading stats to BigQuery failed: missing bucket name.')
      return

    # Retrieve list of fuzzers before iterating them, since the query can expire
    # as we create the load jobs.
    bigquery_client = big_query.get_api_client()
    for fuzzer in list(data_types.Fuzzer.query()):
      logs.log('Loading stats to BigQuery for %s.' % fuzzer.name)
      self._load_data(bigquery_client, fuzzer.name)

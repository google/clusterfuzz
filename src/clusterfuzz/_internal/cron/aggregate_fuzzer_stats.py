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
"""Cron job to aggregate fuzzer stats onto a daily_stats BigQuery table."""

import argparse
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor
import datetime
import io
import json
import random
import time

from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
import httplib2

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types, ndb_utils
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

# Limit worker count to 4 concurrent threads to prevent exhaustion of
# project-wide queued interactive queries quota (1,000 maximum). See
# https://cloud.google.com/bigquery/quotas#query_jobs
NUM_THREADS = 4
NUM_RETRIES = 2
RETRY_SLEEP_TIME = 5

DAILY_STATS_SCHEMA = {
    'fields': [{
        'name': 'fuzzer_name',
        'type': 'STRING',
        'mode': 'NULLABLE'
    }, {
        'name': 'date',
        'type': 'DATE',
        'mode': 'NULLABLE'
    }, {
        'name': 'testcases_executed',
        'type': 'INTEGER',
        'mode': 'NULLABLE'
    }, {
        'name': 'testcase_execution_duration',
        'type': 'INTERVAL',
        'mode': 'NULLABLE'
    }, {
        'name': 'testcases_generated',
        'type': 'INTEGER',
        'mode': 'NULLABLE'
    }, {
        'name': 'testcase_generation_duration',
        'type': 'INTERVAL',
        'mode': 'NULLABLE'
    }, {
        'name': 'fuzzing_duration',
        'type': 'INTERVAL',
        'mode': 'NULLABLE'
    }]
}


def _execute_insert_request(request):
  """Executes a table/dataset insert request, retrying on transport errors."""
  for i in range(NUM_RETRIES + 1):
    try:
      request.execute()
      return
    except HttpError as e:
      if e.resp.status == 409:
        # 409 Conflict: Returned when the resource already exists. This is
        # expected in after the first execution because tables are created
        # exactly once.
        return

      logs.error('Failed to insert table/dataset.', exception=e)
      raise
    except httplib2.HttpLib2Error as e:
      # Network or transport error, retry operation with exponential back-off.
      if i == NUM_RETRIES:
        logs.error('Failed to insert table/dataset after retries.', exception=e)
        raise
      time.sleep(random.uniform(0, (1 << i) * RETRY_SLEEP_TIME))


def _create_dataset_if_needed(bigquery, dataset_id):
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

  _execute_insert_request(dataset_insert)


def _create_table_if_needed(bigquery, dataset_id, table_id, schema):
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
          'field': 'date',
      },
      'schema': schema
  }

  table_insert = bigquery.tables().insert(
      projectId=project_id, datasetId=dataset_id, body=table_body)
  _execute_insert_request(table_insert)


def _poll_completion(bigquery, project_id, job_id):
  """Poll for completion."""
  response = bigquery.jobs().get(
      projectId=project_id, jobId=job_id).execute(num_retries=2)
  while response['status']['state'] == 'RUNNING':
    time.sleep(5)
    response = bigquery.jobs().get(
        projectId=project_id, jobId=job_id).execute(num_retries=2)

  return response


def _query_fuzzer_stats(fuzzer_name, project_id):
  """Queries single fuzzer stats for yesterday."""
  dataset_id = fuzzer_stats.dataset_name(fuzzer_name)
  table_id = 'JobRun'

  # TODO: Pass timestamp from an optional flag with default value for yesterday
  query = f"""
  SELECT
    '{fuzzer_name}' as fuzzer_name,
    CAST(DATE(TIMESTAMP_SECONDS(CAST(timestamp AS INT64))) AS STRING) as date,
    SUM(testcases_executed) as testcases_executed,
    CONCAT(
      'P',
      CAST(EXTRACT(DAY FROM SUM(testcase_execution_duration)) AS STRING), 'DT',
      CAST(EXTRACT(HOUR FROM SUM(testcase_execution_duration)) AS STRING), 'H',
      CAST(EXTRACT(MINUTE FROM SUM(testcase_execution_duration)) AS STRING), 'M',
      CAST(EXTRACT(SECOND FROM SUM(testcase_execution_duration)) AS STRING), 'S'
    ) as testcase_execution_duration,
    SUM(testcases_generated) as testcases_generated,
    CONCAT(
      'P',
      CAST(EXTRACT(DAY FROM SUM(testcase_generation_duration)) AS STRING), 'DT',
      CAST(EXTRACT(HOUR FROM SUM(testcase_generation_duration)) AS STRING), 'H',
      CAST(EXTRACT(MINUTE FROM SUM(testcase_generation_duration)) AS STRING), 'M',
      CAST(EXTRACT(SECOND FROM SUM(testcase_generation_duration)) AS STRING), 'S'
    ) as testcase_generation_duration,
    CONCAT(
      'P',
      CAST(EXTRACT(DAY FROM SUM(fuzzing_duration)) AS STRING), 'DT',
      CAST(EXTRACT(HOUR FROM SUM(fuzzing_duration)) AS STRING), 'H',
      CAST(EXTRACT(MINUTE FROM SUM(fuzzing_duration)) AS STRING), 'M',
      CAST(EXTRACT(SECOND FROM SUM(fuzzing_duration)) AS STRING), 'S'
    ) as fuzzing_duration
  FROM
    `{project_id}.{dataset_id}.{table_id}`
  WHERE
    DATE(TIMESTAMP_SECONDS(CAST(timestamp AS INT64))) = DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)
  GROUP BY
    date
  """

  try:
    source_client = big_query.Client()
    result = source_client.query(query)

    if not result.rows:
      logs.info(f'No data for {fuzzer_name} for yesterday.')
      return []

    return list(result.rows)

  except HttpError as e:
    if e.resp.status == 404:
      logs.info(
          f'JobRun table or dataset does not exist for {fuzzer_name}. Skipping.'
      )
      return []
    else:
      raise  # fallback to general exception
  except Exception as e:
    logs.error(f'Failed to process {fuzzer_name}', exception=e)
    return []


def _gather_all_stats(fuzzers, project_id):
  """Gathers fuzzer statistics concurrently using a thread pool."""
  all_rows = []
  with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
    future_to_fuzzer = {
        executor.submit(_query_fuzzer_stats, fuzzer.name, project_id): fuzzer
        for fuzzer in fuzzers
    }

    for future in as_completed(future_to_fuzzer):
      fuzzer = future_to_fuzzer[future]
      try:
        rows = future.result()
        if rows:
          all_rows.extend(rows)
      except Exception as e:
        logs.error(f'Task execution crashed for {fuzzer.name}', exception=e)

  return all_rows


def _persist_daily_stats(all_rows, bigquery_client, project_id,
                         date_partition_str, non_dry_run):
  """Writes gathered row statistics to destination table."""
  if not all_rows:
    logs.error(f'No data to write to daily_stats on {date_partition_str}')
    return

  if not non_dry_run:
    logs.info(f'DRY RUN: Would insert {len(all_rows)} rows across all fuzzers.')
    logs.info(all_rows)
    return

  try:
    output = io.StringIO()
    for row in all_rows:
      output.write(json.dumps(row) + '\n')

    content = output.getvalue().encode('utf-8')
    media_body = MediaIoBaseUpload(
        io.BytesIO(content),
        mimetype='application/octet-stream',
        resumable=False)

    body = {
        'configuration': {
            'load': {
                'destinationTable': {
                    'projectId': project_id,
                    'datasetId': 'fuzzer_stats',
                    'tableId': f'daily_stats${date_partition_str}'
                },
                'sourceFormat': 'NEWLINE_DELIMITED_JSON',
                'writeDisposition': 'WRITE_TRUNCATE',
                'schema': DAILY_STATS_SCHEMA
            }
        }
    }

    request = bigquery_client.jobs().insert(
        projectId=project_id, body=body, media_body=media_body)
    response = request.execute(num_retries=2)
    job_id = response['jobReference']['jobId']

    logs.info(f'Monitoring completion for load job id: {job_id}')
    poll_response = _poll_completion(bigquery_client, project_id, job_id)

    errors = poll_response['status'].get('errors')
    if errors:
      logs.error(f'Failed load for {job_id} with errors: {str(errors)})')
    else:
      logs.info(f'Successfully loaded data to '
                f'daily_stats${date_partition_str}: {poll_response}')

  except Exception as e:
    logs.error('Failed to execute batch load job in BigQuery', exception=e)


def main(argv):
  """Main entry point for the aggregate_fuzzer_stats cron job."""
  parser = argparse.ArgumentParser(prog='aggregate_fuzzer_stats')
  parser.add_argument(
      '--non-dry-run', action='store_true', help='Whether to write to BigQuery')
  args = parser.parse_args(argv)

  logs.info('Starting fuzzer stats aggregation cron.')

  if environment.is_local_development():
    logs.error('BigQuery requires a cloud project to run. '
               'This cron job cannot run locally.')
    return

  bigquery_client = big_query.get_api_client()
  project_id = utils.get_application_id()

  if args.non_dry_run:
    _create_dataset_if_needed(bigquery_client, 'fuzzer_stats')
    _create_table_if_needed(bigquery_client, 'fuzzer_stats', 'daily_stats',
                            DAILY_STATS_SCHEMA)

  fuzzers = list(data_types.Fuzzer.query(
      ndb_utils.is_false(data_types.Fuzzer.builtin)))


  yesterday = utils.utcnow().date() - datetime.timedelta(days=1)
  date_partition_str = yesterday.strftime('%Y%m%d')

  all_rows = _gather_all_stats(fuzzers, project_id)

  _persist_daily_stats(
      all_rows=all_rows,
      bigquery_client=bigquery_client,
      project_id=project_id,
      date_partition_str=date_partition_str,
      non_dry_run=args.non_dry_run)

  logs.info('Fuzzer stats aggregation cron complete.')

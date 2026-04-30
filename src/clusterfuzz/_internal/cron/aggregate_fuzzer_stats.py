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
import datetime
import io
import json
import time

from googleapiclient.http import MediaIoBaseUpload

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

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


def _create_dataset_if_needed(bigquery, dataset_id):
  """Create a new dataset if necessary."""
  project_id = utils.get_application_id()
  dataset_body = {
      'datasetReference': {
          'datasetId': dataset_id,
          'projectId': project_id,
      },
  }
  try:
    bigquery.datasets().insert(
        projectId=project_id, body=dataset_body).execute()
    logs.info(f'Created dataset {dataset_id}.')
  except Exception as e:
    if '409' not in str(e):
      logs.error(f'Failed to create dataset {dataset_id}: {e}')


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

  try:
    # Validate that existing partitioned state holds right parameters
    table_info = bigquery.tables().get(
        projectId=project_id, datasetId=dataset_id, tableId=table_id).execute()
    time_partitioning = table_info.get('timePartitioning')
    if not time_partitioning or time_partitioning.get('field') != 'date':
      logs.info(f'Table {dataset_id}.{table_id} exists but is unpartitioned or '
                f'configured differently. Re-creating.')
      bigquery.tables().delete(
          projectId=project_id, datasetId=dataset_id,
          tableId=table_id).execute()

  except Exception as e:
    # TODO: Use real exceptions from the API instead of string matching codes
    if '404' not in str(e) and 'dropped for re-creation' not in str(e):
      logs.error(
          f'Error checking metadata for table {dataset_id}.{table_id}: {e}')
      return

  try:
    bigquery.tables().insert(
        projectId=project_id, datasetId=dataset_id, body=table_body).execute()
    logs.info(f'Created table {dataset_id}.{table_id}.')
  except Exception as e:
    if '409' not in str(e):
      logs.error(f'Failed to create table {dataset_id}.{table_id}: {e}')


def _poll_completion(bigquery, project_id, job_id):
  """Poll for completion."""
  response = bigquery.jobs().get(
      projectId=project_id, jobId=job_id).execute(num_retries=2)
  while response['status']['state'] == 'RUNNING':
    time.sleep(5)
    response = bigquery.jobs().get(
        projectId=project_id, jobId=job_id).execute(num_retries=2)

  return response


def main(argv):
  """Main entry point for the aggregate_fuzzer_stats cron job."""
  parser = argparse.ArgumentParser(prog='aggregate_fuzzer_stats')
  parser.add_argument(
      '--non-dry-run', action='store_true', help='Whether to write to BigQuery')
  # parser.add_argument(
  #     '--force-replace', action='store_true', help='Force replace the existing date partition rather than returning a successful no-op by generating a unique BigQuery'
  # )
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

  # The linter suggests a comparison that isn't supported by query() filters.
  # pylint: disable=singleton-comparison
  fuzzers = data_types.Fuzzer.query(data_types.Fuzzer.builtin == False)

  yesterday = utils.utcnow().date() - datetime.timedelta(days=1)
  date_partition_str = yesterday.strftime('%Y%m%d')

  all_rows = []

  for fuzzer in fuzzers:
    logs.info(f'Processing stats for fuzzer: {fuzzer.name}')

    dataset_id = fuzzer_stats.dataset_name(fuzzer.name)
    table_id = 'JobRun'

    query = f"""
    SELECT
      '{fuzzer.name}' as fuzzer_name,
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
        logs.info(f'No data for {fuzzer.name} for yesterday.')
        continue

      for row in result.rows:
        all_rows.append(row)

    except Exception as e:
      logs.error(f'Failed to process {fuzzer.name}: {e}')

  if all_rows:
    if not args.non_dry_run:
      logs.info(
          f'DRY RUN: Would insert {len(all_rows)} rows across all fuzzers.')
      logs.info(all_rows)
    else:
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
        logs.error(f'Failed to execute batch load job in BigQuery: {e}')

  logs.info('Fuzzer stats aggregation cron complete.')

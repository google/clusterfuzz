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
"""Cron job to aggregate fuzzer stats in BigQuery."""

import argparse

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.metrics import logs

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
      'schema': schema
  }
  try:
    bigquery.tables().insert(
        projectId=project_id, datasetId=dataset_id, body=table_body).execute()
    logs.info(f'Created table {dataset_id}.{table_id}.')
  except Exception as e:
    if '409' not in str(e):
      logs.error(f'Failed to create table {dataset_id}.{table_id}: {e}')


def main(argv):
  """Main entry point for the aggregate_fuzzer_stats cron job."""
  parser = argparse.ArgumentParser(prog='aggregate_fuzzer_stats')
  parser.add_argument(
      '--fuzzer', required=False, help='Specific fuzzer to write')
  parser.add_argument(
      '--non-dry-run', action='store_true', help='Whether to write to BigQuery')
  args = parser.parse_args(argv)

  logs.info('Starting fuzzer stats aggregation cron.')

  bigquery_client = big_query.get_api_client()
  project_id = utils.get_application_id()

  _create_dataset_if_needed(bigquery_client, 'fuzzer_stats')
  _create_table_if_needed(bigquery_client, 'fuzzer_stats', 'daily_stats',
                          DAILY_STATS_SCHEMA)

  fuzzers = data_types.Fuzzer.query(data_types.Fuzzer.builtin == False)
  dest_client = big_query.Client(
      dataset_id='fuzzer_stats', table_id='daily_stats')

  for fuzzer in fuzzers:
    if args.fuzzer and args.fuzzer != fuzzer.name:
      continue

    logs.info(f'Processing stats for fuzzer: {fuzzer.name}')
    dataset_id = fuzzer_stats.dataset_name(fuzzer.name)
    table_id = 'JobRun'

    query = f"""
    SELECT
      '{fuzzer.name}' as fuzzer_name,
      CAST(DATE(TIMESTAMP_SECONDS(CAST(timestamp AS INT64))) AS STRING) as date,
      SUM(testcases_executed) as testcases_executed,
      CAST(SUM(testcase_execution_duration) AS STRING) as testcase_execution_duration,
      SUM(testcases_generated) as testcases_generated,
      CAST(SUM(testcase_generation_duration) AS STRING) as testcase_generation_duration,
      CAST(SUM(fuzzing_duration) AS STRING) as fuzzing_duration
    FROM
      `{project_id}.{dataset_id}.{table_id}`
    WHERE
      DATE(TIMESTAMP_SECONDS(CAST(timestamp AS INT64))) = DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)
    GROUP BY
      DATE(TIMESTAMP_SECONDS(CAST(timestamp AS INT64)))
    """

    try:
      source_client = big_query.Client()
      result = source_client.query(query)

      if not result.rows:
        logs.info(f'No data for {fuzzer.name} for yesterday.')
        continue

      inserts = []
      for row in result.rows:
        date_str = row['date']
        insert_id = fuzzer.name + '_' + date_str
        inserts.append(big_query.Insert(row=row, insert_id=insert_id))

      if inserts:
        if not args.non_dry_run:
          logs.info(
              f'DRY RUN: Would insert {len(inserts)} rows for {fuzzer.name}.')
        else:
          insert_result = dest_client.insert(inserts)
          errors = insert_result.get('insertErrors')
          if errors:
            logs.error(f'Failed to insert rows for {fuzzer.name}: {errors}')
          else:
            logs.info(
                f'Successfully inserted {len(inserts)} rows for {fuzzer.name}.')

    except Exception as e:
      logs.error(f'Failed to process {fuzzer.name}: {e}')

  logs.info('Fuzzer stats aggregation cron complete.')

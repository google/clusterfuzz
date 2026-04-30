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
"""Script to migrate BigQuery JobRun table schemas for old fuzzers."""

from googleapiclient.errors import HttpError

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import fuzzer_stats


def execute(args):
  """Migrate historical BigQuery JobRun tables to current JOB_RUN_SCHEMA.

  Adds missing duration fields to fuzzer statistics datasets in BigQuery.
  """
  print('Starting BigQuery statistics tables schema migration.')

  bigquery_client = big_query.get_api_client()
  project_id = utils.get_application_id()

  fuzzers = list(data_types.Fuzzer.query(data_types.Fuzzer.builtin == False))
  count = 0

  for fuzzer in fuzzers:
    dataset_id = fuzzer_stats.dataset_name(fuzzer.name)
    table_id = 'JobRun'

    try:
      table = bigquery_client.tables().get(
          projectId=project_id, datasetId=dataset_id,
          tableId=table_id).execute()
    except HttpError as e:
      if e.resp.status == 404:
        # Table or dataset doesn't exist. No schema to update.
        continue
      print(f'Failed getting table details for {fuzzer.name}: {e}')
      continue
    except Exception as e:
      print(f'Failed getting table details for {fuzzer.name}: {e}')
      continue

    fields = table.get('schema', {}).get('fields', [])
    existing_names = {f['name'] for f in fields}

    expected_fields = fuzzer_stats.JobRun.SCHEMA['fields']
    missing_fields = [
        f for f in expected_fields if f['name'] not in existing_names
    ]

    if not missing_fields:
      continue

    updated_fields = list(fields) + missing_fields
    body = {'schema': {'fields': updated_fields}}

    if not args.non_dry_run:
      missing_names = [f['name'] for f in missing_fields]
      print(f'DRY RUN: Would append {missing_names} to {fuzzer.name}.')
    else:
      try:
        bigquery_client.tables().patch(
            projectId=project_id,
            datasetId=dataset_id,
            tableId=table_id,
            body=body).execute()
        print(f'Successfully updated schema for fuzzer: {fuzzer.name}')
        count += 1
      except Exception as e:
        print(f'Error updating schema for {fuzzer.name}: {e}')

  print(
      f'BigQuery schema migration complete. Updated {count} fuzzer stats schemas.'
  )

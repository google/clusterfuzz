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
"""Tests for aggregate_fuzzer_stats."""

import unittest
from unittest import mock

from clusterfuzz._internal.cron import aggregate_fuzzer_stats
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils.big_query import QueryResult
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class AggregateFuzzerStatsTest(unittest.TestCase):
  """Test AggregateFuzzerStats."""

  def setUp(self):
    # Create a non-builtin fuzzer
    data_types.Fuzzer(name='fuzzer', jobs=['job'], builtin=False).put()
    data_types.Job(name='job').put()

    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.big_query.get_api_client',
        'clusterfuzz._internal.google_cloud_utils.big_query.Client',
        'clusterfuzz._internal.base.utils.get_application_id',
    ])

    self.mock.get_application_id.return_value = 'test-clusterfuzz'
    self.mock_api_client = mock.MagicMock()
    self.mock.get_api_client.return_value = self.mock_api_client

    self.mock_client_instance = mock.MagicMock()
    self.mock.Client.return_value = self.mock_client_instance

    self.mock_client_instance.query.return_value = QueryResult(
        rows=[{
            'fuzzer_name': 'fuzzer',
            'date': '2026-05-01',
            'testcases_executed': 10,
            'testcase_execution_duration': 'P0DT0H1M0S',
            'testcases_generated': 5,
            'testcase_generation_duration': 'P0DT0H0M30S',
            'fuzzing_duration': 'P0DT0H1M30S'
        }],
        total_count=1)

    self.mock_client_instance.insert.return_value = {}

  def test_aggregate(self):
    """Tests execution of the aggregate_fuzzer_stats cron job."""
    # Pass argv list instead of mock args object
    aggregate_fuzzer_stats.main(['--non-dry-run'])

    # Verify dataset creation attempt
    self.mock_api_client.datasets().insert.assert_called_with(
        projectId='test-clusterfuzz',
        body={
            'datasetReference': {
                'projectId': 'test-clusterfuzz',
                'datasetId': 'fuzzer_stats'
            }
        })

    # Verify table creation attempt
    self.mock_api_client.tables().insert.assert_called_with(
        body={
            'tableReference': {
                'projectId': 'test-clusterfuzz',
                'datasetId': 'fuzzer_stats',
                'tableId': 'daily_stats',
            },
            'schema': aggregate_fuzzer_stats.DAILY_STATS_SCHEMA,
        },
        datasetId='fuzzer_stats',
        projectId='test-clusterfuzz')

    # Verify query execution
    self.mock_client_instance.query.assert_called_once()

    # Verify insert
    self.mock_client_instance.insert.assert_called_once()
    args_list = self.mock_client_instance.insert.call_args_list
    inserts = args_list[0][0][0]
    self.assertEqual(len(inserts), 1)
    self.assertEqual(inserts[0].row['fuzzer_name'], 'fuzzer')
    self.assertEqual(inserts[0].insert_id, 'fuzzer_2026-05-01')

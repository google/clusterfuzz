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
"""Tests for load_bigquery_stats."""
import datetime
import unittest
from unittest import mock

from clusterfuzz._internal.cron import load_bigquery_stats
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class LoadBigQueryStatsTest(unittest.TestCase):
  """Test LoadBigQueryStatsTest."""

  def setUp(self):
    data_types.Fuzzer(name='fuzzer', jobs=['job']).put()
    data_types.Job(name='job').put()

    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.big_query.get_api_client',
        'clusterfuzz._internal.metrics.fuzzer_stats_schema.get',
        'handlers.base_handler.Handler.is_cron',
        'clusterfuzz._internal.cron.load_bigquery_stats._utc_now',
    ])

    self.mocked_today = datetime.datetime(2016, 9, 8)
    self.mock._utc_now.return_value = self.mocked_today  # pylint: disable=protected-access
    self.mock_bigquery = mock.MagicMock()
    self.mock.get_api_client.return_value = self.mock_bigquery
    self.mock.get.return_value = {'schema': 'schema'}
    self.mock_bigquery.jobs().get().execute.return_value = {
        'status': {
            'state': 'DONE',
        },
    }

  def _assert_load_calls(self, expected_date_str):
    """Helper method to assert BigQuery dataset, table, and load job API calls."""
    self.mock_bigquery.datasets().insert.assert_has_calls([
        mock.call(
            projectId='test-clusterfuzz',
            body={
                'datasetReference': {
                    'projectId': 'test-clusterfuzz',
                    'datasetId': 'fuzzer_stats'
                }
            }),
        mock.call().execute()
    ])

    self.mock_bigquery.tables().insert.assert_has_calls([
        mock.call(
            body={
                'timePartitioning': {
                    'type': 'DAY'
                },
                'tableReference': {
                    'projectId': 'test-clusterfuzz',
                    'tableId': 'JobRun',
                    'datasetId': 'fuzzer_stats',
                },
                'schema': fuzzer_stats.JobRun.SCHEMA,
            },
            datasetId='fuzzer_stats',
            projectId='test-clusterfuzz'),
        mock.call().execute(),
        mock.call(
            body={
                'timePartitioning': {
                    'type': 'DAY'
                },
                'tableReference': {
                    'projectId': 'test-clusterfuzz',
                    'tableId': 'TestcaseRun',
                    'datasetId': 'fuzzer_stats',
                },
                'schema': {
                    'schema': 'schema'
                },
            },
            datasetId='fuzzer_stats',
            projectId='test-clusterfuzz'),
        mock.call().execute(),
    ])

    for i, prefix in enumerate(load_bigquery_stats._HEX_DIGITS):  # pylint: disable=protected-access
      self.mock_bigquery.jobs().insert.assert_has_calls(
          [
              mock.call(
                  body={
                      'configuration': {
                          'load': {
                              'destinationTable': {
                                  'projectId': 'test-clusterfuzz',
                                  'tableId': f'JobRun${expected_date_str}',
                                  'datasetId': 'fuzzer_stats'
                              },
                              'schemaUpdateOptions': ['ALLOW_FIELD_ADDITION',],
                              'writeDisposition':
                                  'WRITE_TRUNCATE'
                                  if i == 0 else 'WRITE_APPEND',
                              'sourceUris': [
                                  'gs://test-bigquery-bucket/fuzzer/JobRun/date/'
                                  f'{expected_date_str}/' + prefix + '*.json'
                              ],
                              'sourceFormat':
                                  'NEWLINE_DELIMITED_JSON',
                              'schema':
                                  fuzzer_stats.JobRun.SCHEMA,
                          }
                      }
                  },
                  projectId='test-clusterfuzz'),
              mock.call(
                  body={
                      'configuration': {
                          'load': {
                              'destinationTable': {
                                  'projectId':
                                      'test-clusterfuzz',
                                  'tableId':
                                      f'TestcaseRun${expected_date_str}',
                                  'datasetId':
                                      'fuzzer_stats'
                              },
                              'schemaUpdateOptions': ['ALLOW_FIELD_ADDITION',],
                              'writeDisposition':
                                  'WRITE_TRUNCATE'
                                  if i == 0 else 'WRITE_APPEND',
                              'sourceUris': [
                                  'gs://test-bigquery-bucket/fuzzer/TestcaseRun/'
                                  f'date/{expected_date_str}/' + prefix +
                                  '*.json'
                              ],
                              'sourceFormat':
                                  'NEWLINE_DELIMITED_JSON',
                              'schema': {
                                  'schema': 'schema'
                              },
                          }
                      }
                  },
                  projectId='test-clusterfuzz'),
          ],
          # Otherwise we need to mock two calls to mock.call().execute().__str__()
          # which does not seem to work well.
          any_order=True)

  def test_execute(self):
    """Tests executing of cron job without a date argument (defaults to yesterday)."""
    load_bigquery_stats.main()
    expected_yesterday = (self.mocked_today.date() -
                          datetime.timedelta(days=1)).strftime('%Y%m%d')
    self._assert_load_calls(expected_yesterday)

  def test_execute_with_date(self):
    """Tests executing of cron job with an explicit date."""
    load_bigquery_stats.main(['--date', '2016-10-15'])
    self._assert_load_calls('20161015')

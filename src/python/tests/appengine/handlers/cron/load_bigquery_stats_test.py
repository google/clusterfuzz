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
import mock
import unittest

import webapp2
import webtest

from datastore import data_types
from handlers.cron import load_bigquery_stats
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class LoadBigQueryStatsTest(unittest.TestCase):
  """Test LoadBigQueryStatsTest."""

  def setUp(self):
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/load-bigquery-stats',
                                  load_bigquery_stats.Handler)]))

    data_types.Fuzzer(name='fuzzer', jobs=['job']).put()
    data_types.Job(name='job').put()

    test_helpers.patch(self, [
        'google.appengine.api.app_identity.get_application_id',
        'google_cloud_utils.big_query.get_api_client',
        'handlers.base_handler.Handler.is_cron',
        'handlers.cron.load_bigquery_stats.Handler._utc_now',
    ])

    self.mock._utc_now.return_value = datetime.datetime(2016, 9, 8)  # pylint: disable=protected-access
    self.mock.get_application_id.return_value = 'app_id'
    self.mock_bigquery = mock.MagicMock()
    self.mock.get_api_client.return_value = self.mock_bigquery

  def test_execute(self):
    """Tests executing of cron job."""
    self.app.get('/load-bigquery-stats')

    self.mock_bigquery.datasets().insert.assert_has_calls([
        mock.call(
            projectId='app_id',
            body={
                'datasetReference': {
                    'projectId': 'app_id',
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
                    'projectId': 'app_id',
                    'tableId': 'JobRun',
                    'datasetId': 'fuzzer_stats',
                },
            },
            datasetId='fuzzer_stats',
            projectId='app_id'),
        mock.call().execute(),
        mock.call(
            body={
                'timePartitioning': {
                    'type': 'DAY'
                },
                'tableReference': {
                    'projectId': 'app_id',
                    'tableId': 'TestcaseRun',
                    'datasetId': 'fuzzer_stats',
                },
            },
            datasetId='fuzzer_stats',
            projectId='app_id'),
        mock.call().execute(),
    ])

    self.mock_bigquery.jobs().insert.assert_has_calls(
        [
            mock.call(
                body={
                    'configuration': {
                        'load': {
                            'autodetect':
                                False,
                            'destinationTable': {
                                'projectId': 'app_id',
                                'tableId': 'JobRun$20160907',
                                'datasetId': 'fuzzer_stats'
                            },
                            'schemaUpdateOptions': ['ALLOW_FIELD_ADDITION'],
                            'writeDisposition':
                                'WRITE_TRUNCATE',
                            'sourceUris': [
                                'gs://test-bigquery-bucket/fuzzer/JobRun/date/'
                                '20160907/*.json'
                            ],
                            'sourceFormat':
                                'NEWLINE_DELIMITED_JSON',
                            'ignoreUnknownValues':
                                True,
                        }
                    }
                },
                projectId='app_id'),
            mock.call().execute(),
            mock.call(
                body={
                    'configuration': {
                        'load': {
                            'autodetect':
                                True,
                            'destinationTable': {
                                'projectId': 'app_id',
                                'tableId': 'TestcaseRun$20160907',
                                'datasetId': 'fuzzer_stats'
                            },
                            'schemaUpdateOptions': ['ALLOW_FIELD_ADDITION'],
                            'writeDisposition':
                                'WRITE_TRUNCATE',
                            'sourceUris': [
                                'gs://test-bigquery-bucket/fuzzer/TestcaseRun/'
                                'date/20160907/*.json'
                            ],
                            'sourceFormat':
                                'NEWLINE_DELIMITED_JSON',
                            'ignoreUnknownValues':
                                True,
                        }
                    }
                },
                projectId='app_id'),
            mock.call().execute(),
        ],
        # Otherwise we need to mock two calls to mock.call().execute().__str__()
        # which does not seem to work well.
        any_order=True)

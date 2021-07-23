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

import flask
import mock
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import load_bigquery_stats


@test_utils.with_cloud_emulators('datastore')
class LoadBigQueryStatsTest(unittest.TestCase):
  """Test LoadBigQueryStatsTest."""

  def setUp(self):
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/load-bigquery-stats',
        view_func=load_bigquery_stats.Handler.as_view('/load-bigquery-stats'))
    self.app = webtest.TestApp(flaskapp)

    data_types.Fuzzer(name='fuzzer', jobs=['job']).put()
    data_types.Job(name='job').put()

    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.big_query.get_api_client',
        'handlers.base_handler.Handler.is_cron',
        'handlers.cron.load_bigquery_stats.Handler._utc_now',
    ])

    self.mock._utc_now.return_value = datetime.datetime(2016, 9, 8)  # pylint: disable=protected-access
    self.mock_bigquery = mock.MagicMock()
    self.mock.get_api_client.return_value = self.mock_bigquery

  def test_execute(self):
    """Tests executing of cron job."""
    self.app.get('/load-bigquery-stats')

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
            },
            datasetId='fuzzer_stats',
            projectId='test-clusterfuzz'),
        mock.call().execute(),
    ])

    self.mock_bigquery.jobs().insert.assert_has_calls(
        [
            mock.call(
                body={
                    'configuration': {
                        'load': {
                            'destinationTable': {
                                'projectId': 'test-clusterfuzz',
                                'tableId': 'JobRun$20160907',
                                'datasetId': 'fuzzer_stats'
                            },
                            'schemaUpdateOptions': ['ALLOW_FIELD_ADDITION',],
                            'writeDisposition':
                                'WRITE_TRUNCATE',
                            'sourceUris': [
                                'gs://test-bigquery-bucket/fuzzer/JobRun/date/'
                                '20160907/*.json'
                            ],
                            'sourceFormat':
                                'NEWLINE_DELIMITED_JSON',
                            'schema': {
                                'fields': [{
                                    'type': 'INTEGER',
                                    'name': 'testcases_executed',
                                    'mode': 'NULLABLE'
                                }, {
                                    'type': 'INTEGER',
                                    'name': 'build_revision',
                                    'mode': 'NULLABLE'
                                }, {
                                    'type': 'INTEGER',
                                    'name': 'new_crashes',
                                    'mode': 'NULLABLE'
                                }, {
                                    'type': 'STRING',
                                    'name': 'job',
                                    'mode': 'NULLABLE'
                                }, {
                                    'type': 'FLOAT',
                                    'name': 'timestamp',
                                    'mode': 'NULLABLE'
                                }, {
                                    'fields': [{
                                        'type': 'STRING',
                                        'name': 'crash_type',
                                        'mode': 'NULLABLE'
                                    }, {
                                        'type': 'BOOLEAN',
                                        'name': 'is_new',
                                        'mode': 'NULLABLE'
                                    }, {
                                        'type': 'STRING',
                                        'name': 'crash_state',
                                        'mode': 'NULLABLE'
                                    }, {
                                        'type': 'BOOLEAN',
                                        'name': 'security_flag',
                                        'mode': 'NULLABLE'
                                    }, {
                                        'type': 'INTEGER',
                                        'name': 'count',
                                        'mode': 'NULLABLE'
                                    }],
                                    'type':
                                        'RECORD',
                                    'name':
                                        'crashes',
                                    'mode':
                                        'REPEATED'
                                }, {
                                    'type': 'INTEGER',
                                    'name': 'known_crashes',
                                    'mode': 'NULLABLE'
                                }, {
                                    'type': 'STRING',
                                    'name': 'fuzzer',
                                    'mode': 'NULLABLE'
                                }, {
                                    'type': 'STRING',
                                    'name': 'kind',
                                    'mode': 'NULLABLE'
                                }]
                            },
                        }
                    }
                },
                projectId='test-clusterfuzz'),
            mock.call().execute(),
            mock.call(
                body={
                    'configuration': {
                        'load': {
                            'destinationTable': {
                                'projectId': 'test-clusterfuzz',
                                'tableId': 'TestcaseRun$20160907',
                                'datasetId': 'fuzzer_stats'
                            },
                            'schemaUpdateOptions': ['ALLOW_FIELD_ADDITION',],
                            'writeDisposition':
                                'WRITE_TRUNCATE',
                            'sourceUris': [
                                'gs://test-bigquery-bucket/fuzzer/TestcaseRun/'
                                'date/20160907/*.json'
                            ],
                            'sourceFormat':
                                'NEWLINE_DELIMITED_JSON',
                        }
                    }
                },
                projectId='test-clusterfuzz'),
            mock.call().execute(),
        ],
        # Otherwise we need to mock two calls to mock.call().execute().__str__()
        # which does not seem to work well.
        any_order=True)

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
"""big_query tests."""

import datetime
import unittest

import mock

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class InitTest(unittest.TestCase):
  """Test Client.__init__."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.get_application_id',
        'googleapiclient.discovery.build',
        'httplib2.Http',
    ])
    self.mock.get_application_id.return_value = 'project'
    self.mock.build.return_value = 'built'

  def test_init(self):
    """Test __init__."""
    client = big_query.Client(dataset_id='data', table_id='table')

    self.assertEqual('built', client.client)
    self.assertEqual('project', client.project_id)
    self.assertEqual('data', client.dataset_id)
    self.assertEqual('table', client.table_id)

    # `self.mock.build.assert_called_once_with(
    #      'bigquery', 'v2')` doesn't
    # work because `discovery.build` is decorated with @positional.
    # Therefore, we need the below.
    args, _ = self.mock.build.call_args
    self.assertEqual(('bigquery', 'v2'), args)


class RawQueryTest(unittest.TestCase):
  """Test Client.query."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.get_application_id',
        'clusterfuzz._internal.google_cloud_utils.big_query.get_api_client',
    ])
    self.mock.get_application_id.return_value = 'project'

  def test_query(self):
    """Test calling query API."""
    underlying = mock.MagicMock()
    jobs = mock.MagicMock()
    query = mock.MagicMock()

    underlying.jobs.return_value = jobs
    jobs.query.return_value = query
    query.execute.return_value = {'test': 1}
    self.mock.get_api_client.return_value = underlying

    client = big_query.Client()

    self.assertDictEqual({'test': 1}, client.raw_query('sql', max_results=100))
    jobs.query.assert_called_once_with(
        projectId='project',
        body={
            'query': 'sql',
            'timeoutMs': 60000,
            'maxResults': 100,
            'useLegacySql': False
        })


class InsertTest(unittest.TestCase):
  """Test Client.insert."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.get_application_id',
        'clusterfuzz._internal.google_cloud_utils.big_query.get_api_client',
    ])
    self.mock.get_application_id.return_value = 'project'

  def test_insert(self):
    """Test calling insertAll API."""
    underlying = mock.MagicMock()
    tabledata = mock.MagicMock()
    insert_all = mock.MagicMock()

    underlying.tabledata.return_value = tabledata
    tabledata.insertAll.return_value = insert_all
    insert_all.execute.return_value = {'test': 1}
    self.mock.get_api_client.return_value = underlying

    client = big_query.Client(dataset_id='data', table_id='table')

    self.assertDictEqual({
        'test': 1
    },
                         client.insert([
                             big_query.Insert({
                                 'a': 1
                             }, 'prefix:0'),
                             big_query.Insert({
                                 'b': 2
                             }, 'prefix:1')
                         ]))
    tabledata.insertAll.assert_called_once_with(
        projectId='project',
        datasetId='data',
        tableId='table',
        body={
            'kind':
                'bigquery#tableDataInsertAllRequest',
            'rows': [{
                'json': {
                    'a': 1
                },
                'insertId': 'prefix:0'
            }, {
                'json': {
                    'b': 2
                },
                'insertId': 'prefix:1'
            }]
        })


class ConvertTest(unittest.TestCase):
  """Test convert."""

  def test_convert(self):
    """Test convert every field."""
    fields = [{
        'name': 'int',
        'type': 'INTEGER',
        'mode': 'NULLABLE'
    }, {
        'name': 'float',
        'type': 'FLOAT',
        'mode': 'REQUIRED'
    }, {
        'name': 'bool',
        'type': 'BOOLEAN',
        'mode': 'NULLABLE'
    }, {
        'name': 'string',
        'type': 'STRING',
        'mode': 'REQUIRED'
    }, {
        'name': 'list-string',
        'type': 'STRING',
        'mode': 'REPEATED'
    }, {
        'name': 'time',
        'type': 'TIMESTAMP',
        'mode': 'REQUIRED'
    }, {
        'name':
            'counts',
        'type':
            'RECORD',
        'mode':
            'REPEATED',
        'fields': [{
            'name': 'name',
            'type': 'STRING',
            'mode': u'NULLABLE'
        }, {
            'fields': [{
                'name': 'hour',
                'type': 'INTEGER',
                'mode': 'NULLABLE'
            }, {
                'name': 'count',
                'type': 'INTEGER',
                'mode': u'NULLABLE'
            }],
            'type':
                'RECORD',
            'name':
                'slots',
            'mode':
                'REPEATED'
        }]
    }]
    result = {
        'schema': {
            'fields': fields
        },
        'rows': [{
            'f': [
                {
                    'v': '1'
                },
                {
                    'v': '2.3'
                },
                {
                    'v': 'true'
                },
                {
                    'v': 'str'
                },
                {
                    'v': [{
                        'v': 'a'
                    }, {
                        'v': 'b'
                    }]
                },
                {
                    'v': '1.485454187696014E9'
                },
                {
                    'v': [
                        {
                            'v': {
                                'f': [{
                                    'v': 'fuzzer1'
                                }, {
                                    'v': [
                                        {
                                            'v': {
                                                'f': [{
                                                    'v': 123
                                                }, {
                                                    'v': 999
                                                }]
                                            }
                                        },
                                        {
                                            'v': {
                                                'f': [{
                                                    'v': 124
                                                }, {
                                                    'v': 998
                                                }]
                                            }
                                        },
                                    ]
                                }]
                            }
                        },
                        {
                            'v': {
                                'f': [{
                                    'v': 'fuzzer2'
                                }, {
                                    'v': [
                                        {
                                            'v': {
                                                'f': [{
                                                    'v': 223
                                                }, {
                                                    'v': 899
                                                }]
                                            }
                                        },
                                        {
                                            'v': {
                                                'f': [{
                                                    'v': 224
                                                }, {
                                                    'v': 898
                                                }]
                                            }
                                        },
                                    ]
                                }]
                            }
                        },
                        {
                            'v': {
                                'f': [{
                                    'v': 'fuzzer3'
                                }, {
                                    'v': []
                                }]
                            }
                        },
                    ]
                },
            ],
        }, {
            'f': [{
                'v': '2'
            }, {
                'v': '3.3'
            }, {
                'v': 'false'
            }, {
                'v': 'str2'
            }, {
                'v': []
            }, {
                'v': '1.485455187696014E9'
            }, {
                'v': []
            }],
        }]
    }

    self.assertEqual([{
        'int':
            1,
        'float':
            2.3,
        'bool':
            True,
        'string':
            'str',
        'list-string': ['a', 'b'],
        'time':
            datetime.datetime.utcfromtimestamp(1485454187.696014),
        'counts': [
            {
                'name':
                    'fuzzer1',
                'slots': [
                    {
                        'count': 999,
                        'hour': 123
                    },
                    {
                        'count': 998,
                        'hour': 124
                    },
                ],
            },
            {
                'name':
                    'fuzzer2',
                'slots': [
                    {
                        'count': 899,
                        'hour': 223
                    },
                    {
                        'count': 898,
                        'hour': 224
                    },
                ],
            },
            {
                'name': 'fuzzer3',
                'slots': [],
            },
        ]
    }, {
        'int': 2,
        'float': 3.3,
        'bool': False,
        'string': 'str2',
        'list-string': [],
        'time': datetime.datetime.utcfromtimestamp(1485455187.696014),
        'counts': []
    }], big_query.convert(result))


class QueryTest(unittest.TestCase):
  """Test query."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.get_application_id',
        'clusterfuzz._internal.google_cloud_utils.big_query.get_api_client',
        'time.time', 'time.sleep'
    ])
    self.mock.time.return_value = 1
    self.mock.get_application_id.return_value = 'project'

    underlying = mock.MagicMock()
    self.jobs = mock.MagicMock()

    self.query = mock.MagicMock()
    self.get_query_results = mock.MagicMock()

    underlying.jobs.return_value = self.jobs
    self.jobs.query.return_value = self.query
    self.jobs.getQueryResults.return_value = self.get_query_results

    self.mock.get_api_client.return_value = underlying

  def _make_resp(self, page_token, is_complete, total_row, count=1):
    """Make response."""
    resp = {
        'schema': {
            'fields': [{
                'name': 't',
                'type': 'INTEGER',
                'mode': 'NULLABLE'
            }]
        },
        'jobComplete': is_complete,
        'jobReference': {
            'jobId': 'job'
        },
        'totalRows': total_row
    }

    if is_complete:
      resp['rows'] = [{'f': [{'v': '1'}]}] * count

    if page_token:
      resp['pageToken'] = page_token

    return resp

  def test_one_page(self):
    """Test one page."""
    self.query.execute.return_value = self._make_resp(None, True, 1)
    self.get_query_results.execute.return_value = self._make_resp(None, True, 1)
    client = big_query.Client()

    result = client.query('sql', timeout=10, max_results=100)

    self.assertEqual([{'t': 1}], result.rows)
    self.assertEqual(1, result.total_count)
    self.query.execute.assert_called_once_with()
    self.get_query_results.execute.assert_called_once_with()
    self.jobs.query.assert_called_once_with(
        projectId='project',
        body={
            'query': 'sql',
            'timeoutMs': 60000,
            'useLegacySql': False,
            'maxResults': 0
        })

  def test_multiple_page(self):
    """Test multiple page."""
    self.query.execute.return_value = self._make_resp('tok', True, 2)
    self.get_query_results.execute.side_effect = [
        self._make_resp('tok2', True, 2),
        self._make_resp(None, True, 2)
    ]

    client = big_query.Client()

    result = client.query('sql', timeout=10, max_results=100, offset=50)

    self.assertEqual([{'t': 1}, {'t': 1}], result.rows)
    self.assertEqual(2, result.total_count)
    self.query.execute.assert_called_once_with()
    self.jobs.query.assert_called_once_with(
        projectId='project',
        body={
            'query': 'sql',
            'timeoutMs': 60000,
            'useLegacySql': False,
            'maxResults': 0
        })

    self.jobs.getQueryResults.assert_has_calls([
        mock.call(
            projectId='project',
            jobId='job',
            startIndex=50,
            pageToken=None,
            timeoutMs=60000,
            maxResults=100),
        mock.call().execute(),
        mock.call(
            projectId='project',
            jobId='job',
            startIndex=0,
            pageToken='tok2',
            timeoutMs=60000,
            maxResults=100),
        mock.call().execute()
    ])

  def test_multiple_page_with_limit(self):
    """Test multiple page with limit."""
    self.query.execute.return_value = self._make_resp('tok', True, 2)
    self.get_query_results.execute.side_effect = [
        self._make_resp('tok2', True, 2, 3),
        self._make_resp('tok3', True, 2, 3),
        self._make_resp('tok4', True, 2, 3),
        self._make_resp(None, True, 2, 1)
    ]

    client = big_query.Client()

    result = client.query(
        'sql', timeout=10, max_results=100, offset=50, limit=10)

    self.assertEqual([{'t': 1}] * 10, result.rows)
    self.assertEqual(2, result.total_count)
    self.query.execute.assert_called_once_with()
    self.jobs.query.assert_called_once_with(
        projectId='project',
        body={
            'query': 'sql',
            'timeoutMs': 60000,
            'useLegacySql': False,
            'maxResults': 0
        })

    self.jobs.getQueryResults.assert_has_calls([
        mock.call(
            projectId='project',
            jobId='job',
            startIndex=50,
            pageToken=None,
            timeoutMs=60000,
            maxResults=10),
        mock.call().execute(),
        mock.call(
            projectId='project',
            jobId='job',
            startIndex=0,
            pageToken='tok2',
            timeoutMs=60000,
            maxResults=7),
        mock.call().execute(),
        mock.call(
            projectId='project',
            jobId='job',
            startIndex=0,
            pageToken='tok3',
            timeoutMs=60000,
            maxResults=4),
        mock.call().execute(),
        mock.call(
            projectId='project',
            jobId='job',
            startIndex=0,
            pageToken='tok4',
            timeoutMs=60000,
            maxResults=1),
        mock.call().execute()
    ])

  def test_not_complete(self):
    """Test jobComplete=false for the first few request."""
    self.query.execute.return_value = self._make_resp(None, False, 4)
    self.get_query_results.execute.side_effect = [
        self._make_resp(None, False, 4),
        self._make_resp('tok', True, 8),
        self._make_resp(None, True, 8)
    ]

    client = big_query.Client()

    result = client.query('sql', timeout=10, max_results=100, offset=50)

    self.assertEqual([{'t': 1}, {'t': 1}], result.rows)
    self.assertEqual(8, result.total_count)
    self.query.execute.assert_called_once_with()
    self.jobs.query.assert_called_once_with(
        projectId='project',
        body={
            'query': 'sql',
            'timeoutMs': 60000,
            'useLegacySql': False,
            'maxResults': 0
        })

    self.jobs.getQueryResults.assert_has_calls([
        mock.call(
            projectId='project',
            jobId='job',
            timeoutMs=60000,
            maxResults=100,
            pageToken=None,
            startIndex=50),
        mock.call().execute(),
        mock.call(
            projectId='project',
            jobId='job',
            timeoutMs=60000,
            maxResults=100,
            pageToken=None,
            startIndex=50),
        mock.call().execute(),
        mock.call(
            projectId='project',
            jobId='job',
            pageToken='tok',
            timeoutMs=60000,
            maxResults=100,
            startIndex=0),
        mock.call().execute(),
    ])

  def test_timeout(self):
    """Test timeout."""
    self.query.execute.return_value = self._make_resp(None, False, 3)

    self.count = 0

    def get_query_results(**unused_kwargs):
      self.count += 1
      if self.count >= 3:
        self.mock.time.return_value = 100
      return self._make_resp('tok%d' % self.count, False, 3)

    self.get_query_results.execute.side_effect = get_query_results

    client = big_query.Client()

    with self.assertRaises(Exception) as cm:
      client.query('sql', timeout=10, max_results=100, offset=50)

    self.assertEqual("Timeout: the query doesn't finish within 10 seconds.",
                     str(cm.exception))

    self.query.execute.assert_called_once_with()
    self.jobs.query.assert_called_once_with(
        projectId='project',
        body={
            'query': 'sql',
            'timeoutMs': 60000,
            'useLegacySql': False,
            'maxResults': 0
        })

    self.jobs.getQueryResults.assert_has_calls([
        mock.call(
            projectId='project',
            jobId='job',
            timeoutMs=60000,
            maxResults=100,
            pageToken=None,
            startIndex=50),
        mock.call().execute(),
    ] * 3)


@test_utils.with_cloud_emulators('datastore')
class WriteRangeTest(unittest.TestCase):
  """Test write_range."""

  def setUp(self):
    self.client = mock.Mock(spec_set=big_query.Client)
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.log_error',
        'clusterfuzz._internal.google_cloud_utils.big_query.Client',
        'time.time',
    ])
    self.mock.time.return_value = 99
    self.mock.Client.return_value = self.client

    self.testcase = data_types.Testcase(
        crash_type='type',
        crash_state='state',
        security_flag=True,
        fuzzer_name='libfuzzer',
        overridden_fuzzer_name='libfuzzer_pdf',
        job_type='some_job')
    self.testcase.put()

  def test_write(self):
    """Tests write."""
    self.client.insert.return_value = {}
    big_query.write_range('regressions', self.testcase, 'regression', 456, 789)

    self.assertEqual(0, self.mock.log_error.call_count)
    self.client.insert.assert_called_once_with([
        big_query.Insert(
            row={
                'testcase_id': str(self.testcase.key.id()),
                'crash_type': 'type',
                'crash_state': 'state',
                'security_flag': True,
                'parent_fuzzer_name': 'libfuzzer',
                'fuzzer_name': 'libfuzzer_pdf',
                'job_type': 'some_job',
                'created_at': 99,
                'regression_range_start': 456,
                'regression_range_end': 789,
            },
            insert_id='%s:456:789' % self.testcase.key.id())
    ])

  def test_error(self):
    """Tests error."""
    self.client.insert.return_value = {'insertErrors': ['exception']}
    big_query.write_range('regressions', self.testcase, 'regression', 456, 789)

    self.mock.log_error.assert_called_once_with(
        ("Ignoring error writing the testcase's regression range (%s) to "
         'BigQuery.' % self.testcase.key.id()),
        exception=mock.ANY)
    self.client.insert.assert_called_once_with([
        big_query.Insert(
            row={
                'testcase_id': str(self.testcase.key.id()),
                'crash_type': 'type',
                'crash_state': 'state',
                'security_flag': True,
                'parent_fuzzer_name': 'libfuzzer',
                'fuzzer_name': 'libfuzzer_pdf',
                'job_type': 'some_job',
                'created_at': 99,
                'regression_range_start': 456,
                'regression_range_end': 789,
            },
            insert_id='%s:456:789' % self.testcase.key.id())
    ])

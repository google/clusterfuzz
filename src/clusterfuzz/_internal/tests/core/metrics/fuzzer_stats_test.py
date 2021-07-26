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
"""Tests for fuzzer_stats."""

import datetime
import json
import os
import re
import unittest

import mock
import six

from clusterfuzz._internal.bot.tasks import fuzz_task
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


def sanitize_sql(s):
  """Sanitize the sql by removing all new lines and surrounding whitespace."""
  s = re.sub('[ \\s\n\r]*\n[ \\s\n\r]*', ' ', s, flags=re.MULTILINE)
  s = re.sub('\\([ \t]+', '(', s)
  s = re.sub('[ \t]+\\)', ')', s)
  return s.strip()


@test_utils.with_cloud_emulators('datastore')
class FuzzerStatsTest(unittest.TestCase):
  """Fuzzer stats tests."""

  def setUp(self):
    helpers.patch_environ(self)
    data_types.Fuzzer(name='parent').put()

    data_types.FuzzTarget(engine='parent', binary='child').put()
    data_types.FuzzTargetJob(
        engine='parent',
        fuzz_target_name='parent_child',
        job='test_job',
        last_run=datetime.datetime.utcnow()).put()

    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.write_data',
    ])

  def test_upload_testcase_run(self):
    """Tests uploading of TestcaseRun."""
    testcase_run_0 = fuzzer_stats.TestcaseRun('fuzzer', 'job', 123,
                                              1472846341.017923)
    testcase_run_1 = fuzzer_stats.TestcaseRun('fuzzer', 'job', 123,
                                              1472846341.017923)

    testcase_run_0['stat'] = 1000
    testcase_run_1['stat'] = 2000

    fuzzer_stats.upload_stats(
        [testcase_run_0, testcase_run_1], filename='upload.json')

    self.mock.write_data.assert_called_once_with(
        b'{"fuzzer": "fuzzer", "job": "job", "build_revision": 123, '
        b'"timestamp": 1472846341.017923, "kind": "TestcaseRun", '
        b'"stat": 1000}\n'
        b'{"fuzzer": "fuzzer", "job": "job", "build_revision": 123, '
        b'"timestamp": 1472846341.017923, "kind": "TestcaseRun", '
        b'"stat": 2000}',
        'gs://test-bigquery-bucket/fuzzer/TestcaseRun/date/20160902/upload.json'
    )

  def tests_upload_testcase_run_with_source(self):
    """Test uploading testcase run with source."""
    os.environ['STATS_SOURCE'] = 'custom_source'
    testcase_run = fuzzer_stats.TestcaseRun('fuzzer', 'job', 123,
                                            1472846341.017923)
    fuzzer_stats.upload_stats([testcase_run], filename='upload.json')
    self.mock.write_data.assert_called_once_with(
        b'{"fuzzer": "fuzzer", "job": "job", "build_revision": 123, '
        b'"timestamp": 1472846341.017923, "kind": "TestcaseRun", '
        b'"source": "custom_source"}',
        'gs://test-bigquery-bucket/fuzzer/TestcaseRun/date/20160902/upload.json'
    )

  def test_upload_testcase_run_child(self):
    """Tests uploading of Testcaserun for a child fuzzer."""
    testcase_run_0 = fuzzer_stats.TestcaseRun('parent_child', 'job', 123,
                                              1472846341.017923)
    testcase_run_0['stat'] = 1000

    fuzzer_stats.upload_stats([testcase_run_0], filename='upload.json')
    self.mock.write_data.assert_called_once_with(
        b'{"fuzzer": "parent_child", "job": "job", "build_revision": 123, '
        b'"timestamp": 1472846341.017923, "kind": "TestcaseRun", '
        b'"stat": 1000}',
        'gs://test-bigquery-bucket/parent/TestcaseRun/date/20160902/upload.json'
    )

  def test_upload_testcase_run_2_days(self):
    """Tests uploading TestcaseRuns that span multiple days."""
    testcase_run_0 = fuzzer_stats.TestcaseRun('fuzzer', 'job', 123,
                                              1472846341.017923)
    testcase_run_1 = fuzzer_stats.TestcaseRun('fuzzer', 'job', 123,
                                              1472846345.017923)
    testcase_run_2 = fuzzer_stats.TestcaseRun('fuzzer', 'job', 123,
                                              1472932741.017923)
    testcase_run_3 = fuzzer_stats.TestcaseRun('fuzzer', 'job', 123,
                                              1472932745.017923)
    testcase_run_0['stat'] = 1000
    testcase_run_1['stat'] = 2000
    testcase_run_2['stat'] = 3000
    testcase_run_3['stat'] = 4000

    fuzzer_stats.upload_stats(
        [testcase_run_0, testcase_run_1, testcase_run_2, testcase_run_3],
        filename='upload.json')

    expected_calls = [
        mock.call(
            b'{"fuzzer": "fuzzer", "job": "job", "build_revision": 123, '
            b'"timestamp": 1472846341.017923, "kind": "TestcaseRun", '
            b'"stat": 1000}\n'
            b'{"fuzzer": "fuzzer", "job": "job", "build_revision": 123, '
            b'"timestamp": 1472846345.017923, "kind": "TestcaseRun", '
            b'"stat": 2000}',
            'gs://test-bigquery-bucket/fuzzer/TestcaseRun/date/20160902/'
            'upload.json'),
        mock.call(
            b'{"fuzzer": "fuzzer", "job": "job", "build_revision": 123, '
            b'"timestamp": 1472932741.017923, "kind": "TestcaseRun", '
            b'"stat": 3000}\n'
            b'{"fuzzer": "fuzzer", "job": "job", "build_revision": 123, '
            b'"timestamp": 1472932745.017923, "kind": "TestcaseRun", '
            b'"stat": 4000}',
            'gs://test-bigquery-bucket/fuzzer/TestcaseRun/date/20160903/'
            'upload.json'),
    ]

    six.assertCountEqual(self, self.mock.write_data.call_args_list,
                         expected_calls)

  def test_upload_job_run(self):
    """Tests uploading of JobRun."""
    crashes = [{
        'is_new': False,
        'count': 2,
        'crash_type': 't1',
        'crash_state': 's1',
        'security_flag': True
    }]
    fuzzer_run = fuzzer_stats.JobRun('fuzzer', 'job', 123, 1472846341.017923,
                                     9001, 0, 1, crashes)

    fuzzer_stats.upload_stats([fuzzer_run], filename='upload.json')

    self.assertEqual(1, self.mock.write_data.call_count)
    self.assertEqual({
        'kind': 'JobRun',
        'known_crashes': 1,
        'timestamp': 1472846341.017923,
        'job': 'job',
        'fuzzer': 'fuzzer',
        'new_crashes': 0,
        'build_revision': 123,
        'testcases_executed': 9001,
        'crashes': crashes
    }, json.loads(self.mock.write_data.call_args[0][0]))

    self.assertEqual(
        'gs://test-bigquery-bucket/fuzzer/JobRun/date/20160902/upload.json',
        self.mock.write_data.call_args[0][1])

  @mock.patch('os.path.exists')
  def test_testcase_run_read_from_disk(self, mock_path_exists):
    """Tests TestcaseRun deserialization."""
    read_data = ('{"stat": 1000, "timestamp": 1472846341.017923, '
                 '"kind": "TestcaseRun", "job": "job", "fuzzer": "fuzzer", '
                 '"build_revision": 123}')

    mock_path_exists.return_value = True
    m = mock.mock_open(read_data=read_data)
    with mock.patch('clusterfuzz._internal.metrics.fuzzer_stats.open', m):
      testcase_run = fuzzer_stats.TestcaseRun.read_from_disk('fake_path')

    self.assertIsNotNone(testcase_run)
    self.assertEqual(testcase_run.kind, 'TestcaseRun')
    self.assertEqual(testcase_run.fuzzer, 'fuzzer')
    self.assertEqual(testcase_run.job, 'job')
    self.assertEqual(testcase_run.build_revision, 123)
    self.assertEqual(testcase_run.timestamp, 1472846341.017923)
    self.assertEqual(testcase_run['stat'], 1000)

  def test_testcase_run_write_to_disk(self):
    """Tests TestcaseRun serialization."""
    testcase_run = fuzzer_stats.TestcaseRun('fuzzer', 'job', 123,
                                            1472846341.017923)

    m = mock.mock_open()
    with mock.patch('clusterfuzz._internal.metrics.fuzzer_stats.open', m):
      fuzzer_stats.TestcaseRun.write_to_disk(testcase_run, 'fake_path')

    handle = m()
    handle.write.assert_called_once_with(
        '{"fuzzer": "fuzzer", "job": "job", "build_revision": 123, '
        '"timestamp": 1472846341.017923, "kind": "TestcaseRun"}')

  def test_job_run_from_json(self):
    """Tests JobRun deserialization."""
    data = json.dumps({
        'kind': 'JobRun',
        'known_crashes': 1,
        'timestamp': 1472846341.017923,
        'job': 'job',
        'fuzzer': 'fuzzer',
        'new_crashes': 0,
        'build_revision': 123,
        'testcases_executed': 9001,
        'crashes': [{
            'test': 'crash'
        }]
    })
    job_run = fuzzer_stats.BaseRun.from_json(data)
    self.assertIsNotNone(job_run)
    self.assertEqual(job_run.kind, 'JobRun')
    self.assertEqual(job_run.fuzzer, 'fuzzer')
    self.assertEqual(job_run.job, 'job')
    self.assertEqual(job_run.build_revision, 123)
    self.assertEqual(job_run.timestamp, 1472846341.017923)
    self.assertEqual(job_run['new_crashes'], 0)
    self.assertEqual(job_run['known_crashes'], 1)
    self.assertEqual(job_run['testcases_executed'], 9001)
    self.assertEqual(job_run['crashes'], [{'test': 'crash'}])

  @mock.patch(
      'clusterfuzz._internal.metrics.fuzzer_stats.TestcaseRun.read_from_disk')
  def test_fuzz_task_upload_testcase_run_stats_builtin_fuzzer(
      self, mock_read_from_disk_new):
    """Tests that fuzz_task.read_and_upload_testcase_run_stats uploads stats."""
    testcase_run = fuzzer_stats.TestcaseRun('placeholder', 'placeholder', 0,
                                            1472846341.017923)
    testcase_run['stat'] = 9001

    mock_read_from_disk_new.return_value = testcase_run
    fuzz_task.read_and_upload_testcase_run_stats(
        'libFuzzer', 'libFuzzer_fuzzer1', 'job', 123, ['fake_path'])

    self.assertEqual(1, self.mock.write_data.call_count)

    self.assertEqual(
        b'{"fuzzer": "libFuzzer_fuzzer1", "job": "job", "build_revision": 123, '
        b'"timestamp": 1472846341.017923, "kind": "TestcaseRun", "stat": 9001}',
        self.mock.write_data.call_args[0][0])

  @mock.patch(
      'clusterfuzz._internal.metrics.fuzzer_stats.TestcaseRun.read_from_disk')
  def test_fuzz_task_upload_testcase_run_stats_blackbox_fuzzer(
      self, mock_read_from_disk_new):
    """Tests that fuzz_task.read_and_upload_testcase_run_stats uploads stats."""
    testcase_run = fuzzer_stats.TestcaseRun('placeholder', 'placeholder', 0,
                                            1472846341.017923)
    testcase_run['stat'] = 9001

    mock_read_from_disk_new.return_value = testcase_run
    fuzz_task.read_and_upload_testcase_run_stats(
        'blackbox_fuzzer', 'blackbox_fuzzer', 'job', 123, ['fake_path'])

    self.assertEqual(0, self.mock.write_data.call_count)

  def test_fuzz_task_upload_job_run_stats(self):
    """Tests that fuzz_task.upload_job_run_stats uploads stats."""
    groups = [
        mock.Mock(
            crashes=[mock.Mock(), mock.Mock()],
            main_crash=mock.Mock(
                crash_type='t1', crash_state='s1', security_flag=True)),
        mock.Mock(
            crashes=[mock.Mock()],
            main_crash=mock.Mock(
                crash_type='t2', crash_state='s2', security_flag=False)),
    ]
    groups[0].is_new.return_value = False
    groups[1].is_new.return_value = True

    fuzz_task.upload_job_run_stats('fuzzer', 'job', 123, 1472846341.017923, 1,
                                   2, 1337, groups)
    self.assertEqual(1, self.mock.write_data.call_count)
    self.assertEqual({
        'kind':
            'JobRun',
        'known_crashes':
            2,
        'timestamp':
            1472846341.017923,
        'job':
            'job',
        'fuzzer':
            'fuzzer',
        'new_crashes':
            1,
        'build_revision':
            123,
        'testcases_executed':
            1337,
        'crashes': [
            {
                'is_new': False,
                'count': 2,
                'crash_type': 't1',
                'crash_state': 's1',
                'security_flag': True
            },
            {
                'is_new': True,
                'count': 1,
                'crash_type': 't2',
                'crash_state': 's2',
                'security_flag': False
            },
        ]
    }, json.loads(self.mock.write_data.call_args[0][0]))


@test_utils.with_cloud_emulators('datastore')
class BigQueryStatsTests(unittest.TestCase):
  """BigQuery stats tests."""

  def setUp(self):
    data_types.Fuzzer(name='parent').put()

    data_types.FuzzTarget(engine='parent', binary='child').put()
    data_types.FuzzTargetJob(
        engine='parent',
        fuzz_target_name='parent_child',
        job='test_job',
        last_run=datetime.datetime.utcnow()).put()

  def test_parse_stats_column_fields(self):
    """Tests stats column parsing."""
    fields = fuzzer_stats.parse_stats_column_fields(
        'sum(t.abc), avg(j.abc) as bcd, custom(j.def) as def,  '
        '_EDGE_COV, _FUNC_COV as 123,\n'
        '_COV_REPORT as blahblah, _CORPUS_SIZE as corpus_size, '
        '_CORPUS_BACKUP as corpus_backup')

    self.assertEqual(len(fields), 8)

    self.assertIsInstance(fields[0], fuzzer_stats.QueryField)
    self.assertEqual(fields[0].aggregate_function, 'sum')
    self.assertFalse(fields[0].is_custom())
    self.assertEqual(fields[0].name, 'abc')
    self.assertEqual(fields[0].table_alias, 't')
    # select_alias is defauled to name.
    self.assertEqual(fields[0].select_alias, 'abc')

    self.assertIsInstance(fields[1], fuzzer_stats.QueryField)
    self.assertEqual(fields[1].aggregate_function, 'avg')
    self.assertFalse(fields[1].is_custom())
    self.assertEqual(fields[1].name, 'abc')
    self.assertEqual(fields[1].table_alias, 'j')
    self.assertEqual(fields[1].select_alias, 'bcd')

    self.assertIsInstance(fields[2], fuzzer_stats.QueryField)
    self.assertEqual(fields[2].aggregate_function, 'custom')
    self.assertTrue(fields[2].is_custom())
    self.assertEqual(fields[2].name, 'def')
    self.assertEqual(fields[2].table_alias, 'j')
    self.assertEqual(fields[2].select_alias, 'def')

    self.assertIsInstance(fields[3], fuzzer_stats.BuiltinFieldSpecifier)
    self.assertEqual(fields[3].name, '_EDGE_COV')
    self.assertEqual(fields[3].field_class(), fuzzer_stats.CoverageField)
    self.assertIsNone(fields[3].alias)

    self.assertIsInstance(fields[4], fuzzer_stats.BuiltinFieldSpecifier)
    self.assertEqual(fields[4].name, '_FUNC_COV')
    self.assertEqual(fields[4].field_class(), fuzzer_stats.CoverageField)
    self.assertEqual(fields[4].alias, '123')

    self.assertIsInstance(fields[5], fuzzer_stats.BuiltinFieldSpecifier)
    self.assertEqual(fields[5].name, '_COV_REPORT')
    self.assertEqual(fields[5].field_class(), fuzzer_stats.CoverageReportField)
    self.assertEqual(fields[5].alias, 'blahblah')

    self.assertIsInstance(fields[6], fuzzer_stats.BuiltinFieldSpecifier)
    self.assertEqual(fields[6].name, '_CORPUS_SIZE')
    self.assertEqual(fields[6].field_class(), fuzzer_stats.CorpusSizeField)
    self.assertEqual(fields[6].alias, 'corpus_size')

    self.assertIsInstance(fields[7], fuzzer_stats.BuiltinFieldSpecifier)
    self.assertEqual(fields[7].name, '_CORPUS_BACKUP')
    self.assertEqual(fields[7].field_class(), fuzzer_stats.CorpusBackupField)
    self.assertEqual(fields[7].alias, 'corpus_backup')

    # Test that invalid fields are ignored.
    fields = fuzzer_stats.parse_stats_column_fields(
        'sum(abc)  ,   min(t.bcd)    as bcd   , '
        'sum(t.def) as "1, _EDGE_COV as ""1"')
    self.assertEqual(len(fields), 1)
    self.assertIsInstance(fields[0], fuzzer_stats.QueryField)
    self.assertEqual(fields[0].aggregate_function, 'min')
    self.assertEqual(fields[0].name, 'bcd')
    self.assertEqual(fields[0].table_alias, 't')
    self.assertEqual(fields[0].select_alias, 'bcd')

  def test_query_job_day(self):
    """Tests querying for JobRuns grouped by day."""
    fields = fuzzer_stats.parse_stats_column_fields(
        fuzzer_stats.JobQuery.DEFAULT_FIELDS)
    query = fuzzer_stats.JobQuery('fuzzer_name', ['job_type', 'job_type2'],
                                  fields,
                                  fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                                  datetime.date(2016, 10, 1),
                                  datetime.date(2016, 10, 7))

    self.assertEqual(
        sanitize_sql(query.build()),
        sanitize_sql("""
        WITH
          JobRunWithConcatedCrashes AS (
            SELECT
              TIMESTAMP_TRUNC(
                TIMESTAMP_SECONDS(CAST(timestamp AS INT64)), DAY, "UTC"
              ) as date,
              sum(testcases_executed) as testcases_executed,
              ARRAY_CONCAT_AGG(crashes) AS crashes
            FROM
              `test-clusterfuzz`.fuzzer_name_stats.JobRun
            WHERE
              (
                _PARTITIONTIME BETWEEN
                TIMESTAMP_SECONDS(1475280000) AND TIMESTAMP_SECONDS(1475798400)
              ) AND (
                job = \'job_type\' OR job = \'job_type2\'
              )
            GROUP BY date
          ),
          JobRunWithUniqueCrashes AS (
            SELECT
              * EXCEPT(crashes),
              ARRAY(
                SELECT AS STRUCT
                  crash.crash_type,
                  crash.crash_state,
                  crash.security_flag,
                  SUM(count) AS count,
                  MAX(crash.is_new) AS is_new
                FROM
                  UNNEST(crashes) AS crash
                GROUP BY
                  crash.crash_type,
                  crash.crash_state,
                  crash.security_flag
              ) AS crashes
            FROM
              JobRunWithConcatedCrashes
          ),
          JobRunWithSummary AS (
            SELECT
              * EXCEPT(crashes),
              (
                SELECT AS STRUCT
                  IFNULL(SUM(crash.count), 0) AS total,
                  COUNTIF(crash.is_new) AS unique_new,
                  COUNT(crash) AS unique
                FROM
                  UNNEST(crashes) AS crash
              ) AS crash_count
            FROM
              JobRunWithUniqueCrashes
          )

        SELECT
          * EXCEPT(crash_count),
          crash_count.total AS total_crashes,
          crash_count.unique_new AS new_crashes,
          (crash_count.unique - crash_count.unique_new) AS known_crashes
        FROM
          JobRunWithSummary
        """))

  def test_query_job_revision(self):
    """Tests querying for JobRuns grouped by revision."""
    fields = fuzzer_stats.parse_stats_column_fields(
        fuzzer_stats.JobQuery.DEFAULT_FIELDS)
    query = fuzzer_stats.JobQuery('fuzzer_name', ['job_type', 'job_type2'],
                                  fields,
                                  fuzzer_stats.QueryGroupBy.GROUP_BY_REVISION,
                                  datetime.date(2016, 10, 1),
                                  datetime.date(2016, 10, 7))

    self.assertEqual(
        sanitize_sql(query.build()),
        sanitize_sql("""
        WITH
          JobRunWithConcatedCrashes AS (
            SELECT
              build_revision,
              sum(testcases_executed) as testcases_executed,
              ARRAY_CONCAT_AGG(crashes) AS crashes
            FROM
              `test-clusterfuzz`.fuzzer_name_stats.JobRun
            WHERE
              (
                _PARTITIONTIME BETWEEN
                TIMESTAMP_SECONDS(1475280000) AND TIMESTAMP_SECONDS(1475798400)
              ) AND (
                job = \'job_type\' OR job = \'job_type2\'
              )
            GROUP BY build_revision
          ),
          JobRunWithUniqueCrashes AS (
            SELECT
              * EXCEPT(crashes),
              ARRAY(
                SELECT AS STRUCT
                  crash.crash_type,
                  crash.crash_state,
                  crash.security_flag,
                  SUM(count) AS count,
                  MAX(crash.is_new) AS is_new
                FROM
                  UNNEST(crashes) AS crash
                GROUP BY
                  crash.crash_type,
                  crash.crash_state,
                  crash.security_flag
              ) AS crashes
            FROM
              JobRunWithConcatedCrashes
          ),
          JobRunWithSummary AS (
            SELECT
              * EXCEPT(crashes),
              (
                SELECT AS STRUCT
                  IFNULL(SUM(crash.count), 0) AS total,
                  COUNTIF(crash.is_new) AS unique_new,
                  COUNT(crash) AS unique
                FROM
                  UNNEST(crashes) AS crash
              ) AS crash_count
            FROM
              JobRunWithUniqueCrashes
          )

        SELECT
          * EXCEPT(crash_count),
          crash_count.total AS total_crashes,
          crash_count.unique_new AS new_crashes,
          (crash_count.unique - crash_count.unique_new) AS known_crashes
        FROM
          JobRunWithSummary
        """))

  def test_query_job_fuzzer(self):
    """Tests querying for JobRuns grouped by fuzzer."""
    fields = fuzzer_stats.parse_stats_column_fields(
        fuzzer_stats.JobQuery.DEFAULT_FIELDS)
    query = fuzzer_stats.JobQuery('fuzzer_name', ['job_type', 'job_type2'],
                                  fields,
                                  fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                                  datetime.date(2016, 10, 1),
                                  datetime.date(2016, 10, 7))

    self.assertEqual(
        sanitize_sql(query.build()),
        sanitize_sql("""
        WITH
          JobRunWithConcatedCrashes AS (
            SELECT
              fuzzer,
              sum(testcases_executed) as testcases_executed,
              ARRAY_CONCAT_AGG(crashes) AS crashes
            FROM
              `test-clusterfuzz`.fuzzer_name_stats.JobRun
            WHERE
              (
                _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000)
                AND TIMESTAMP_SECONDS(1475798400)
              ) AND (
                job = \'job_type\' OR job = \'job_type2\'
              )
            GROUP BY fuzzer
          ),
          JobRunWithUniqueCrashes AS (
            SELECT
              * EXCEPT(crashes),
              ARRAY(
                SELECT AS STRUCT
                  crash.crash_type,
                  crash.crash_state,
                  crash.security_flag,
                  SUM(count) AS count,
                  MAX(crash.is_new) AS is_new
                FROM
                  UNNEST(crashes) AS crash
                GROUP BY
                  crash.crash_type,
                  crash.crash_state,
                  crash.security_flag
              ) AS crashes
            FROM
              JobRunWithConcatedCrashes
          ),
          JobRunWithSummary AS (
            SELECT
              * EXCEPT(crashes),
              (
                SELECT AS STRUCT
                  IFNULL(SUM(crash.count), 0) AS total,
                  COUNTIF(crash.is_new) AS unique_new,
                  COUNT(crash) AS unique
                FROM
                  UNNEST(crashes) AS crash
              ) AS crash_count
            FROM
              JobRunWithUniqueCrashes
          )

        SELECT
          * EXCEPT(crash_count),
          crash_count.total AS total_crashes,
          crash_count.unique_new AS new_crashes,
          (crash_count.unique - crash_count.unique_new) AS known_crashes
        FROM
          JobRunWithSummary
        """))

  def test_table_query_join(self):
    """Tests basic table query involving a join."""
    stats_columns = """
      sum(j.testcases_executed) as testcases_executed,
      custom(j.total_crashes) as total_crashes,
      custom(j.new_crashes) as new_crashes,
      custom(j.known_crashes) as known_crashes,
      avg(t.average_exec_per_sec) as average_exec_per_sec
    """

    query = fuzzer_stats.TableQuery('fuzzer_name', ['job_type', 'job_type2'],
                                    stats_columns,
                                    fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                                    datetime.date(2016, 10, 1),
                                    datetime.date(2016, 10, 7))
    self.assertEqual(
        sanitize_sql(query.build()),
        sanitize_sql("""
        SELECT j.date, * EXCEPT(date) FROM (
          WITH
            JobRunWithConcatedCrashes AS (
              SELECT
                TIMESTAMP_TRUNC(
                  TIMESTAMP_SECONDS(CAST(timestamp AS INT64)), DAY, "UTC"
                ) as date,
                sum(testcases_executed) as testcases_executed,
                ARRAY_CONCAT_AGG(crashes) AS crashes
              FROM
                `test-clusterfuzz`.fuzzer_name_stats.JobRun
              WHERE
                (
                  _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000)
                  AND TIMESTAMP_SECONDS(1475798400)
                ) AND (
                  job = \'job_type\' OR job = \'job_type2\'
                )
              GROUP BY date
            ),
            JobRunWithUniqueCrashes AS (
              SELECT
                * EXCEPT(crashes),
                ARRAY(
                  SELECT AS STRUCT
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag,
                    SUM(count) AS count,
                    MAX(crash.is_new) AS is_new
                  FROM
                    UNNEST(crashes) AS crash
                  GROUP BY
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag
                ) AS crashes
              FROM
                JobRunWithConcatedCrashes
            ),
            JobRunWithSummary AS (
              SELECT
                * EXCEPT(crashes),
                (
                  SELECT AS STRUCT
                    IFNULL(SUM(crash.count), 0) AS total,
                    COUNTIF(crash.is_new) AS unique_new,
                    COUNT(crash) AS unique
                  FROM
                    UNNEST(crashes) AS crash
                ) AS crash_count
              FROM
                JobRunWithUniqueCrashes
            )

          SELECT
            * EXCEPT(crash_count),
            crash_count.total AS total_crashes,
            crash_count.unique_new AS new_crashes,
            (crash_count.unique - crash_count.unique_new) AS known_crashes
          FROM
            JobRunWithSummary
        ) as j INNER JOIN (
          SELECT
            TIMESTAMP_TRUNC(
              TIMESTAMP_SECONDS(CAST(timestamp AS INT64)), DAY, "UTC"
            ) as date,
            avg(average_exec_per_sec) as average_exec_per_sec
          FROM `test-clusterfuzz`.fuzzer_name_stats.TestcaseRun
          WHERE
            (
              _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000) AND
              TIMESTAMP_SECONDS(1475798400)
            ) AND (
              job = 'job_type' OR job = 'job_type2'
            )
          GROUP BY date
        ) as t ON j.date = t.date
        """))

  def test_table_query_single(self):
    """Tests basic table query involving single subquery."""
    stats_columns = """
      sum(j.testcases_executed) as testcases_executed,
      custom(j.total_crashes) as total_crashes,
      custom(j.new_crashes) as new_crashes,
      custom(j.known_crashes) as known_crashes
    """

    query = fuzzer_stats.TableQuery('fuzzer_name', ['job_type'], stats_columns,
                                    fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                                    datetime.date(2016, 10, 1),
                                    datetime.date(2016, 10, 7))

    self.assertEqual(
        sanitize_sql(query.build()),
        sanitize_sql("""
        SELECT j.date, * EXCEPT(date) FROM (
          WITH
            JobRunWithConcatedCrashes AS (
              SELECT
                TIMESTAMP_TRUNC(
                  TIMESTAMP_SECONDS(CAST(timestamp AS INT64)), DAY, "UTC"
                ) as date,
                sum(testcases_executed) as testcases_executed,
                ARRAY_CONCAT_AGG(crashes) AS crashes
              FROM
                `test-clusterfuzz`.fuzzer_name_stats.JobRun
              WHERE
                (
                  _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000) AND
                  TIMESTAMP_SECONDS(1475798400)
                ) AND (
                  job = \'job_type\'
                )
              GROUP BY date
            ),
            JobRunWithUniqueCrashes AS (
              SELECT
                * EXCEPT(crashes),
                ARRAY(
                  SELECT AS STRUCT
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag,
                    SUM(count) AS count,
                    MAX(crash.is_new) AS is_new
                  FROM
                    UNNEST(crashes) AS crash
                  GROUP BY
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag
                ) AS crashes
              FROM
                JobRunWithConcatedCrashes
            ),
            JobRunWithSummary AS (
              SELECT
                * EXCEPT(crashes),
                (
                  SELECT AS STRUCT
                    IFNULL(SUM(crash.count), 0) AS total,
                    COUNTIF(crash.is_new) AS unique_new,
                    COUNT(crash) AS unique
                  FROM
                    UNNEST(crashes) AS crash
                ) AS crash_count
              FROM
                JobRunWithUniqueCrashes
            )

          SELECT
            * EXCEPT(crash_count),
            crash_count.total AS total_crashes,
            crash_count.unique_new AS new_crashes,
            (crash_count.unique - crash_count.unique_new) AS known_crashes
          FROM
            JobRunWithSummary
        ) as j
        """))

  def test_table_query_group_fuzzer(self):
    """Tests table query grouping by fuzzer."""
    stats_columns = """
      sum(j.testcases_executed) as testcases_executed,
      custom(j.total_crashes) as total_crashes,
      custom(j.new_crashes) as new_crashes,
      custom(j.known_crashes) as known_crashes,
      avg(t.average_exec_per_sec) as average_exec_per_sec
    """

    query = fuzzer_stats.TableQuery('parent_child', ['test_job', 'test_job2'],
                                    stats_columns,
                                    fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                                    datetime.date(2016, 10, 1),
                                    datetime.date(2016, 10, 7))
    self.assertEqual(
        sanitize_sql(query.build()),
        sanitize_sql("""
        SELECT j.fuzzer, * EXCEPT(fuzzer) FROM (
          WITH
            JobRunWithConcatedCrashes AS (
              SELECT
                fuzzer,
                sum(testcases_executed) as testcases_executed,
                ARRAY_CONCAT_AGG(crashes) AS crashes
              FROM
                `test-clusterfuzz`.parent_stats.JobRun
              WHERE
                (
                  _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000) AND
                  TIMESTAMP_SECONDS(1475798400)
                ) AND (
                  job = \'test_job\' OR job = \'test_job2\'
                )
                AND fuzzer = \'parent_child\'
              GROUP BY fuzzer
            ),
            JobRunWithUniqueCrashes AS (
              SELECT
                * EXCEPT(crashes),
                ARRAY(
                  SELECT AS STRUCT
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag,
                    SUM(count) AS count,
                    MAX(crash.is_new) AS is_new
                  FROM
                    UNNEST(crashes) AS crash
                  GROUP BY
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag
                ) AS crashes
              FROM
                JobRunWithConcatedCrashes
            ),
            JobRunWithSummary AS (
              SELECT
                * EXCEPT(crashes),
                (
                  SELECT AS STRUCT
                    IFNULL(SUM(crash.count), 0) AS total,
                    COUNTIF(crash.is_new) AS unique_new,
                    COUNT(crash) AS unique
                  FROM
                    UNNEST(crashes) AS crash
                ) AS crash_count
              FROM
                JobRunWithUniqueCrashes
            )

          SELECT
            * EXCEPT(crash_count),
            crash_count.total AS total_crashes,
            crash_count.unique_new AS new_crashes,
            (crash_count.unique - crash_count.unique_new) AS known_crashes
          FROM
            JobRunWithSummary
        ) as j INNER JOIN (
          SELECT
            fuzzer,
            avg(average_exec_per_sec) as average_exec_per_sec
          FROM `test-clusterfuzz`.parent_stats.TestcaseRun
          WHERE
            (
              _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000) AND
              TIMESTAMP_SECONDS(1475798400)
            ) AND (
              job = \'test_job\' OR job = \'test_job2\'
            ) AND fuzzer = \'parent_child\'
          GROUP BY fuzzer
        ) as t ON j.fuzzer = t.fuzzer
        """))

    # Don't specify a job.
    query = fuzzer_stats.TableQuery('parent_child', None, stats_columns,
                                    fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                                    datetime.date(2016, 10, 1),
                                    datetime.date(2016, 10, 7))
    self.assertEqual(
        sanitize_sql(query.build()),
        sanitize_sql("""
        SELECT j.fuzzer, * EXCEPT(fuzzer) FROM (
          WITH
            JobRunWithConcatedCrashes AS (
              SELECT
                fuzzer,
                sum(testcases_executed) as testcases_executed,
                ARRAY_CONCAT_AGG(crashes) AS crashes
              FROM
                `test-clusterfuzz`.parent_stats.JobRun
              WHERE
                (
                  _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000) AND
                  TIMESTAMP_SECONDS(1475798400)
                )
                AND fuzzer = \'parent_child\'
              GROUP BY fuzzer
            ),
            JobRunWithUniqueCrashes AS (
              SELECT
                * EXCEPT(crashes),
                ARRAY(
                  SELECT AS STRUCT
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag,
                    SUM(count) AS count,
                    MAX(crash.is_new) AS is_new
                  FROM
                    UNNEST(crashes) AS crash
                  GROUP BY
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag
                ) AS crashes
              FROM
                JobRunWithConcatedCrashes
            ),
            JobRunWithSummary AS (
              SELECT
                * EXCEPT(crashes),
                (
                  SELECT AS STRUCT
                    IFNULL(SUM(crash.count), 0) AS total,
                    COUNTIF(crash.is_new) AS unique_new,
                    COUNT(crash) AS unique
                  FROM
                    UNNEST(crashes) AS crash
                ) AS crash_count
              FROM
                JobRunWithUniqueCrashes
            )

          SELECT
            * EXCEPT(crash_count),
            crash_count.total AS total_crashes,
            crash_count.unique_new AS new_crashes,
            (crash_count.unique - crash_count.unique_new) AS known_crashes
          FROM
            JobRunWithSummary
        ) as j INNER JOIN (
          SELECT
            fuzzer,
            avg(average_exec_per_sec) as average_exec_per_sec
          FROM `test-clusterfuzz`.parent_stats.TestcaseRun
          WHERE
            (
              _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000) AND
              TIMESTAMP_SECONDS(1475798400)
            )
            AND fuzzer = \'parent_child\'
          GROUP BY fuzzer
        ) as t ON j.fuzzer = t.fuzzer
        """))

  def test_table_query_group_job(self):
    """Tests grouping by job."""
    stats_columns = """
      sum(j.testcases_executed) as testcases_executed,
      custom(j.total_crashes) as total_crashes,
      custom(j.new_crashes) as new_crashes,
      custom(j.known_crashes) as known_crashes,
      avg(t.average_exec_per_sec) as average_exec_per_sec
    """

    query = fuzzer_stats.TableQuery('parent_child', None, stats_columns,
                                    fuzzer_stats.QueryGroupBy.GROUP_BY_JOB,
                                    datetime.date(2016, 10, 1),
                                    datetime.date(2016, 10, 7))
    self.assertEqual(
        sanitize_sql(query.build()),
        sanitize_sql("""
        SELECT j.job, * EXCEPT(job) FROM (
          WITH
            JobRunWithConcatedCrashes AS (
              SELECT
                job,
                sum(testcases_executed) as testcases_executed,
                ARRAY_CONCAT_AGG(crashes) AS crashes
              FROM
                `test-clusterfuzz`.parent_stats.JobRun
              WHERE
                (
                  _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000) AND
                  TIMESTAMP_SECONDS(1475798400)
                )
                AND fuzzer = \'parent_child\'
              GROUP BY job
            ),
            JobRunWithUniqueCrashes AS (
              SELECT
                * EXCEPT(crashes),
                ARRAY(
                  SELECT AS STRUCT
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag,
                    SUM(count) AS count,
                    MAX(crash.is_new) AS is_new
                  FROM
                    UNNEST(crashes) AS crash
                  GROUP BY
                    crash.crash_type,
                    crash.crash_state,
                    crash.security_flag
                ) AS crashes
              FROM
                JobRunWithConcatedCrashes
            ),
            JobRunWithSummary AS (
              SELECT
                * EXCEPT(crashes),
                (
                  SELECT AS STRUCT
                    IFNULL(SUM(crash.count), 0) AS total,
                    COUNTIF(crash.is_new) AS unique_new,
                    COUNT(crash) AS unique
                  FROM
                    UNNEST(crashes) AS crash
                ) AS crash_count
              FROM
                JobRunWithUniqueCrashes
            )

          SELECT
            * EXCEPT(crash_count),
            crash_count.total AS total_crashes,
            crash_count.unique_new AS new_crashes,
            (crash_count.unique - crash_count.unique_new) AS known_crashes
          FROM
            JobRunWithSummary
        ) as j INNER JOIN (
          SELECT
            job,
            avg(average_exec_per_sec) as average_exec_per_sec
          FROM `test-clusterfuzz`.parent_stats.TestcaseRun
          WHERE
            (
              _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000) AND
              TIMESTAMP_SECONDS(1475798400)
            ) AND
            fuzzer = \'parent_child\'
          GROUP BY job
        ) as t ON j.job = t.job
        """))

  def test_table_query_group_time(self):
    """Tests table query grouping by fuzzer."""
    stats_columns = """
      sum(j.testcases_executed) as testcases_executed,
      custom(j.total_crashes) as total_crashes,
      custom(j.new_crashes) as new_crashes,
      custom(j.known_crashes) as known_crashes,
      avg(t.average_exec_per_sec) as average_exec_per_sec
    """

    query = fuzzer_stats.TableQuery('parent_child', ['test_job', 'test_job2'],
                                    stats_columns,
                                    fuzzer_stats.QueryGroupBy.GROUP_BY_TIME,
                                    datetime.date(2016, 10, 1),
                                    datetime.date(2016, 10, 7))
    self.assertEqual(
        sanitize_sql(query.build()),
        sanitize_sql("""
        SELECT
          t.time, * EXCEPT(time)
        FROM
          (
            SELECT
              TIMESTAMP_SECONDS(
                CAST(timestamp AS INT64)
              ) as time,
              avg(average_exec_per_sec) as average_exec_per_sec
            FROM `test-clusterfuzz`.parent_stats.TestcaseRun
            WHERE
              (
                _PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(1475280000) AND
                TIMESTAMP_SECONDS(1475798400)
              ) AND
              (
                job = \'test_job\' OR job = \'test_job2\'
              ) AND
                fuzzer = \'parent_child\'
              GROUP BY time
            ) as t
        """))

  def test_query_invalid_names(self):
    """Tests passing invalid fuzzer/job names."""
    stats_columns = ('sum(j.testcases_executed) as testcases_executed, '
                     'sum(j.new_crashes) as new_crashes, '
                     'sum(j.known_crashes) as known_crashes, '
                     'avg(t.average_exec_per_sec) as average_exec_per_sec ')

    with self.assertRaises(fuzzer_stats.FuzzerStatsException):
      fuzzer_stats.TableQuery('fuzzer_n\'ame$', ['job_type'], stats_columns,
                              fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                              datetime.date(2016, 10, 1),
                              datetime.date(2016, 10, 7))


@test_utils.with_cloud_emulators('datastore')
class BuiltinFieldTests(unittest.TestCase):
  """Builtin field tests."""

  def setUp(self):
    self.today = datetime.datetime.utcnow().date()
    self.yesterday = self.today - datetime.timedelta(days=1)
    cov_info = data_types.CoverageInformation(
        fuzzer='fuzzer1', date=self.yesterday)
    cov_info.edges_covered = 11
    cov_info.edges_total = 30
    cov_info.functions_covered = 10
    cov_info.functions_total = 15
    cov_info.html_report_url = 'https://report_for_fuzzer1/{}'.format(
        data_types.coverage_information_date_to_string(self.yesterday))
    cov_info.corpus_size_units = 20
    cov_info.corpus_size_bytes = 200
    cov_info.quarantine_size_units = 5
    cov_info.quarantine_size_bytes = 50
    cov_info.corpus_location = 'gs://corpus'
    cov_info.corpus_backup_location = 'gs://corpus-backup/file.zip'
    cov_info.quarantine_location = 'gs://quarantine'
    cov_info.put()

    cov_info = data_types.CoverageInformation(fuzzer='fuzzer2', date=self.today)
    cov_info.edges_covered = 16
    cov_info.edges_total = 33
    cov_info.functions_covered = 58
    cov_info.functions_total = 90
    cov_info.html_report_url = 'https://report_for_fuzzer2/{}'.format(
        data_types.coverage_information_date_to_string(self.today))
    cov_info.corpus_size_units = 40
    cov_info.corpus_size_bytes = 99
    cov_info.quarantine_size_units = 6
    cov_info.quarantine_size_bytes = 14
    cov_info.corpus_location = 'gs://corpus'
    cov_info.corpus_backup_location = 'gs://corpus-backup/file.zip'
    cov_info.quarantine_location = 'gs://quarantine'
    cov_info.put()

    cov_info = data_types.CoverageInformation(
        fuzzer='fuzzer2', date=self.yesterday)
    cov_info.edges_covered = 15
    cov_info.edges_total = 40
    cov_info.functions_covered = 11
    cov_info.functions_total = 16
    cov_info.html_report_url = 'https://report_for_fuzzer2/{}'.format(
        data_types.coverage_information_date_to_string(self.yesterday))
    cov_info.corpus_size_units = 15
    cov_info.corpus_size_bytes = 230
    cov_info.quarantine_size_units = 8
    cov_info.quarantine_size_bytes = 60
    cov_info.corpus_location = 'gs://corpus'
    cov_info.corpus_backup_location = 'gs://corpus-backup/file.zip'
    cov_info.quarantine_location = 'gs://quarantine'
    cov_info.put()

    cov_info = data_types.CoverageInformation(fuzzer='fuzzer3', date=self.today)
    cov_info.edges_covered = None
    cov_info.edges_total = None
    cov_info.functions_covered = None
    cov_info.functions_total = None
    cov_info.html_report_url = None
    cov_info.corpus_size_units = 0
    cov_info.corpus_size_bytes = 0
    cov_info.quarantine_size_units = 0
    cov_info.quarantine_size_bytes = 0
    cov_info.corpus_location = 'gs://corpus'
    cov_info.corpus_backup_location = 'gs://corpus-backup/file.zip'
    cov_info.quarantine_location = 'gs://quarantine'
    cov_info.put()

    data_types.Job(
        name='job1', environment_string='FUZZ_LOGS_BUCKET = bucket1').put()
    data_types.Job(
        name='job2', environment_string='FUZZ_LOGS_BUCKET = bucket2').put()

  def test_constructors(self):
    """Test builtin field constructors."""
    field = fuzzer_stats.BuiltinFieldSpecifier('_EDGE_COV').create()
    self.assertIsInstance(field, fuzzer_stats.CoverageField)

    field = fuzzer_stats.BuiltinFieldSpecifier('_FUNC_COV').create()
    self.assertIsInstance(field, fuzzer_stats.CoverageField)

    field = fuzzer_stats.BuiltinFieldSpecifier('_CORPUS_SIZE').create()
    self.assertIsInstance(field, fuzzer_stats.CorpusSizeField)

    field = fuzzer_stats.BuiltinFieldSpecifier('_CORPUS_BACKUP').create()
    self.assertIsInstance(field, fuzzer_stats.CorpusBackupField)

    field = fuzzer_stats.BuiltinFieldSpecifier('_QUARANTINE_SIZE').create()
    self.assertIsInstance(field, fuzzer_stats.CorpusSizeField)

    field = fuzzer_stats.BuiltinFieldSpecifier('_COV_REPORT').create()
    self.assertIsInstance(field, fuzzer_stats.CoverageReportField)

  def test_coverage_fields(self):
    """Test coverage fields."""
    ctx = fuzzer_stats.CoverageFieldContext()
    edge_field = fuzzer_stats.BuiltinFieldSpecifier('_EDGE_COV').create(ctx)
    func_field = fuzzer_stats.BuiltinFieldSpecifier('_FUNC_COV').create(ctx)

    data = edge_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER, 'fuzzer1')
    self.assertEqual(data.value, '36.67% (11/30)')
    self.assertAlmostEqual(data.sort_key, 36.666666666666664)
    self.assertIsNone(data.link)

    data = func_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER, 'fuzzer2')
    self.assertEqual(data.value, '64.44% (58/90)')
    self.assertAlmostEqual(data.sort_key, 64.44444444444444)
    self.assertIsNone(data.link)

    ctx = fuzzer_stats.CoverageFieldContext(fuzzer='fuzzer2')
    edge_field = fuzzer_stats.BuiltinFieldSpecifier('_EDGE_COV').create(ctx)
    data = edge_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY, self.today)
    self.assertEqual(data.value, '48.48% (16/33)')
    self.assertAlmostEqual(data.sort_key, 48.484848484848484)
    self.assertIsNone(data.link)

    data = edge_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                          self.yesterday)
    self.assertEqual(data.value, '37.50% (15/40)')
    self.assertAlmostEqual(data.sort_key, 37.5)
    self.assertIsNone(data.link)

  def test_corpus_size_fields(self):
    """Test corpus size fields."""
    ctx = fuzzer_stats.CoverageFieldContext()
    corpus_field = fuzzer_stats.BuiltinFieldSpecifier('_CORPUS_SIZE').create(
        ctx)
    corpus_backup_field = fuzzer_stats.BuiltinFieldSpecifier(
        '_CORPUS_BACKUP').create(ctx)
    quarantine_field = fuzzer_stats.BuiltinFieldSpecifier(
        '_QUARANTINE_SIZE').create(ctx)

    data = corpus_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                            'fuzzer1')
    self.assertEqual(data.value, '20 (200 B)')
    self.assertEqual(data.sort_key, 20)
    self.assertEqual(data.link, 'gs://corpus')

    data = corpus_backup_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                                   'fuzzer1')
    self.assertEqual(data.value, 'Download')
    self.assertEqual(data.sort_key, None)
    self.assertEqual(data.link, 'gs://corpus-backup')

    data = corpus_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                            'fuzzer2')
    self.assertEqual(data.value, '40 (99 B)')
    self.assertEqual(data.sort_key, 40)
    self.assertEqual(data.link, 'gs://corpus')

    data = corpus_backup_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                                   'fuzzer2')
    self.assertEqual(data.value, 'Download')
    self.assertEqual(data.sort_key, None)
    self.assertEqual(data.link, 'gs://corpus-backup')

    data = quarantine_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                                'fuzzer1')
    self.assertEqual(data.value, '5 (50 B)')
    self.assertEqual(data.sort_key, 5)
    self.assertEqual(data.link, 'gs://quarantine')

    data = quarantine_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                                'fuzzer2')
    self.assertEqual(data.value, '6 (14 B)')
    self.assertEqual(data.sort_key, 6)
    self.assertEqual(data.link, 'gs://quarantine')

    ctx = fuzzer_stats.CoverageFieldContext('fuzzer2')
    corpus_field = fuzzer_stats.BuiltinFieldSpecifier('_CORPUS_SIZE').create(
        ctx)
    corpus_backup_field = fuzzer_stats.BuiltinFieldSpecifier(
        '_CORPUS_BACKUP').create(ctx)

    data = corpus_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY, self.today)
    self.assertEqual(data.value, '40 (99 B)')
    self.assertEqual(data.sort_key, 40)
    self.assertEqual(data.link, 'gs://corpus')

    data = corpus_backup_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                                   self.today)
    self.assertEqual(data.value, 'Download')
    self.assertEqual(data.sort_key, None)
    self.assertEqual(data.link, 'gs://corpus-backup')

    data = corpus_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                            self.yesterday)
    self.assertEqual(data.value, '15 (230 B)')
    self.assertEqual(data.sort_key, 15)
    self.assertEqual(data.link, 'gs://corpus')

    data = corpus_backup_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                                   self.yesterday)
    self.assertEqual(data.value, 'Download')
    self.assertEqual(data.sort_key, None)
    self.assertEqual(data.link, 'gs://corpus-backup')

  def test_coverage_report_field(self):
    """Test coverage report field."""
    ctx = fuzzer_stats.CoverageFieldContext()
    coverage_report_field = fuzzer_stats.BuiltinFieldSpecifier(
        '_COV_REPORT').create(ctx)

    ctx = fuzzer_stats.CoverageFieldContext('fuzzer2')
    coverage_report_field = fuzzer_stats.BuiltinFieldSpecifier(
        '_COV_REPORT').create(ctx)

    data = coverage_report_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                                     self.today)
    self.assertEqual(data.value, 'Coverage')
    self.assertEqual(
        data.link, 'https://report_for_fuzzer2/{}'.format(
            data_types.coverage_information_date_to_string(self.today)))

    data = coverage_report_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                                     self.yesterday)
    self.assertEqual(data.value, 'Coverage')
    self.assertEqual(
        data.link, 'https://report_for_fuzzer2/{}'.format(
            data_types.coverage_information_date_to_string(self.yesterday)))

  def test_coverage_field_invalid_info(self):
    """Test that coverage field works as expected with invalid coverage info."""
    ctx = fuzzer_stats.CoverageFieldContext(fuzzer='fuzzer3')
    edge_field = fuzzer_stats.BuiltinFieldSpecifier('_EDGE_COV').create(ctx)
    data = edge_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY, self.today)
    self.assertIsNone(data)

  def test_logs_field_by_fuzzer(self):
    """Test logs field (group by fuzzer)."""
    ctx = fuzzer_stats.FuzzerRunLogsContext('fuzzer1', ['job1'])
    logs_field = fuzzer_stats.BuiltinFieldSpecifier('_FUZZER_RUN_LOGS').create(
        ctx)

    data = logs_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                          'fuzzer_child1')
    self.assertEqual(data.value, 'Logs')
    self.assertEqual(data.link, 'gs://bucket1/fuzzer_child1/job1')

  def test_logs_field_by_day(self):
    """Test logs field (group by day)."""
    ctx = fuzzer_stats.FuzzerRunLogsContext('fuzzer1', ['job1'])
    logs_field = fuzzer_stats.BuiltinFieldSpecifier('_FUZZER_RUN_LOGS').create(
        ctx)

    data = logs_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                          datetime.date(2016, 11, 18))
    self.assertEqual(data.value, 'Logs')
    self.assertEqual(data.link, 'gs://bucket1/fuzzer1/job1/2016-11-18')

  def test_logs_field_by_job(self):
    """Test logs field (group by job)."""
    ctx = fuzzer_stats.FuzzerRunLogsContext('fuzzer1', ['blah'])
    logs_field = fuzzer_stats.BuiltinFieldSpecifier('_FUZZER_RUN_LOGS').create(
        ctx)

    data = logs_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_JOB, 'job2')
    self.assertEqual(data.value, 'Logs')
    self.assertEqual(data.link, 'gs://bucket2/fuzzer1/job2')

  def test_performance_field_by_fuzzer(self):
    """Test performance field (group by fuzzer)."""
    ctx = fuzzer_stats.FuzzerRunLogsContext('fuzzer1', ['job1'])
    performance_field = (
        fuzzer_stats.BuiltinFieldSpecifier('_PERFORMANCE_REPORT').create(ctx))

    data = performance_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_FUZZER,
                                 'fuzzer_child1')
    self.assertEqual(data.value, 'Performance')
    expected_link = '/performance-report/fuzzer_child1/job1/latest'
    self.assertEqual(data.link, expected_link)

  def test_performance_field_by_day(self):
    """Test performance field (group by day)."""
    ctx = fuzzer_stats.FuzzerRunLogsContext('fuzzer1', ['job1'])
    performance_field = (
        fuzzer_stats.BuiltinFieldSpecifier('_PERFORMANCE_REPORT').create(ctx))

    data = performance_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_DAY,
                                 datetime.date(2016, 11, 18))
    self.assertEqual(data.value, 'Performance')
    expected_link = '/performance-report/fuzzer1/job1/2016-11-18'
    self.assertEqual(data.link, expected_link)

  def test_performance_field_by_job(self):
    """Test performance field (group by job)."""
    ctx = fuzzer_stats.FuzzerRunLogsContext('fuzzer1', ['blah'])
    performance_field = (
        fuzzer_stats.BuiltinFieldSpecifier('_PERFORMANCE_REPORT').create(ctx))

    data = performance_field.get(fuzzer_stats.QueryGroupBy.GROUP_BY_JOB, 'job2')
    self.assertEqual(data.value, 'Performance')
    expected_link = '/performance-report/fuzzer1/job2/latest'
    self.assertEqual(data.link, expected_link)

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
"""Tests for fuzzer stats."""
# pylint: disable=protected-access
import ast
import datetime
import json
import os
import unittest

import flask
import mock
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import fuzzer_stats
from libs import helpers

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'fuzzer_stats_data')


def _read_data_file(data_file):
  """Helper function to read the contents of a data file."""
  with open(os.path.join(DATA_DIRECTORY, data_file)) as handle:
    return handle.read()


def _mock_query(fuzzer, jobs, group_by, date_start, date_end):
  return json.loads(
      _read_data_file('%s_%s_%s_%s_%s.txt' % (fuzzer, '_'.join(jobs)
                                              if jobs else None, group_by,
                                              date_start, date_end)))


@test_utils.with_cloud_emulators('datastore')
class TestBuildResults(unittest.TestCase):
  """Tests for fuzzer_stats build_results and wrappers."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.maxDiff = None  # pylint: disable=invalid-name

    data_types.Fuzzer(
        name='testFuzzer',
        stats_columns=('sum(t.blah) as blah, custom(j.new_crashes) '
                       'as new_crashes, _EDGE_COV as edge_coverage, '
                       '_FUNC_COV as func_coverage, '
                       '_CORPUS_SIZE as corpus_size, '
                       '_CORPUS_BACKUP as corpus_backup, '
                       '_QUARANTINE_SIZE as quarantine_size, '
                       '_COV_REPORT as coverage_report, '
                       '_FUZZER_RUN_LOGS as fuzzer_logs,'
                       '_PERFORMANCE_REPORT as performance_report'),
        stats_column_descriptions=(
            'blah: "blah description"\n'
            'func_coverage: "func coverage description"\n')).put()

    data_types.Fuzzer(
        name='testFuzzer2',
        stats_columns=('sum(t.blah) as blah, custom(j.new_crashes) '
                       'as new_crashes, _EDGE_COV as edge_coverage, '
                       '_FUNC_COV as func_coverage, '
                       '_CORPUS_SIZE as corpus_size, '
                       '_CORPUS_BACKUP as corpus_backup, '
                       '_QUARANTINE_SIZE as quarantine_size, '
                       '_COV_REPORT as coverage_report, '
                       '_FUZZER_RUN_LOGS as fuzzer_logs,'
                       '_PERFORMANCE_REPORT as performance_report'),
        stats_column_descriptions=(
            'blah: "blah description"\n'
            'func_coverage: "func coverage description"\n')).put()

    data_types.Job(
        name='job', environment_string='FUZZ_LOGS_BUCKET = bucket').put()

    now = datetime.datetime.utcnow()

    data_types.FuzzTarget(
        engine='testFuzzer', project='test-project', binary='1_fuzzer').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='testFuzzer_1_fuzzer', job='job', last_run=now).put()

    data_types.FuzzTarget(
        engine='testFuzzer', project='test-project', binary='2_fuzzer').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='testFuzzer_2_fuzzer', job='job', last_run=now).put()

    data_types.FuzzTarget(
        engine='testFuzzer', project='test-project', binary='3_fuzzer').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='testFuzzer_3_fuzzer', job='job', last_run=now).put()

    data_types.FuzzTarget(
        engine='testFuzzer2', project='test-project', binary='1_fuzzer').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='testFuzzer2_1_fuzzer', job='job', last_run=now).put()

    cov_info = data_types.CoverageInformation(
        fuzzer='2_fuzzer', date=datetime.date(2016, 10, 19))
    cov_info.edges_covered = 11
    cov_info.edges_total = 30
    cov_info.functions_covered = 10
    cov_info.functions_total = 15
    cov_info.html_report_url = 'https://report_for_2_fuzzer/20161019'
    cov_info.corpus_size_units = 20
    cov_info.corpus_size_bytes = 200
    cov_info.quarantine_size_units = 0
    cov_info.quarantine_size_bytes = 0
    cov_info.corpus_location = 'gs://corpus'
    cov_info.corpus_backup_location = 'gs://corpus-backup/file.zip'
    cov_info.quarantine_location = 'gs://quarantine'
    cov_info.put()

    cov_info = data_types.CoverageInformation(
        fuzzer='2_fuzzer', date=datetime.date(2016, 10, 21))
    cov_info.edges_covered = 15
    cov_info.edges_total = 30
    cov_info.functions_covered = 11
    cov_info.functions_total = 15
    cov_info.html_report_url = 'https://report_for_2_fuzzer/20161021'
    cov_info.corpus_size_units = 40
    cov_info.corpus_size_bytes = 400
    cov_info.quarantine_size_units = 8
    cov_info.quarantine_size_bytes = 80
    cov_info.corpus_location = 'gs://corpus'
    cov_info.corpus_backup_location = 'gs://corpus-backup/file.zip'
    cov_info.quarantine_location = 'gs://quarantine'
    cov_info.put()

    cov_info = data_types.CoverageInformation(
        fuzzer='1_fuzzer', date=datetime.date(2016, 10, 20))
    cov_info.edges_covered = 17
    cov_info.edges_total = 38
    cov_info.functions_covered = 12
    cov_info.functions_total = 19
    cov_info.html_report_url = 'https://report_for_1_fuzzer/20161020'
    cov_info.corpus_size_units = 47
    cov_info.corpus_size_bytes = 480
    cov_info.quarantine_size_units = 3
    cov_info.quarantine_size_bytes = 8
    cov_info.corpus_location = 'gs://corpus'
    cov_info.corpus_backup_location = 'gs://corpus-backup/file.zip'
    cov_info.quarantine_location = 'gs://quarantine'
    cov_info.put()

    self.client = mock.Mock(spec_set=big_query.Client)
    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.big_query.Client',
    ])
    self.mock.Client.return_value = self.client

  def test_build_invalid_params(self):
    """Tests build_results with invalid/missing params."""
    with self.assertRaises(helpers.EarlyExitException):
      fuzzer_stats.build_results('', '', '', '', '')

  def test_build_by_fuzzer(self):
    """Tests basic build_results with valid parameters (group by fuzzer)."""
    build_args = [
        'testFuzzer', ['job'], 'by-fuzzer', '2016-10-20', '2016-10-21'
    ]
    self.client.raw_query.return_value = _mock_query(*build_args)
    result = fuzzer_stats.build_results(*build_args)

    self.assertDictEqual(
        ast.literal_eval(_read_data_file('by_fuzzer_expected.txt')), result)

  def test_build_by_day(self):
    """Tests basic build_results with valid parameters (group by day)."""
    build_args = [
        'testFuzzer_2_fuzzer', ['job'], 'by-day', '2016-10-19', '2016-10-21'
    ]
    self.client.raw_query.return_value = _mock_query(*build_args)
    result = fuzzer_stats.build_results(*build_args)

    self.assertDictEqual(
        ast.literal_eval(_read_data_file('by_day_expected.txt')), result)

  def test_build_by_job(self):
    """Tests basic build_results with valid parameters (group by job)."""
    build_args = [
        'testFuzzer_1_fuzzer', None, 'by-job', '2016-10-20', '2016-10-21'
    ]
    self.client.raw_query.return_value = _mock_query(*build_args)
    result = fuzzer_stats.build_results(*build_args)

    self.assertDictEqual(
        ast.literal_eval(_read_data_file('by_job_expected.txt')), result)

  def test_build_by_time(self):
    """Tests basic build_results with valid parameters (group by time)."""
    build_args = [
        'testFuzzer_2_fuzzer', ['job'], 'by-time', '2016-10-19', '2016-10-21'
    ]
    self.client.raw_query.return_value = _mock_query(*build_args)
    result = fuzzer_stats.build_results(*build_args)

    self.assertDictEqual(
        ast.literal_eval(_read_data_file('by_time_expected.txt')), result)

  def test_build_none_results(self):
    """Tests basic build_results, with bigquery returning None for some
    columns."""
    build_args = ['testFuzzer', None, 'by-fuzzer', '2016-10-20', '2016-10-22']
    self.client.raw_query.return_value = _mock_query(*build_args)
    result = fuzzer_stats.build_results(*build_args)

    self.assertDictEqual(
        ast.literal_eval(_read_data_file('by_fuzzer_expected_None.txt')),
        result)

  def test_build_old_results(self):
    """Tests build_results is caching old results appropriately."""
    test_helpers.patch(self, [
        'handlers.fuzzer_stats._build_old_results',
        'handlers.fuzzer_stats._build_todays_results',
        'clusterfuzz._internal.base.utils.utcnow',
    ])

    self.mock._build_old_results.return_value = None
    self.mock._build_todays_results.return_value = None
    self.mock.utcnow.return_value = datetime.datetime(2018, 5, 4)

    date_yesterday = '2018-05-03'
    build_args = [
        'testFuzzer_2_fuzzer', ['job'], 'by-time', date_yesterday,
        date_yesterday
    ]

    # Test that results from yesterday are cached for a full day.
    fuzzer_stats.build_results(*build_args)
    self.mock._build_old_results.assert_called_with(*build_args)
    self.assertEqual(0, self.mock._build_todays_results.call_count)

  def test_build_today_results(self):
    """Tests build_results is caching results from today appropriately."""
    test_helpers.patch(self, [
        'handlers.fuzzer_stats._build_old_results',
        'handlers.fuzzer_stats._build_todays_results',
        'clusterfuzz._internal.base.utils.utcnow',
    ])

    self.mock._build_old_results.return_value = None
    self.mock._build_todays_results.return_value = None
    self.mock.utcnow.return_value = datetime.datetime(2018, 5, 4)

    date_today = '2018-05-04'
    build_args = [
        'testFuzzer_2_fuzzer', ['job'], 'by-time', date_today, date_today
    ]

    # Test that results from yesterday are cached for a full day.
    fuzzer_stats.build_results(*build_args)
    self.mock._build_todays_results.assert_called_with(*build_args)
    self.assertEqual(0, self.mock._build_old_results.call_count)


@test_utils.with_cloud_emulators('datastore')
class TestPermissions(unittest.TestCase):
  """Permissions tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.auth.get_current_user',
        'libs.auth.is_current_user_admin',
        'handlers.fuzzer_stats.build_results',
    ])

    self.mock.build_results.return_value = json.dumps({})

    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/fuzzer-stats/load',
        view_func=fuzzer_stats.LoadHandler.as_view('/fuzzer-stats/load'))
    self.app = webtest.TestApp(flaskapp)

    data_types.ExternalUserPermission(
        email='test@user.com',
        entity_kind=data_types.PermissionEntityKind.JOB,
        entity_name='job1',
        is_prefix=False,
        auto_cc=data_types.AutoCCType.ALL).put()

    data_types.ExternalUserPermission(
        email='test@user.com',
        entity_kind=data_types.PermissionEntityKind.JOB,
        entity_name='job2',
        is_prefix=False,
        auto_cc=data_types.AutoCCType.ALL).put()

    data_types.Job(name='job1').put()
    data_types.Job(name='job2').put()
    data_types.Job(name='job3').put()

  def test_internal_user_with_job(self):
    """Test internal user access (with job)."""
    self.mock.is_current_user_admin.return_value = True
    response = self.app.post_json(
        '/fuzzer-stats/load', {
            'fuzzer': 'fuzzer',
            'job': 'job1',
            'group_by': 'by-fuzzer',
            'date_start': '2017-01-01',
            'date_end': '2017-01-07',
        })
    self.assertEqual(200, response.status_int)
    self.mock.build_results.assert_called_with('fuzzer', ['job1'], 'by-fuzzer',
                                               '2017-01-01', '2017-01-07')

  def test_internal_user_without_job(self):
    """Test internal user access (with job)."""
    self.mock.is_current_user_admin.return_value = True
    response = self.app.post_json(
        '/fuzzer-stats/load', {
            'fuzzer': 'fuzzer',
            'group_by': 'by-fuzzer',
            'date_start': '2017-01-01',
            'date_end': '2017-01-07',
        })
    self.assertEqual(200, response.status_int)
    self.mock.build_results.assert_called_with('fuzzer', None, 'by-fuzzer',
                                               '2017-01-01', '2017-01-07')

  def test_external_user_with_job(self):
    """Test external user access (job specified)."""
    self.mock.is_current_user_admin.return_value = False
    self.mock.get_current_user().email = 'test@user.com'

    response = self.app.post_json(
        '/fuzzer-stats/load', {
            'fuzzer': 'fuzzer',
            'job': 'job1',
            'group_by': 'by-fuzzer',
            'date_start': '2017-01-01',
            'date_end': '2017-01-07',
        })
    self.assertEqual(200, response.status_int)

    response = self.app.post_json(
        '/fuzzer-stats/load', {
            'fuzzer': 'fuzzer',
            'job': 'job2',
            'group_by': 'by-fuzzer',
            'date_start': '2017-01-01',
            'date_end': '2017-01-07',
        })
    self.assertEqual(200, response.status_int)

    response = self.app.post_json(
        '/fuzzer-stats/load', {
            'fuzzer': 'fuzzer',
            'job': 'job3',
            'group_by': 'by-fuzzer',
            'date_start': '2017-01-01',
            'date_end': '2017-01-07',
        },
        expect_errors=True)
    self.assertEqual(403, response.status_int)

  def test_external_user_without_job(self):
    """Test external user access (no job specified)."""
    self.mock.is_current_user_admin.return_value = False
    self.mock.get_current_user().email = 'test@user.com'

    response = self.app.post_json(
        '/fuzzer-stats/load', {
            'fuzzer': 'fuzzer',
            'group_by': 'by-fuzzer',
            'date_start': '2017-01-01',
            'date_end': '2017-01-07',
        })
    self.assertEqual(200, response.status_int)
    self.mock.build_results.assert_called_with(
        'fuzzer', ['job1', 'job2'], 'by-fuzzer', '2017-01-01', '2017-01-07')


class TestGetDate(unittest.TestCase):
  """Test for fuzzer_stats._get_date."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
    ])

  def test_get_date_empty_date(self):
    """Test _get_date correctly replaces an empty date."""
    self.mock.utcnow.return_value = datetime.datetime(2018, 5, 4)
    # Test that when given '' and 1, it returns the string representing
    # the date one day ago.
    self.assertEqual(fuzzer_stats._get_date('', 1), '2018-05-03')

  def test_get_date_non_empty_date(self):
    """Test _get_date just returns a non-empty date."""
    date = '2018-5-1'
    self.assertEqual(fuzzer_stats._get_date(date, 1), date)

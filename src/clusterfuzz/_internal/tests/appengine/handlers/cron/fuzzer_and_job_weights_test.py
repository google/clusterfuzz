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
"""Tests for the automatic weight adjustment cron job."""
# pylint: disable=protected-access
import datetime
import unittest

import six

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import fuzzer_and_job_weights

_TEST_SPECIFICATION = fuzzer_and_job_weights.QuerySpecification(
    query_format='ignored',
    formatter=fuzzer_and_job_weights._past_day_formatter,
    reason='matches test specification')


class TestFormatters(unittest.TestCase):
  """Tests for the query formatter functions used by
  fuzzer_and_job_weights.py."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
    ])
    self.mock.utcnow.return_value = datetime.datetime(2018, 1, 1)

  def test_past_day_formatter(self):
    """Tests for _past_day_formatter."""
    expected_query = """
SELECT
  fuzzer,
  job,
  1.0 - (1.0 - 0.25) * AVG(field) AS new_weight
FROM
  engine.TestcaseRun
WHERE
  _PARTITIONTIME BETWEEN TIMESTAMP('2017-12-31')
  AND TIMESTAMP('2018-01-01')
GROUP BY
  fuzzer,
  job
"""
    specific_query_format = fuzzer_and_job_weights.GENERIC_QUERY_FORMAT.format(
        field_name='field', min_weight=0.25)
    actual_query = fuzzer_and_job_weights._past_day_formatter(
        specific_query_format, 'engine')
    self.assertEqual(actual_query, expected_query)

  def test_new_fuzzer_formatter(self):
    """Tests for _new_fuzzer_formatter."""
    expected_query = """
SELECT
  fuzzer,
  job,
  5.0 as new_weight,
  MIN(_PARTITIONTIME) as first_time
FROM
  engine.TestcaseRun
GROUP BY
  fuzzer,
  job
HAVING
  first_time >= TIMESTAMP('2017-12-25')
"""
    actual_query = fuzzer_and_job_weights._new_fuzzer_formatter(
        fuzzer_and_job_weights.NEW_FUZZER_FORMAT, 'engine')
    self.assertEqual(actual_query, expected_query)

  def test_coverage_formatter(self):
    """Tests for _coverage_formatter."""
    expected_query = """
SELECT
  recent.fuzzer AS fuzzer,
  recent.job AS job,
  0.75 as new_weight
FROM (
  SELECT
    fuzzer,
    job,
    MAX(edge_coverage / edges_total) AS coverage
  FROM
    engine.TestcaseRun
  WHERE
    _PARTITIONTIME BETWEEN TIMESTAMP('2017-12-24')
    AND TIMESTAMP('2017-12-31')
    AND edges_total > 0
    AND edge_coverage > 0
  GROUP BY
    fuzzer,
    job
  HAVING
    coverage <= 1.0) AS recent
JOIN (
  SELECT
    fuzzer,
    job,
    MAX(edge_coverage / edges_total) AS coverage
  FROM
    engine.TestcaseRun
  WHERE
    _PARTITIONTIME BETWEEN TIMESTAMP('2017-12-17')
    AND TIMESTAMP('2017-12-24')
    AND edges_total > 0
    AND edge_coverage > 0
  GROUP BY
    fuzzer,
    job
  HAVING
    coverage <= 1.0) AS older
ON
  recent.fuzzer = older.fuzzer
  AND recent.job = older.job
WHERE
  ABS((recent.coverage - older.coverage) / recent.coverage) < 0.01
"""
    actual_query = fuzzer_and_job_weights._coverage_formatter(
        fuzzer_and_job_weights.COVERAGE_UNCHANGED_FORMAT, 'engine')
    self.assertEqual(actual_query, expected_query)


@test_utils.with_cloud_emulators('datastore')
class TestUpdateChildWeightsForParentFuzzer(unittest.TestCase):
  """Tests for update_target_weights_for_engine."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'handlers.cron.fuzzer_and_job_weights._query_helper',
        'handlers.cron.fuzzer_and_job_weights.'
        'store_current_weights_in_bigquery',
        'handlers.cron.fuzzer_and_job_weights.update_weight_for_target',
    ])

  def test_reported_fuzzer_has_weight_restored(self):
    """Ensure that a target reported fixed has its weight restored."""
    data_types.FuzzTarget(
        engine='libFuzzer', binary='good_fuzzer', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_good_fuzzer',
        engine='libFuzzer',
        job='asan',
        weight=0.1).put()

    # Report that the issue is corrected.
    self.mock._query_helper.return_value = [
        {
            'fuzzer': 'libFuzzer_good_fuzzer',
            'job': 'asan',
            'new_weight': 1.00,
        },
    ]

    fuzzer_and_job_weights.update_target_weights_for_engine(
        None, 'libFuzzer', [_TEST_SPECIFICATION])
    self.mock.update_weight_for_target.assert_called_with(
        'libFuzzer_good_fuzzer', 'asan',
        fuzzer_and_job_weights.RESTORE_DEFAULT_MATCH)

  def test_weight_increase(self):
    """Ensure that weight increases are possible."""
    data_types.FuzzTarget(
        engine='libFuzzer', binary='very_good_fuzzer',
        project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_very_good_fuzzer',
        engine='libFuzzer',
        job='asan',
        weight=1.0).put()

    # Report that the issue is corrected.
    self.mock._query_helper.return_value = [
        {
            'fuzzer': 'libFuzzer_very_good_fuzzer',
            'job': 'asan',
            'new_weight': 2.00,
        },
    ]

    specification = fuzzer_and_job_weights.QuerySpecification(
        query_format='ignored',
        formatter=fuzzer_and_job_weights._past_day_formatter,
        reason='increase weight for test')
    match = fuzzer_and_job_weights.SpecificationMatch(
        new_weight=2.0, reason=specification.reason)
    fuzzer_and_job_weights.update_target_weights_for_engine(
        None, 'libFuzzer', [specification])
    self.mock.update_weight_for_target.assert_called_with(
        'libFuzzer_very_good_fuzzer', 'asan', match)

  def test_target_ignored_if_not_ran(self):
    """Ensure that we don't reset a target weight if it did not run."""
    data_types.FuzzTarget(
        engine='libFuzzer', binary='good_fuzzer', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_good_fuzzer',
        engine='libFuzzer',
        job='asan',
        weight=0.1).put()

    # Do not report any runs.
    self.mock._query_helper.return_value = []

    fuzzer_and_job_weights.update_target_weights_for_engine(
        None, 'libFuzzer', [_TEST_SPECIFICATION])
    self.assertFalse(self.mock.update_weight_for_target.called)

  def test_problem_penalized(self):
    """Ensure that we penalize a target for having problems."""
    data_types.FuzzTarget(
        engine='libFuzzer', binary='problematic_fuzzer',
        project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_problematic_fuzzer',
        engine='libFuzzer',
        job='dummy_job',
        weight=0.1).put()

    self.mock._query_helper.return_value = [
        {
            'fuzzer': 'libFuzzer_problematic_fuzzer',
            'job': 'dummy_job',
            'new_weight': 0.25,
        },
    ]

    fuzzer_and_job_weights.update_target_weights_for_engine(
        None, 'libFuzzer', [_TEST_SPECIFICATION])
    expected_match = fuzzer_and_job_weights.SpecificationMatch(
        new_weight=0.25, reason=_TEST_SPECIFICATION.reason)
    self.mock.update_weight_for_target.assert_called_with(
        'libFuzzer_problematic_fuzzer', 'dummy_job', expected_match)

  def test_new_fuzzer(self):
    """Tests to ensure that the new fuzzer query works properly."""
    data_types.FuzzTarget(
        engine='libFuzzer', binary='old_fuzzer', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_old_fuzzer',
        engine='libFuzzer',
        job='dummy_job',
        weight=1.0).put()

    data_types.FuzzTarget(
        engine='libFuzzer', binary='new_fuzzer', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_new_fuzzer',
        engine='libFuzzer',
        job='dummy_job',
        weight=1.0).put()

    self.mock._query_helper.return_value = [
        {
            'fuzzer': 'libFuzzer_new_fuzzer',
            'job': 'dummy_job',
            'new_weight': 5.0,
            'first_time': '<irrelavent for test>',
        },
    ]

    fuzzer_and_job_weights.update_target_weights_for_engine(
        None, 'libFuzzer', [fuzzer_and_job_weights.NEW_FUZZER_SPECIFICATION])
    expected_match = fuzzer_and_job_weights.SpecificationMatch(
        new_weight=5.0,
        reason=fuzzer_and_job_weights.NEW_FUZZER_SPECIFICATION.reason)
    self.mock.update_weight_for_target.assert_called_with(
        'libFuzzer_new_fuzzer', 'dummy_job', expected_match)


@test_utils.with_cloud_emulators('datastore')
class TestUpdateJobWeights(unittest.TestCase):
  """Test updating job weights."""

  def setUp(self):
    test_fuzzer_jobs = {
        'libFuzzer': [
            'libfuzzer_asan_job',
            'libfuzzer_asan_large_job',
            'libfuzzer_msan_job',
            'libfuzzer_ubsan_job',
            'libfuzzer_tsan_job',
            'libfuzzer_cfi_job',
            'libfuzzer_asan_job2',
        ],
        'afl': ['afl_asan_job',],
        'honggfuzz': ['honggfuzz_asan_job'],
        'blackbox': ['asan_blackbox_job',]
    }

    for fuzzer, jobs in six.iteritems(test_fuzzer_jobs):
      for job in jobs:
        data_types.Job(name=job).put()
        data_types.FuzzerJob(fuzzer=fuzzer, job=job).put()

    data_types.FuzzTargetsCount(id='libfuzzer_asan_job', count=10).put()
    data_types.FuzzTargetsCount(id='libfuzzer_msan_job', count=5).put()
    data_types.FuzzTargetsCount(id='libfuzzer_ubsan_job', count=5).put()
    data_types.FuzzTargetsCount(id='libfuzzer_tsan_job', count=5).put()
    data_types.FuzzTargetsCount(id='libfuzzer_cfi_job', count=5).put()
    data_types.FuzzTargetsCount(id='afl_asan_job', count=10).put()
    data_types.FuzzTargetsCount(id='libfuzzer_asan_job2', count=0).put()
    data_types.FuzzTargetsCount(id='honggfuzz_asan_job', count=10).put()
    data_types.FuzzTargetsCount(id='libfuzzer_asan_large_job', count=1000).put()

  def test_update_job_weights(self):
    """Test update job weights."""
    fuzzer_and_job_weights.update_job_weights()

    def get_result(job):
      return data_types.FuzzerJob.query(data_types.FuzzerJob.job == job).get()

    self.assertEqual(5.0, get_result('libfuzzer_asan_job').multiplier)
    self.assertEqual(1.0, get_result('libfuzzer_msan_job').multiplier)
    self.assertEqual(0.5, get_result('libfuzzer_ubsan_job').multiplier)
    self.assertEqual(0.5, get_result('libfuzzer_tsan_job').multiplier)
    self.assertEqual(0.5, get_result('libfuzzer_cfi_job').multiplier)
    self.assertEqual(5.0, get_result('afl_asan_job').multiplier)
    self.assertEqual(15.0, get_result('asan_blackbox_job').multiplier)
    self.assertEqual(15.0, get_result('libfuzzer_asan_job2').multiplier)
    self.assertEqual(1.0, get_result('honggfuzz_asan_job').multiplier)
    self.assertEqual(50.0, get_result('libfuzzer_asan_large_job').multiplier)

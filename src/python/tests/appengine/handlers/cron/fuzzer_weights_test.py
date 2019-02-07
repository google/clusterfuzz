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
"""Tests for the automatic weight adjusment cron job."""
# pylint: disable=protected-access
import datetime
import unittest

from datastore import data_types
from handlers.cron import fuzzer_weights
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

_TEST_SPECIFICATION = fuzzer_weights.QuerySpecification(
    adjusted_weight=0.15,
    threshold=0.90,
    query_format='ignored',
    formatter=fuzzer_weights._past_day_formatter,
    reason='matches test specification')


class TestFormatters(unittest.TestCase):
  """Tests for the query formatter functions used by fuzzer_weights.py."""

  def setUp(self):
    test_helpers.patch(self, [
        'base.utils.utcnow',
    ])
    self.mock.utcnow.return_value = datetime.datetime(2018, 1, 1)

  def test_past_day_formatter(self):
    """Tests for _past_day_formatter."""
    expected_query = """
SELECT
  fuzzer,
  job,
  AVG(field) AS ratio
FROM
  engine.TestcaseRun
WHERE
  _PARTITIONTIME BETWEEN TIMESTAMP('2017-12-31')
  AND TIMESTAMP('2018-01-01')
GROUP BY
  fuzzer,
  job
"""
    specific_query_format = fuzzer_weights.GENERIC_QUERY_FORMAT.format(
        field_name='field')
    actual_query = fuzzer_weights._past_day_formatter(specific_query_format,
                                                      'engine')
    self.assertEqual(actual_query, expected_query)

  def test_new_fuzzer_formatter(self):
    """Tests for _new_fuzzer_formatter."""
    expected_query = """
SELECT
  fuzzer,
  job,
  1 as ratio,
  MIN(_PARTITIONTIME) as first_time
FROM
  engine.TestcaseRun
GROUP BY
  fuzzer,
  job
HAVING
  first_time >= TIMESTAMP('2017-12-25')
"""
    actual_query = fuzzer_weights._new_fuzzer_formatter(
        fuzzer_weights.NEW_FUZZER_FORMAT, 'engine')
    self.assertEqual(actual_query, expected_query)

  def test_coverage_formatter(self):
    """Tests for _coverage_formatter."""
    expected_query = """
SELECT
  recent.fuzzer AS fuzzer,
  recent.job AS job,
  1 as ratio
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
    actual_query = fuzzer_weights._coverage_formatter(
        fuzzer_weights.COVERAGE_UNCHANGED_FORMAT, 'engine')
    self.assertEqual(actual_query, expected_query)


@test_utils.with_cloud_emulators('datastore')
class TestUpdateChildWeightsForParentFuzzer(unittest.TestCase):
  """Tests for update_target_weights_for_engine."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'handlers.cron.fuzzer_weights._query_helper',
        'handlers.cron.fuzzer_weights.update_weight_for_target',
    ])

  def test_target_fuzzer_has_weight_restored(self):
    """Ensure that a target with all issues fixed has its weight restored."""
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
            'ratio': 0.00,
        },
    ]

    fuzzer_weights.update_target_weights_for_engine(None, 'libFuzzer',
                                                    [_TEST_SPECIFICATION])
    self.mock.update_weight_for_target.assert_called_with(
        'libFuzzer_good_fuzzer', 'asan',
        fuzzer_weights.RESTORE_DEFAULT_SPECIFICATION)

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
            'ratio': 1.00,
        },
    ]

    specification = fuzzer_weights.QuerySpecification(
        adjusted_weight=2.0,
        threshold=0.90,
        query_format='ignored',
        formatter=fuzzer_weights._past_day_formatter,
        reason='increase weight for test')
    fuzzer_weights.update_target_weights_for_engine(None, 'libFuzzer',
                                                    [specification])
    self.mock.update_weight_for_target.assert_called_with(
        'libFuzzer_very_good_fuzzer', 'asan', specification)

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

    fuzzer_weights.update_target_weights_for_engine(None, 'libFuzzer',
                                                    [_TEST_SPECIFICATION])
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
            'ratio': 0.99,
        },
    ]

    fuzzer_weights.update_target_weights_for_engine(None, 'libFuzzer',
                                                    [_TEST_SPECIFICATION])
    self.mock.update_weight_for_target.assert_called_with(
        'libFuzzer_problematic_fuzzer', 'dummy_job', _TEST_SPECIFICATION)

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
            'ratio': 1,
            'first_time': '<irrelavent for test>',
        },
    ]

    fuzzer_weights.update_target_weights_for_engine(
        None, 'libFuzzer', [fuzzer_weights.NEW_FUZZER_SPECIFICATION])
    self.mock.update_weight_for_target.assert_called_with(
        'libFuzzer_new_fuzzer', 'dummy_job',
        fuzzer_weights.NEW_FUZZER_SPECIFICATION)

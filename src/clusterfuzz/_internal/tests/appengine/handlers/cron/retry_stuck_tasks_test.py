# Copyright 2025 Google LLC
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
"""Tests for retry_stuck_tasks cron script."""

import datetime
import os
import unittest
from unittest import mock

from clusterfuzz._internal.cron import retry_stuck_tasks
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


def _create_mock_testcase(testcase_id: int, job_type: str | None,
                          metadata: dict) -> mock.Mock:
  """Builds a mock Testcase object for use in tests.

  This helper simplifies test setup by creating a mock that conforms to the
  Testcase interface, with methods like `Youtube` and `put` already
  mocked out. The metadata methods are configured to simulate a simple
  dictionary lookup.

  Args:
    testcase_id: The integer ID for the mock testcase.
    job_type: The string representing the job type.
    metadata: A dictionary of metadata values to be returned by get_metadata.

  Returns:
    A mock.Mock object configured to behave like a data_types.Testcase.
  """
  testcase = mock.Mock(spec=data_types.Testcase)
  testcase.key = mock.Mock()
  testcase.key.id.return_value = testcase_id
  testcase.job_type = job_type
  testcase.crash_type = 'Test-Crash-Type'
  testcase.fuzzer_name = 'TestFuzzer'

  testcase.get_metadata = mock.Mock(
      side_effect=lambda key, default=None: metadata.get(key, default))
  testcase.set_metadata = mock.Mock()
  testcase.put = mock.Mock()
  return testcase


@test_utils.with_cloud_emulators('datastore')
class RetryStuckTasksTest(unittest.TestCase):
  """Unit and integration tests for the retry_stuck_tasks cron job."""

  def setUp(self):
    """Initializes the test environment before each test method.

    This method uses `helpers.patch` to mock all external dependencies of the
    `retry_stuck_tasks` script, ensuring that our tests are isolated and
    deterministic. It also mocks `utils.utcnow` to provide a consistent sense
    of time across all tests.
    """
    helpers.patch(self, [
        'clusterfuzz._internal.cron.retry_stuck_tasks.data_handler',
        'clusterfuzz._internal.cron.retry_stuck_tasks.task_creation',
        'clusterfuzz._internal.cron.retry_stuck_tasks.logs',
        'clusterfuzz._internal.base.utils.utcnow',
    ])

    self.now = datetime.datetime.utcnow()
    self.mock.utcnow.return_value = self.now

  def test_parse_arguments_with_defaults(self):
    """Tests that the argument parser correctly applies default values."""
    parsed_args = retry_stuck_tasks.parse_script_args([])
    self.assertEqual(parsed_args.stuck_deadline_hours, 24)
    self.assertEqual(parsed_args.cooldown_hours, 12)
    self.assertEqual(parsed_args.max_retries, 3)
    self.assertEqual(parsed_args.restarts_per_run_limit, 5)
    self.assertFalse(parsed_args.non_dry_run)

  def test_parse_arguments_with_custom_values(self):
    """Tests that custom command-line arguments correctly override defaults."""
    custom_args = [
        '--stuck-deadline-hours=12',
        '--max-retries=5',
        '--non-dry-run',
    ]
    parsed_args = retry_stuck_tasks.parse_script_args(custom_args)
    self.assertEqual(parsed_args.stuck_deadline_hours, 12)
    self.assertEqual(parsed_args.max_retries, 5)
    self.assertTrue(parsed_args.non_dry_run)

  def test_filter_and_categorize_candidates(self):
    """Tests the main filtering and categorization logic end-to-end.

    This test sets up five distinct testcase scenarios:
      1. A genuinely stuck testcase that should be restarted.
      2. A testcase that is already considered complete.
      3. A testcase associated with a job that no longer exists.
      4. A testcase that has already reached its maximum retry limit.
      5. A testcase that was restarted recently and is in a cooldown period.

    It then verifies that the `filter_and_categorize_candidates` function
    correctly sorts each of these testcases into the appropriate category.
    """
    parsed_args = retry_stuck_tasks.parse_script_args([])
    config = retry_stuck_tasks.get_script_config(parsed_args)

    tc_to_restart = _create_mock_testcase(1, 'valid_job', {})
    tc_complete = _create_mock_testcase(2, 'valid_job', {})
    tc_invalid_job = _create_mock_testcase(3, 'invalid_job', {})
    tc_max_attempts = _create_mock_testcase(
        4, 'valid_job', {'retry_stuck_task_attempt_count': 3})
    last_attempt = self.now - datetime.timedelta(hours=1)
    tc_in_cooldown = _create_mock_testcase(
        5, 'valid_job', {'retry_stuck_task_last_attempt_time': last_attempt})

    all_candidates = [
        tc_to_restart, tc_complete, tc_invalid_job, tc_max_attempts,
        tc_in_cooldown
    ]

    self.mock.data_handler.critical_tasks_completed.side_effect = (
        lambda tc: tc == tc_complete)

    with mock.patch('clusterfuzz._internal.cron.retry_stuck_tasks._is_job_valid'
                   ) as mock_is_job_valid:
      mock_is_job_valid.side_effect = lambda tc: tc.job_type == 'valid_job'
      results = retry_stuck_tasks.filter_and_categorize_candidates(
          all_candidates, config)

    self.assertIn(tc_to_restart, results.to_restart)
    self.assertIn(tc_complete, results.skipped_as_complete)
    self.assertIn(tc_invalid_job, results.skipped_for_invalid_job)
    self.assertIn(tc_max_attempts, results.skipped_max_attempts)
    self.assertIn(tc_in_cooldown, results.skipped_for_cooldown)

  def test_restart_analysis_in_dry_run_mode(self):
    """Tests that no write operations occur when in dry-run mode.

    This test verifies the script's simulation mode. It asserts that:
      1. A warning log is generated with the '[DRY RUN]' prefix.
      2. No state-changing functions (task creation, metadata updates) are
         actually called.
      3. The returned counter IS incremented to reflect the number of tasks
         that *would have been* processed, ensuring the final log summary is
         informative even in a dry run.
    """
    parsed_args = retry_stuck_tasks.parse_script_args([])
    config = retry_stuck_tasks.get_script_config(parsed_args)
    self.assertFalse(config.non_dry_run)
    tc1 = _create_mock_testcase(1, 'job1', {})

    restarted_count = retry_stuck_tasks.restart_analysis_for_testcases([tc1],
                                                                       config)

    self.mock.logs.warning.assert_called_once()
    log_message = self.mock.logs.warning.call_args[0][0]
    self.assertIn('[DRY RUN]', log_message)
    self.mock.task_creation.create_minimize_task_if_needed.assert_not_called()
    tc1.set_metadata.assert_not_called()
    tc1.put.assert_not_called()
    self.assertEqual(restarted_count, 1)

  def test_restart_analysis_in_non_dry_run_mode(self):
    """Tests that all write operations occur when in non-dry-run mode.

    This test verifies the script's 'happy path' for real execution. It
    confirms that when the --non-dry-run flag is active, the script correctly
    calls all expected functions to create a new task and update the testcase's
    state in the Datastore.
    """
    parsed_args = retry_stuck_tasks.parse_script_args(['--non-dry-run'])
    config = retry_stuck_tasks.get_script_config(parsed_args)
    self.assertTrue(config.non_dry_run)
    tc1 = _create_mock_testcase(1, 'job1', {})

    restarted_count = retry_stuck_tasks.restart_analysis_for_testcases([tc1],
                                                                       config)

    self.mock.task_creation.create_minimize_task_if_needed.assert_called_once_with(
        tc1)
    tc1.set_metadata.assert_any_call('retry_stuck_task_attempt_count', 1)
    tc1.set_metadata.assert_any_call('retry_stuck_task_last_attempt_time',
                                     self.now)
    tc1.put.assert_called_once()
    self.assertEqual(restarted_count, 1)

  def test_restart_analysis_respects_run_limit(self):
    """Tests that the script stops after reaching the per-run restart limit.

    This test validates the safety throttle. It provides more testcases than
    the configured limit and asserts that the remediation loop correctly
    breaks after the limit is reached, preventing the script from enqueuing an
    excessive number of tasks in a single run.
    """
    parsed_args = retry_stuck_tasks.parse_script_args(
        ['--non-dry-run', '--restarts-per-run-limit=2'])
    config = retry_stuck_tasks.get_script_config(parsed_args)
    testcases = [
        _create_mock_testcase(1, 'job1', {}),
        _create_mock_testcase(2, 'job1', {}),
        _create_mock_testcase(3, 'job1', {}),
    ]

    restarted_count = retry_stuck_tasks.restart_analysis_for_testcases(
        testcases, config)

    self.assertEqual(restarted_count, 2)
    self.assertEqual(
        self.mock.task_creation.create_minimize_task_if_needed.call_count, 2)
    self.mock.logs.info.assert_called_with(
        'Reached the limit of 2 restarts for this run. '
        'Exiting remediation loop.')

  def test_parse_arguments_hierarchy(self):
    """
    Tests the configuration hierarchy for argument parsing.

    This test verifies the intended order of precedence for setting
    configuration parameters:
      1. A command-line flag (highest priority).
      2. An environment variable (medium priority).
      3. The hardcoded default value (lowest priority).

    It uses mock.patch.dict to simulate different environment variable
    states for each scenario.
    """
    with mock.patch.dict(os.environ, {}, clear=True):
      parsed_args = retry_stuck_tasks.parse_script_args([])
      self.assertEqual(parsed_args.max_retries, 3)
      self.assertFalse(parsed_args.non_dry_run)

    with mock.patch.dict(os.environ, {
        'MAX_RETRY_ATTEMPTS': '7',
        'NON_DRY_RUN': 'true'
    }):
      parsed_args = retry_stuck_tasks.parse_script_args([])
      self.assertEqual(parsed_args.max_retries, 7)
      self.assertTrue(parsed_args.non_dry_run)

    with mock.patch.dict(os.environ, {
        'MAX_RETRY_ATTEMPTS': '7',
        'NON_DRY_RUN': 'false'
    }):
      parsed_args = retry_stuck_tasks.parse_script_args(
          ['--max-retries=99', '--non-dry-run'])
      self.assertEqual(parsed_args.max_retries, 99)
      self.assertTrue(parsed_args.non_dry_run)

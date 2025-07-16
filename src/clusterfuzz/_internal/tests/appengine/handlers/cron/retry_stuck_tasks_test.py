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
import unittest
from unittest import mock

from clusterfuzz._internal.cron import retry_stuck_tasks
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


def _create_mock_testcase(testcase_id: int, job_type: str | None,
                          metadata: dict) -> mock.Mock:
  """Helper function to create a mock Testcase object for testing."""
  testcase = mock.Mock(spec=data_types.Testcase)
  testcase.key = mock.Mock()
  testcase.key.id.return_value = testcase_id
  testcase.job_type = job_type
  testcase.crash_type = 'Test-Crash-Type'
  testcase.fuzzer_name = 'TestFuzzer'

  # Mock the metadata methods to simulate a simple dictionary lookup.
  testcase.get_metadata.side_effect = (
      lambda key, default=None: metadata.get(key, default))
  testcase.set_metadata = mock.Mock()
  testcase.put = mock.Mock()
  return testcase


@test_utils.with_cloud_emulators('datastore')
class RetryStuckTasksTest(unittest.TestCase):
  """Unit and integration tests for the retry_stuck_tasks cron job."""

  def setUp(self):
    """Set up the test environment and mock all external dependencies."""
    helpers.patch(self, [
        'clusterfuzz._internal.cron.retry_stuck_tasks.data_handler',
        'clusterfuzz._internal.cron.retry_stuck_tasks.task_creation',
        'clusterfuzz._internal.cron.retry_stuck_tasks.logs',
        'clusterfuzz._internal.base.utils.utcnow',
        'clusterfuzz._internal.datastore.data_types.Job.query',
    ])

    # Mock time to have deterministic results in tests.
    self.now = datetime.datetime.utcnow()
    self.mock.utcnow.return_value = self.now

  def test_parse_arguments_with_defaults(self):
    """Test that arguments are parsed correctly when none are provided."""
    parsed_args = retry_stuck_tasks.parse_script_args([])
    self.assertEqual(parsed_args.stuck_deadline_hours, 8)
    self.assertEqual(parsed_args.cooldown_hours, 4)
    self.assertEqual(parsed_args.max_retries, 3)
    self.assertEqual(parsed_args.restarts_per_run_limit, 10)
    self.assertFalse(parsed_args.non_dry_run)

  def test_parse_arguments_with_custom_values(self):
    """Test that custom arguments override the defaults."""
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
    """Tests the main filtering and categorization logic end-to-end."""
    parsed_args = retry_stuck_tasks.parse_script_args([])
    config = retry_stuck_tasks.get_script_config(parsed_args)

    # --- Test Data Setup ---
    # 1. A testcase that is genuinely stuck and should be restarted.
    tc_to_restart = _create_mock_testcase(1, 'valid_job', {})

    # 2. A testcase whose critical tasks are already complete.
    tc_complete = _create_mock_testcase(2, 'valid_job', {})

    # 3. A testcase with a job that no longer exists.
    tc_invalid_job = _create_mock_testcase(3, 'invalid_job', {})

    # 4. A testcase that has reached the max retry attempts.
    tc_max_attempts = _create_mock_testcase(
        4, 'valid_job', {'retry_stuck_task_attempt_count': 3})

    # 5. A testcase that is in the cooldown period.
    last_attempt = self.now - datetime.timedelta(hours=1)
    tc_in_cooldown = _create_mock_testcase(
        5, 'valid_job', {'retry_stuck_task_last_attempt_time': last_attempt})

    all_candidates = [
        tc_to_restart, tc_complete, tc_invalid_job, tc_max_attempts,
        tc_in_cooldown
    ]

    # --- Mocking Dependencies ---
    # Configure the mock for the critical tasks check.
    self.mock.data_handler.critical_tasks_completed.side_effect = (
        lambda tc: tc == tc_complete)

    # This is the correct way to mock '_is_job_valid' only for this test.
    # It temporarily replaces the real function with our mock.
    with mock.patch('clusterfuzz._internal.cron.retry_stuck_tasks._is_job_valid'
                   ) as mock_is_job_valid:
      # We tell the mock to return True if the job_type is 'valid_job',
      # and False otherwise.
      mock_is_job_valid.side_effect = lambda tc: tc.job_type == 'valid_job'

      # --- Execution ---
      # Execute the filtering function within the mock's context.
      results = retry_stuck_tasks.filter_and_categorize_candidates(
          all_candidates, config)

    # --- Assertions ---
    # Verify that each testcase ended up in the correct category list.
    self.assertIn(tc_to_restart, results.to_restart)
    self.assertIn(tc_complete, results.skipped_as_complete)
    self.assertIn(tc_invalid_job, results.skipped_for_invalid_job)
    self.assertIn(tc_max_attempts, results.skipped_max_attempts)
    self.assertIn(tc_in_cooldown, results.skipped_for_cooldown)
    self.assertEqual(len(results.to_restart), 1)

  def test_restart_analysis_in_dry_run_mode(self):
    """
    Tests that in dry-run mode, a specific log prefix is used, the counter is
    incremented, but no actual write operations occur.
    """
    # Setup: Create a config where non_dry_run is False (i.e., dry run is ON).
    parsed_args = retry_stuck_tasks.parse_script_args([])
    config = retry_stuck_tasks.get_script_config(parsed_args)
    self.assertFalse(config.non_dry_run)

    tc1 = _create_mock_testcase(1, 'job1', {})

    # Execution: Run the function with the testcase.
    restarted_count = retry_stuck_tasks.restart_analysis_for_testcases([tc1],
                                                                       config)

    # --- Assertions ---
    # 1. Assert that the warning log was called exactly once.
    self.mock.logs.warning.assert_called_once()

    # 2. Assert that the log message CONTAINS the '[DRY RUN]' prefix.
    log_message = self.mock.logs.warning.call_args[0][0]
    self.assertIn('[DRY RUN]', log_message)

    # 3. Assert that NO write functions were called.
    self.mock.task_creation.create_minimize_task_if_needed.assert_not_called()
    tc1.set_metadata.assert_not_called()
    tc1.put.assert_not_called()

    # 4. Assert that the counter was still incremented (as per your script's logic).
    self.assertEqual(restarted_count, 1)

  def test_restart_analysis_in_non_dry_run_mode(self):
    """Test that write operations DO occur when in non-dry-run mode."""
    parsed_args = retry_stuck_tasks.parse_script_args(['--non-dry-run'])
    config = retry_stuck_tasks.get_script_config(parsed_args)
    self.assertTrue(config.non_dry_run)

    tc1 = _create_mock_testcase(1, 'job1', {})
    retry_stuck_tasks.restart_analysis_for_testcases([tc1], config)

    # Assert that all write/task creation functions were called correctly.
    self.mock.task_creation.create_minimize_task_if_needed.assert_called_once_with(
        tc1)
    tc1.set_metadata.assert_any_call('retry_stuck_task_attempt_count', 1)
    tc1.set_metadata.assert_any_call('retry_stuck_task_last_attempt_time',
                                     self.now)
    tc1.put.assert_called_once()

  def test_restart_analysis_respects_run_limit(self):
    """Test that the script stops after reaching the per-run restart limit."""
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

    # Assert that it stopped after processing exactly 2 testcases.
    self.assertEqual(restarted_count, 2)
    self.assertEqual(
        self.mock.task_creation.create_minimize_task_if_needed.call_count, 2)
    self.mock.logs.info.assert_called_with(
        'Reached the limit of 2 restarts for this run. Exiting remediation loop.'
    )

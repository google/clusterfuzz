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
"""
Cron job to find and restart the analysis of stuck testcases.

This script identifies testcases that entered the analysis pipeline
but stalled due to transient errors or other issues. It makes them
idempotent by marking restart attempts and validates data integrity,
ensuring associated jobs still exist before creating new analysis
tasks. This version performs all filtering and categorization upfront
before remediation, providing a clear and verbose summary of findings.
"""

import datetime
import os
from typing import NamedTuple

from google.cloud import ndb  # pylint: disable=no-name-in-module

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs

RETRY_ATTEMPT_COUNT_KEY = 'retry_stuck_task_attempt_count'
RETRY_LAST_ATTEMPT_TIME_KEY = 'retry_stuck_task_last_attempt_time'


class ScriptConfig(NamedTuple):
  """Contains the configuration parameters for the cron job."""

  stuck_deadline: datetime.datetime
  cooldown_deadline: datetime.datetime
  max_retry_attempts: int
  restarts_per_run_limit: int


def _get_stuck_deadline_hours() -> int:
  """
  Returns the deadline in hours for considering a testcase as "stuck".

  A longer deadline helps avoid race conditions with tasks that are legitimately
  running for a long time. This is the main guard against restarting tasks that
  are just slow, not truly stuck.
  """
  return int(os.getenv('STUCK_DEADLINE_HOURS', '8'))


def _get_retry_cooldown_hours() -> int:
  """
  Returns the cooldown period in hours for this script's own actions.

  This prevents the cron from creating duplicate tasks if it runs multiple
  times in quick succession, making the script idempotent regarding its own
  restarts.
  """
  return int(os.getenv('RETRY_COOLDOWN_HOURS', '4'))


def _get_max_retry_attempts() -> int:
  """
  Returns the maximum number of retry attempts for stuck testcases.

  This is a safeguard to prevent infinite loops in case of persistent issues.
  """
  return int(os.getenv('MAX_RETRY_ATTEMPTS', '3'))


def _get_restarts_per_run_limit() -> int:
  """
  Returns the maximum number of testcases to restart in a single cron run.

  This acts as a safety throttle to prevent a single run from enqueuing
  an unexpectedly large number of tasks, which could overload the system.
  """
  return int(os.getenv('RESTARTS_PER_RUN_LIMIT', '10'))


def _get_script_config() -> ScriptConfig:
  """
  Defines and returns the core time-based parameters for the script's logic.
  """
  stuck_deadline = utils.utcnow() - datetime.timedelta(
      hours=_get_stuck_deadline_hours())
  cooldown_deadline = utils.utcnow() - datetime.timedelta(
      hours=_get_retry_cooldown_hours())
  max_retry_attempts = _get_max_retry_attempts()
  restarts_per_run_limit = _get_restarts_per_run_limit()
  return ScriptConfig(stuck_deadline=stuck_deadline,
                      cooldown_deadline=cooldown_deadline,
                      max_retry_attempts=max_retry_attempts,
                      restarts_per_run_limit=restarts_per_run_limit)


def _get_stuck_testcase_candidates_query(
    stuck_deadline: datetime.datetime,) -> ndb.Query:
  """
  Builds the Datastore query for potentially stuck testcases.

  The query is carefully optimized to fetch only relevant candidates. It filters
  for testcases that are still open and valid (not 'Unreproducible') but have
  not been updated recently, indicating they may be stalled in any
  intermediate state.
  """
  return data_types.Testcase.query(
      data_types.Testcase.fixed != "NA",
      ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag),
      ndb_utils.is_true(data_types.Testcase.open),
      ndb.OR(data_types.Testcase.status == 'Processed',
             data_types.Testcase.status == 'Duplicate'),
      data_types.Testcase.timestamp < stuck_deadline,  # type: ignore[operator]
  )


def _get_testcase_id(testcase: data_types.Testcase) -> str:
  """
  Safely retrieves the string representation of the testcase's ID.

  This helper function assumes the testcase and its key are valid, as it's
  called on entities that have been successfully fetched from a Datastore
  query. It converts the native integer ID to a string for consistent use
  in logging and task arguments.

  Args:
    testcase: The Testcase entity from which to extract the ID.

  Returns:
    The string representation of the testcase ID.
  """
  return str(testcase.key.id())  # type: ignore


def _is_job_valid(testcase: data_types.Testcase) -> bool:
  """
  Checks if the job associated with a testcase still exists.
  """
  job_exists_query = data_types.Job.query(
      data_types.Job.name == testcase.job_type)
  if not job_exists_query.get(keys_only=True):
    logs.error(
        f"Skipping testcase {_get_testcase_id(testcase)} because its job "
        f'"{testcase.job_type}" no longer exists in Job entities.')
    return False
  return True


def _is_in_cooldown(testcase: data_types.Testcase,
                    cooldown_deadline: datetime.datetime) -> bool:
  """
  Checks if a restart was recently attempted for this testcase by this cron.
  """
  last_attempt_time = testcase.get_metadata(RETRY_LAST_ATTEMPT_TIME_KEY)
  if last_attempt_time and last_attempt_time > cooldown_deadline:
    logs.info(
        f"Skipping testcase {_get_testcase_id(testcase)} "
        f"because a restart was already attempted at {last_attempt_time}.")
    return True
  return False


def _has_reached_max_attempts(testcase: data_types.Testcase,
                              max_attempts: int) -> bool:
  """
  Checks if a testcase has reached the maximum number of restart attempts.

  This acts as a safeguard to prevent a testcase from being retried
  indefinitely. It reads a custom metadata counter and compares it against
  a defined limit. If the limit is met or exceeded, the testcase is
  considered "permanently stuck" and should be escalated for manual review.

  Args:
    testcase: The Testcase entity to check.
    max_attempts: The integer limit for retry attempts.

  Returns:
    True if the attempt count is greater than or equal to the maximum,
    False otherwise.
  """
  attempt_count = testcase.get_metadata(RETRY_ATTEMPT_COUNT_KEY) or 0
  return attempt_count >= max_attempts


def _get_stuck_reason(testcase: data_types.Testcase) -> str:
  """
  Analyzes a testcase to generate a human-readable reason for why it's stuck.
  """
  reasons = []
  if not testcase.minimized_keys:
    reasons.append("is not minimized")
  if not testcase.regression:
    reasons.append("has no regression range")
  if utils.is_chromium():
    if not testcase.is_impact_set_flag:
      reasons.append("has no impact set")
    if testcase.analyze_pending:
      reasons.append("has analyze_pending=True")
  if not reasons:
    return "an unknown reason (critical_tasks_completed is False)"
  return ", ".join(reasons)


def _restart_analysis_for_testcases(testcases_to_restart: list[
    data_types.Testcase], restarts_per_run_limit: int) -> int:
  """
  Performs the remediation action for a final list of stuck testcases.
  """
  restarted_count = 0
  for testcase in testcases_to_restart:
    testcase_id = _get_testcase_id(testcase)
    stuck_reason = _get_stuck_reason(testcase)

    attempt_count = testcase.get_metadata(RETRY_ATTEMPT_COUNT_KEY) or 0

    logs.warning(f'Retriggering "minimize" for stuck testcase {testcase_id}. '
                 f'(Attempt #{attempt_count + 1}). '
                 f"Reason: Testcase {stuck_reason}. "
                 f"Details: [Job: {testcase.job_type}, "
                 f"Crash Type: {testcase.crash_type}, "
                 f"Fuzzer: {testcase.fuzzer_name}]")

    task_creation.create_minimize_task_if_needed(testcase)

    testcase.set_metadata(RETRY_ATTEMPT_COUNT_KEY, attempt_count + 1)
    testcase.set_metadata(RETRY_LAST_ATTEMPT_TIME_KEY, utils.utcnow())
    testcase.put()
    restarted_count += 1

    if restarted_count >= restarts_per_run_limit:
      logs.info(f'Reached the limit of {restarts_per_run_limit} '
                'restarts for this run. Exiting remediation loop.')
      break
  return restarted_count


class CategorizedTestcases(NamedTuple):
  """Holds the lists of testcases after filtering and categorization."""

  to_restart: list[data_types.Testcase]
  skipped_as_complete: list[data_types.Testcase]
  skipped_for_invalid_job: list[data_types.Testcase]
  skipped_for_cooldown: list[data_types.Testcase]
  skipped_max_attempts: list[data_types.Testcase]


def _filter_and_categorize_candidates(
    candidates: list[data_types.Testcase],
    cooldown_deadline: datetime.datetime,
    max_retry_attempts: int,
) -> CategorizedTestcases:
  """
  Processes a list of candidates, filtering and categorizing them.
  """
  categorized = CategorizedTestcases(
      to_restart=[],
      skipped_as_complete=[],
      skipped_for_invalid_job=[],
      skipped_for_cooldown=[],
      skipped_max_attempts=[],
  )

  for testcase in candidates:
    if data_handler.critical_tasks_completed(testcase):
      categorized.skipped_as_complete.append(testcase)
      continue
    if not _is_job_valid(testcase):
      categorized.skipped_for_invalid_job.append(testcase)
      continue
    if _is_in_cooldown(testcase, cooldown_deadline):
      categorized.skipped_for_cooldown.append(testcase)
      continue
    if _has_reached_max_attempts(testcase, max_retry_attempts):
      categorized.skipped_max_attempts.append(testcase)
      continue
    categorized.to_restart.append(testcase)
  return categorized


def _log_verbose_summary(total_from_query: int, results: CategorizedTestcases):
  """
  Prints a detailed, verbose summary of the filtering results.
  """
  logs.info(f"""
    Analysis phase complete.
    Total candidates from query: {total_from_query}
    -------------------------------------------------------------------
    Skipped (already complete): {len(results.skipped_as_complete)}
    Skipped (job no longer exists): {len(results.skipped_for_invalid_job)}
    Skipped (in cooldown period): {len(results.skipped_for_cooldown)}
    Skipped (max attempts reached): {len(results.skipped_max_attempts)}
    -------------------------------------------------------------------
    Testcases to be restarted: {len(results.to_restart)}
    """)

  for testcase in results.skipped_max_attempts:
    attempt_count = testcase.get_metadata(RETRY_ATTEMPT_COUNT_KEY) or 0
    logs.error(f'Testcase {_get_testcase_id(testcase)} is permanently stuck. '
               f'It failed to recover after {attempt_count} attempts. '
               'Please investigate manually.')


@logs.cron_log_context()
def main():
  """
  Finds, filters, and restarts stuck testcases in a three-phase process.
  """
  logs.info("Stuck testcase recovery cron started.")

  config = _get_script_config()
  query = _get_stuck_testcase_candidates_query(config.stuck_deadline)

  all_candidates = list(query)

  categorized_results = _filter_and_categorize_candidates(
      all_candidates, config.cooldown_deadline, config.max_retry_attempts)

  _log_verbose_summary(len(all_candidates), categorized_results)

  restarted_count = _restart_analysis_for_testcases(
      categorized_results.to_restart, config.restarts_per_run_limit)

  logs.info(
      f"Stuck testcase recovery cron finished. {len(all_candidates)} "
      f"candidates analyzed, {restarted_count} stuck testcases were restarted.")

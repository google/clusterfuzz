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
before remediation, providing a clear and verbose summary of its findings.
"""

import argparse
import datetime
from typing import cast
from typing import NamedTuple

from google.cloud import ndb  # pylint: disable=no-name-in-module

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs

RETRY_ATTEMPT_COUNT_KEY = "retry_stuck_task_attempt_count"
RETRY_LAST_ATTEMPT_TIME_KEY = "retry_stuck_task_last_attempt_time"


class ScriptConfig(NamedTuple):
  """Contains the configuration parameters for the cron job."""

  stuck_deadline: datetime.datetime
  cooldown_deadline: datetime.datetime
  max_retry_attempts: int
  restarts_per_run_limit: int
  non_dry_run: bool


def _parse_script_args(args: list[str]) -> argparse.Namespace:
  """
  Defines and parses command-line arguments for the script.

  This function centralizes all configuration parameters, providing defaults
  and help text for each. This makes the script flexible, self-documenting,
  and easily configurable for different environments or testing scenarios.

  Args:
    args: The list of string arguments passed to the script, typically from
          the `run_cron` executor.

  Returns:
    An argparse.Namespace object containing the parsed arguments.
  """
  parser = argparse.ArgumentParser(
      description="Find and restart stuck testcases.")
  parser.add_argument(
      "--stuck-deadline-hours",
      type=int,
      default=8,
      help="The deadline in hours for considering a testcase as 'stuck'.")
  parser.add_argument(
      "--cooldown-hours",
      type=int,
      default=4,
      help="The cooldown period in hours before retrying the same testcase.")
  parser.add_argument(
      "--max-retries",
      type=int,
      default=3,
      help="The maximum number of retry attempts for a single testcase.")
  parser.add_argument(
      "--restarts-per-run-limit",
      type=int,
      default=10,
      help="A safety throttle for the max number of restarts per cron run.")
  parser.add_argument(
      "--non-dry-run",
      action="store_true",
      default=False,
      help="If set, the script will perform write operations (create tasks, "
      "update metadata). Otherwise, it only logs what it would do.")
  return parser.parse_args(args)


def _get_script_config(parsed_args: argparse.Namespace) -> ScriptConfig:
  """
  Creates the ScriptConfig object from parsed command-line arguments.

  This function translates the raw arguments (like hours) into the
  concrete values needed for the script's logic, such as calculated datetime
  objects based on the current time.

  Args:
    parsed_args: The namespace object from ArgumentParser containing the
                 script's parameters.

  Returns:
    A final, immutable ScriptConfig object to be used by the script.
  """
  stuck_deadline = utils.utcnow() - datetime.timedelta(
      hours=parsed_args.stuck_deadline_hours)
  cooldown_deadline = utils.utcnow() - datetime.timedelta(
      hours=parsed_args.cooldown_hours)

  return ScriptConfig(stuck_deadline=stuck_deadline,
                      cooldown_deadline=cooldown_deadline,
                      max_retry_attempts=parsed_args.max_retries,
                      restarts_per_run_limit=parsed_args.restarts_per_run_limit,
                      non_dry_run=parsed_args.non_dry_run)


def _get_stuck_testcase_candidates_query(
    stuck_deadline: datetime.datetime,) -> ndb.Query:
  """
  Builds the Datastore query for potentially stuck testcases.

  The query is carefully constructed to fetch only relevant candidates. It
  filters for testcases that are still open, valid, and have not been updated
  recently, indicating they may be stalled. It specifically targets testcases
  in 'Processed' or 'Duplicate' status and those not marked as 'NA' for the
  'fixed' property, although this last filter has significant performance
  implications.

  Args:
    stuck_deadline: The datetime threshold. Testcases updated more recently
      than this will be ignored.

  Returns:
    An ndb.Query object for the candidate testcases.
  """
  return data_types.Testcase.query(
      data_types.Testcase.fixed != "NA",
      ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag),
      ndb_utils.is_true(data_types.Testcase.open),
      ndb.OR(data_types.Testcase.status == "Processed",
             data_types.Testcase.status == "Duplicate"),
      ndb.FilterNode("timestamp", "<", stuck_deadline))


def _get_testcase_id(testcase: data_types.Testcase) -> str:
  """
  Safely retrieves the string representation of the testcase's ID.

  This helper function assumes the testcase and its key are valid, as it's
  called on entities successfully fetched from Datastore. It uses
  typing.cast to inform static type checkers about the type of the ndb.Key,
  resolving potential linting errors. It converts the native integer ID to a
  string for consistent use in logging and task arguments.

  Args:
    testcase: The Testcase entity from which to extract the ID.

  Returns:
    The string representation of the testcase ID.
  """
  key = cast(ndb.Key, testcase.key)
  return str(key.id())


def _is_job_valid(testcase: data_types.Testcase) -> bool:
  """
  Checks if the job associated with a testcase still exists.

  This validation prevents the script from crashing when processing legacy
  testcases whose original jobs might have been deleted or renamed. It performs
  a direct and efficient query against the 'Job' entity using
  `.get(keys_only=True)` to minimize cost and latency, as it only needs to
  verify existence.

  Args:
    testcase: The Testcase entity to check.

  Returns:
    True if the job exists, False otherwise.
  """
  job_exists_query = data_types.Job.query(
      data_types.Job.name == testcase.job_type)
  if not job_exists_query.get(keys_only=True):
    logs.error(
        f"Skipping testcase {_get_testcase_id(testcase)} because its job "
        f"'{testcase.job_type}' no longer exists in Job entities.")
    return False
  return True


def _is_in_cooldown(testcase: data_types.Testcase,
                    cooldown_deadline: datetime.datetime) -> bool:
  """
  Checks if a restart was recently attempted for this testcase by this cron.

  This check makes the script idempotent by reading a custom metadata
  timestamp. This prevents creating duplicate tasks if the cron runs more
  frequently than the cooldown period allows.

  Args:
    testcase: The Testcase entity to check.
    cooldown_deadline: The datetime threshold for the cooldown period.

  Returns:
    True if a restart was attempted within the cooldown window.
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
  indefinitely. It reads a custom metadata counter, handling missing values
  gracefully by treating them as 0. If the limit is met or exceeded, the
  testcase is considered "permanently stuck" and should be escalated.

  Args:
    testcase: The Testcase entity to check.
    max_attempts: The integer limit for retry attempts.

  Returns:
    True if the attempt count is greater than or equal to the maximum.
  """
  attempt_count = testcase.get_metadata(RETRY_ATTEMPT_COUNT_KEY) or 0
  return attempt_count >= max_attempts


def _get_stuck_reason(testcase: data_types.Testcase) -> str:
  """
  Analyzes a testcase to generate a human-readable reason for why it's stuck.

  This function mirrors the logic of `data_handler.critical_tasks_completed`
  to identify which specific analysis steps (e.g., minimization, regression)
  are missing, providing a clear reason for the restart action.

  Args:
    testcase: The stuck Testcase entity.

  Returns:
    A string detailing the missing critical tasks.
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
    data_types.Testcase], config: ScriptConfig) -> int:
  """
  Performs the remediation action for a final list of stuck testcases.

  This function iterates through the pre-filtered list and applies the fix
  to each testcase. For each one, it logs a detailed warning, enqueues a new
  'minimize' task via the safe `task_creation` module, and updates the
  testcase's metadata to track the retry attempt for idempotency. It stops
  if the per-run restart limit is reached.

  Args:
    testcases_to_restart: A list of Testcase entities that need remediation.
    config: The script's configuration object.

  Returns:
    The number of testcases for which a restart was successfully triggered.
  """
  restarted_count = 0
  for testcase in testcases_to_restart:
    testcase_id = _get_testcase_id(testcase)
    stuck_reason = _get_stuck_reason(testcase)

    attempt_count = testcase.get_metadata(RETRY_ATTEMPT_COUNT_KEY) or 0

    logs.warning(f"Retriggering 'minimize' for stuck testcase {testcase_id}. "
                 f"(Attempt #{attempt_count + 1}). "
                 f"Reason: Testcase {stuck_reason}. "
                 f"Details: [Job: {testcase.job_type}, "
                 f"Crash Type: {testcase.crash_type}, "
                 f"Fuzzer: {testcase.fuzzer_name}]")

    if config.non_dry_run:
      task_creation.create_minimize_task_if_needed(testcase)

      testcase.set_metadata(RETRY_ATTEMPT_COUNT_KEY, attempt_count + 1)
      testcase.set_metadata(RETRY_LAST_ATTEMPT_TIME_KEY, utils.utcnow())
      testcase.put()

    restarted_count += 1

    if restarted_count >= config.restarts_per_run_limit:
      logs.info(f"Reached the limit of {config.restarts_per_run_limit} "
                "restarts for this run. Exiting remediation loop.")
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

  This is the main filtering pass. For each candidate, it applies a series of
  guard clauses in a specific order. If a testcase fails a check, it is added
  to the appropriate "skipped" list and the next candidate is processed. This
  ensures only truly actionable testcases reach the final `to_restart` list.

  Args:
    candidates: A list of candidate Testcase entities.
    config: The script's configuration object.

  Returns:
    A CategorizedTestcases named tuple containing lists for each category.
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
  Prints a detailed, verbose summary of the filtering phase.

  This function provides a clear, human-readable summary of the script's
  findings *before* any remediation actions are taken. It also explicitly logs
  an error for each testcase that has been given up on, escalating them for
  manual review and increasing data integrity visibility.
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
    logs.error(f"Testcase {_get_testcase_id(testcase)} is permanently stuck. "
               f"It failed to recover after {attempt_count} attempts. "
               "Please investigate manually.")


@logs.cron_log_context()
def main(args: list[str]):
  """
  Finds, filters, and restarts stuck testcases in a three-phase process.

  The workflow is designed for clarity, safety, and observability:
  1. Parse arguments and configure the run.
  2. Query the database to fetch a broad list of potential candidates.
  3. Filter and categorize all candidates in memory.
  4. Log a verbose summary of the findings.
  5. Act only on the final, validated list of testcases that need a restart.
  """
  parsed_args = _parse_script_args(args)

  config = _get_script_config(parsed_args)

  logs.info("Stuck testcase recovery cron started.")

  query = _get_stuck_testcase_candidates_query(config.stuck_deadline)

  all_candidates = list(query)

  categorized_results = _filter_and_categorize_candidates(
      all_candidates, config.cooldown_deadline, config.max_retry_attempts)

  _log_verbose_summary(len(all_candidates), categorized_results)

  restarted_count = _restart_analysis_for_testcases(
      categorized_results.to_restart, config)

  logs.info(
      f"Stuck testcase recovery cron finished. {len(all_candidates)} "
      f"candidates analyzed, {restarted_count} stuck testcases were restarted.")

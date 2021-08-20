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
"""Cleanup task for cleaning up unneeded testcases."""

import collections
import datetime
import json

from googleapiclient.errors import HttpError

from clusterfuzz._internal.base import dates
from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.chrome import build_info
from clusterfuzz._internal.crash_analysis import crash_comparer
from clusterfuzz._internal.crash_analysis import severity_analyzer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.fuzzing import leak_blacklist
from clusterfuzz._internal.metrics import crash_stats
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler
from libs import mail
from libs.issue_management import issue_filer
from libs.issue_management import issue_tracker_policy
from libs.issue_management import issue_tracker_utils

GENERIC_INCORRECT_COMMENT = (
    '\n\nIf this is incorrect, please add the {label_text}')
OSS_FUZZ_INCORRECT_COMMENT = ('\n\nIf this is incorrect, please file a bug on '
                              'https://github.com/google/oss-fuzz/issues/new')

TOP_CRASHES_LIMIT = 5
TOP_CRASHES_DAYS_LOOKBEHIND = 7
TOP_CRASHES_MIN_THRESHOLD = 50 * TOP_CRASHES_DAYS_LOOKBEHIND
TOP_CRASHES_IGNORE_CRASH_TYPES = [
    'Out-of-memory',
    'Stack-overflow',
    'Timeout',
]
TOP_CRASHES_IGNORE_CRASH_STATES = ['NULL']

FUZZ_TARGET_UNUSED_THRESHOLD = 15
UNUSED_HEARTBEAT_THRESHOLD = 15

ProjectMap = collections.namedtuple('ProjectMap', 'jobs platforms')


def _get_predator_result_item(testcase, key, default=None):
  """Return the suspected components for a test case."""
  predator_result = testcase.get_metadata('predator_result')
  if not predator_result:
    return default

  return predator_result['result'].get(key, default)


def _append_generic_incorrect_comment(comment, policy, issue, suffix):
  """Get the generic incorrect comment."""
  wrong_label = policy.label('wrong')
  if not wrong_label:
    return comment

  return comment + GENERIC_INCORRECT_COMMENT.format(
      label_text=issue.issue_tracker.label_text(wrong_label)) + suffix


def job_platform_to_real_platform(job_platform):
  """Get real platform from job platform."""
  for platform in data_types.PLATFORMS:
    if platform in job_platform:
      return platform

  raise ValueError('Unknown platform: ' + job_platform)


def cleanup_reports_metadata():
  """Delete ReportMetadata for uploaded reports."""
  uploaded_reports = ndb_utils.get_all_from_query(
      data_types.ReportMetadata.query(
          ndb_utils.is_true(data_types.ReportMetadata.is_uploaded)),
      keys_only=True)
  ndb_utils.delete_multi(uploaded_reports)


def cleanup_testcases_and_issues():
  """Clean up unneeded open testcases and their associated issues."""
  jobs = data_handler.get_all_job_type_names()
  testcase_keys = ndb_utils.get_all_from_query(
      data_types.Testcase.query(
          ndb_utils.is_false(data_types.Testcase.triaged)),
      keys_only=True)
  top_crashes_by_project_and_platform_map = (
      get_top_crashes_for_all_projects_and_platforms())

  utils.python_gc()

  testcases_processed = 0
  empty_issue_tracker_policy = issue_tracker_policy.get_empty()
  for testcase_key in testcase_keys:
    testcase_id = testcase_key.id()
    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      # Already deleted.
      continue

    logs.log('Processing testcase %d.' % testcase_id)

    try:
      issue = issue_tracker_utils.get_issue_for_testcase(testcase)
      policy = issue_tracker_utils.get_issue_tracker_policy_for_testcase(
          testcase)
      if not policy:
        policy = empty_issue_tracker_policy

      # Issue updates.
      update_os_labels(policy, testcase, issue)
      update_fuzz_blocker_label(policy, testcase, issue,
                                top_crashes_by_project_and_platform_map)
      update_component_labels(testcase, issue)
      update_issue_ccs_from_owners_file(policy, testcase, issue)
      update_issue_owner_and_ccs_from_predator_results(policy, testcase, issue)
      update_issue_labels_for_flaky_testcase(policy, testcase, issue)

      # Testcase marking rules.
      mark_duplicate_testcase_as_closed_with_no_issue(testcase)
      mark_issue_as_closed_if_testcase_is_fixed(policy, testcase, issue)
      mark_testcase_as_closed_if_issue_is_closed(policy, testcase, issue)
      mark_testcase_as_closed_if_job_is_invalid(testcase, jobs)
      mark_unreproducible_testcase_as_fixed_if_issue_is_closed(testcase, issue)
      mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
          policy, testcase, issue)
      mark_na_testcase_issues_as_wontfix(policy, testcase, issue)

      # Notification, to be done at end after testcase state is updated from
      # previous rules.
      notify_closed_issue_if_testcase_is_open(policy, testcase, issue)
      notify_issue_if_testcase_is_invalid(policy, testcase, issue)
      notify_uploader_when_testcase_is_processed(policy, testcase, issue)

      # Mark testcase as triage complete if both testcase and associated issue
      # are closed. This also need to be done before the deletion rules.
      mark_testcase_as_triaged_if_needed(testcase, issue)

      # Testcase deletion rules.
      delete_unreproducible_testcase_with_no_issue(testcase)
    except Exception:
      logs.log_error('Failed to process testcase %d.' % testcase_id)

    testcases_processed += 1
    if testcases_processed % 100 == 0:
      utils.python_gc()


def cleanup_unused_fuzz_targets_and_jobs():
  """Clean up unused FuzzTarget and FuzzTargetJob entities."""
  last_run_cutoff = utils.utcnow() - datetime.timedelta(
      days=FUZZ_TARGET_UNUSED_THRESHOLD)

  unused_target_jobs = data_types.FuzzTargetJob.query(
      data_types.FuzzTargetJob.last_run < last_run_cutoff)
  valid_target_jobs = data_types.FuzzTargetJob.query(
      data_types.FuzzTargetJob.last_run >= last_run_cutoff)

  to_delete = [t.key for t in unused_target_jobs]

  valid_fuzz_targets = set(t.fuzz_target_name for t in valid_target_jobs)
  for fuzz_target in ndb_utils.get_all_from_model(data_types.FuzzTarget):
    if fuzz_target.fully_qualified_name() not in valid_fuzz_targets:
      to_delete.append(fuzz_target.key)

  ndb_utils.delete_multi(to_delete)


def get_jobs_and_platforms_for_project():
  """Return a map of projects to jobs and platforms map to use for picking top
  crashes."""
  all_jobs = ndb_utils.get_all_from_model(data_types.Job)
  projects_to_jobs_and_platforms = {}
  for job in all_jobs:
    job_environment = job.get_environment()

    # Skip experimental jobs.
    if utils.string_is_true(job_environment.get('EXPERIMENTAL')):
      continue

    # Skip custom binary jobs.
    if (utils.string_is_true(job_environment.get('CUSTOM_BINARY')) or
        job_environment.get('SYSTEM_BINARY_DIR')):
      continue

    # Skip if explicitly excluded using flag.
    if utils.string_is_true(job_environment.get('EXCLUDE_FROM_TOP_CRASHES')):
      continue

    if job.project not in projects_to_jobs_and_platforms:
      projects_to_jobs_and_platforms[job.project] = ProjectMap(set(), set())

    projects_to_jobs_and_platforms[job.project].jobs.add(job.name)
    projects_to_jobs_and_platforms[job.project].platforms.add(
        job_platform_to_real_platform(job.platform))

  return projects_to_jobs_and_platforms


@memoize.wrap(memoize.Memcache(12 * 60 * 60))
def _get_crash_occurrence_platforms_from_crash_parameters(
    crash_type, crash_state, security_flag, project_name, lookbehind_days):
  """Get platforms from crash stats based on crash parameters."""
  last_hour = crash_stats.get_last_successful_hour()
  if not last_hour:
    # No crash stats available, skip.
    return []

  where_clause = ('crash_type = {crash_type} AND '
                  'crash_state = {crash_state} AND '
                  'security_flag = {security_flag} AND '
                  'project = {project}').format(
                      crash_type=json.dumps(crash_type),
                      crash_state=json.dumps(crash_state),
                      security_flag=json.dumps(security_flag),
                      project=json.dumps(project_name),
                  )

  _, rows = crash_stats.get(
      end=last_hour,
      block='day',
      days=lookbehind_days,
      group_by='platform',
      where_clause=where_clause,
      group_having_clause='',
      sort_by='total_count',
      offset=0,
      limit=1)

  platforms = set()
  for row in rows:
    for group in row['groups']:
      platform = group['name'].split(':')[0]
      platforms.add(platform.lower())
  return list(platforms)


def get_platforms_from_testcase_variants(testcase):
  """Get platforms from crash stats based on crash parameters."""
  variant_query = data_types.TestcaseVariant.query(
      data_types.TestcaseVariant.testcase_id == testcase.key.id())
  platforms = {
      variant.platform
      for variant in variant_query
      if variant.is_similar and variant.platform
  }
  return platforms


def get_crash_occurrence_platforms(testcase, lookbehind_days=1):
  """Get platforms from crash stats for a testcase."""
  return set(
      _get_crash_occurrence_platforms_from_crash_parameters(
          testcase.crash_type, testcase.crash_state, testcase.security_flag,
          testcase.project_name, lookbehind_days))


def get_top_crashes_for_all_projects_and_platforms():
  """Return top crashes for all projects and platforms."""
  last_hour = crash_stats.get_last_successful_hour()
  if not last_hour:
    # No crash stats available, skip.
    return {}

  projects_to_jobs_and_platforms = (get_jobs_and_platforms_for_project())
  top_crashes_by_project_and_platform_map = {}

  for project_name, project_map in projects_to_jobs_and_platforms.items():
    top_crashes_by_project_and_platform_map[project_name] = {}

    for platform in project_map.platforms:
      where_clause = (
          'crash_type NOT IN UNNEST(%s) AND '
          'crash_state NOT IN UNNEST(%s) AND '
          'job_type IN UNNEST(%s) AND '
          'platform LIKE %s AND '
          'project = %s' % (json.dumps(TOP_CRASHES_IGNORE_CRASH_TYPES),
                            json.dumps(TOP_CRASHES_IGNORE_CRASH_STATES),
                            json.dumps(list(project_map.jobs)),
                            json.dumps(platform.lower() + '%'),
                            json.dumps(project_name)))

      _, rows = crash_stats.get(
          end=last_hour,
          block='day',
          days=TOP_CRASHES_DAYS_LOOKBEHIND,
          group_by='platform',
          where_clause=where_clause,
          group_having_clause='',
          sort_by='total_count',
          offset=0,
          limit=TOP_CRASHES_LIMIT)
      if not rows:
        continue

      top_crashes_by_project_and_platform_map[project_name][platform] = [{
          'crashState': row['crashState'],
          'crashType': row['crashType'],
          'isSecurity': row['isSecurity'],
          'totalCount': row['totalCount'],
      } for row in rows if row['totalCount'] >= TOP_CRASHES_MIN_THRESHOLD]

  return top_crashes_by_project_and_platform_map


def get_top_crash_platforms(testcase, top_crashes_by_project_and_platform_map):
  """Return list of platforms where this testcase is a top crasher."""
  if testcase.project_name not in top_crashes_by_project_and_platform_map:
    return []

  top_crashes_by_platform_map = top_crashes_by_project_and_platform_map[
      testcase.project_name]
  top_crash_platforms = set()
  for platform in list(top_crashes_by_platform_map.keys()):
    top_crashes = top_crashes_by_platform_map[platform]
    if not top_crashes:
      continue

    for top_crash in top_crashes:
      crash_state_comparer = crash_comparer.CrashComparer(
          top_crash['crashState'], testcase.crash_state)
      crash_type_comparer = crash_comparer.CrashComparer(
          top_crash['crashType'], testcase.crash_type)
      if (crash_state_comparer.is_similar() and
          top_crash['isSecurity'] == testcase.security_flag and
          (top_crash['isSecurity'] or crash_type_comparer.is_similar())):
        top_crash_platforms.add(platform.lower())

  return sorted(list(top_crash_platforms))


def delete_unreproducible_testcase_with_no_issue(testcase):
  """Delete an unreproducible testcase if it has no associated issue and has
  been open for a certain time interval."""
  # Make sure that this testcase is an unreproducible bug. If not, bail out.
  if not testcase.one_time_crasher_flag:
    return

  # Make sure that this testcase has no associated bug. If not, bail out.
  if testcase.bug_information:
    return

  # Make sure that testcase is atleast older than
  # |UNREPRODUCIBLE_TESTCASE_NO_BUG_DEADLINE|, otherwise it will be seen in
  # crash stats anyway.
  if (testcase.timestamp and not dates.time_has_expired(
      testcase.timestamp,
      days=data_types.UNREPRODUCIBLE_TESTCASE_NO_BUG_DEADLINE)):
    return

  # Make sure that testcase is not seen in crash stats for a certain time
  # interval.
  if get_crash_occurrence_platforms(
      testcase, data_types.UNREPRODUCIBLE_TESTCASE_NO_BUG_DEADLINE):
    return

  testcase.key.delete()
  logs.log(
      'Deleted unreproducible testcase %d with no issue.' % testcase.key.id())


def mark_duplicate_testcase_as_closed_with_no_issue(testcase):
  """Closes a duplicate testcase if it has no associated issue and has been open
  for a certain time interval."""
  # Make sure that this testcase is a duplicate bug. If not, bail out.
  if testcase.status != 'Duplicate':
    return

  # Make sure that this testcase has no associated bug. If not, bail out.
  if testcase.bug_information:
    return

  # Make sure that testcase has been open for a certain time interval. We do
  # a null timestamp check since some older testcases could be missing it.
  if (testcase.timestamp and not dates.time_has_expired(
      testcase.timestamp, days=data_types.DUPLICATE_TESTCASE_NO_BUG_DEADLINE)):
    return

  testcase.fixed = 'NA'
  testcase.open = False
  testcase.put()
  logs.log('Closed duplicate testcase %d with no issue.' % testcase.key.id())


def mark_issue_as_closed_if_testcase_is_fixed(policy, testcase, issue):
  """Mark an issue as fixed if all of its associated reproducible testcase are
  fixed."""
  verified_label = policy.label('verified')
  if not verified_label:
    return

  # If there is no associated issue, then bail out.
  if not issue or not testcase.bug_information:
    return

  # If the issue is closed in a status other than Fixed, like Duplicate, WontFix
  # or Archived, we shouldn't change it. Bail out.
  if not issue.is_open and issue.status != policy.status('fixed'):
    return

  # Check testcase status, so as to skip unreproducible uploads.
  if testcase.status not in ['Processed', 'Duplicate']:
    return

  # If the testcase is still open, no work needs to be done. Bail out.
  if testcase.open:
    return

  # FIXME: Find a better solution to skip over reproducible tests that are now
  # showing up a flaky (esp when we are unable to reproduce crash in original
  # crash revision).
  if testcase.fixed == 'NA':
    return

  # We can only verify fixed issues for reproducible testcases. If the testcase
  # is unreproducible, bail out. Exception is if we explicitly marked this as
  # fixed.
  if testcase.one_time_crasher_flag and testcase.fixed != 'Yes':
    return

  # Make sure that no other testcases associated with this issue are open.
  similar_testcase = data_types.Testcase.query(
      data_types.Testcase.bug_information == testcase.bug_information,
      ndb_utils.is_true(data_types.Testcase.open),
      ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag)).get()
  if similar_testcase:
    return

  # As a last check, do the expensive call of actually checking all issue
  # comments to make sure we didn't do the verification already and we didn't
  # get called out on issue mistriage.
  if (issue_tracker_utils.was_label_added(issue, verified_label) or
      issue_tracker_utils.was_label_added(issue, policy.label('wrong'))):
    return

  issue.labels.add(verified_label)
  comment = 'ClusterFuzz testcase %d is verified as fixed' % testcase.key.id()

  fixed_range_url = data_handler.get_fixed_range_url(testcase)
  if fixed_range_url:
    comment += ' in ' + fixed_range_url
  else:
    comment += '.'

  if utils.is_oss_fuzz():
    comment += OSS_FUZZ_INCORRECT_COMMENT
  else:
    comment = _append_generic_incorrect_comment(comment, policy, issue,
                                                ' and re-open the issue.')

  skip_auto_close = data_handler.get_value_from_job_definition(
      testcase.job_type, 'SKIP_AUTO_CLOSE_ISSUE')
  if not skip_auto_close:
    issue.status = policy.status('verified')

  issue.save(new_comment=comment, notify=True)
  logs.log('Mark issue %d as verified for fixed testcase %d.' %
           (issue.id, testcase.key.id()))
  issue_filer.notify_issue_update(testcase, 'verified')


def mark_unreproducible_testcase_as_fixed_if_issue_is_closed(testcase, issue):
  """Mark an unreproducible testcase as fixed if the associated issue is
  closed."""
  # If the testcase is already closed, no more work to do.
  if not testcase.open:
    return

  # Make sure that this testcase is an unreproducible bug. If not, bail out.
  if not testcase.one_time_crasher_flag:
    return

  # Make sure that this testcase has an associated bug. If not, bail out.
  if not testcase.bug_information:
    return

  # Make sure that there is an associated bug and it is in closed state.
  if not issue or issue.is_open:
    return

  testcase.fixed = 'NA'
  testcase.open = False
  testcase.put()
  logs.log('Closed unreproducible testcase %d with issue closed.' %
           testcase.key.id())


def mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
    policy, testcase, issue):
  """Closes an unreproducible testcase and its associated issue after a certain
  time period."""
  # If the testcase is already closed, no more work to do.
  if not testcase.open:
    return

  # Check testcase status, so as to skip unreproducible uploads.
  if testcase.status not in ['Processed', 'Duplicate']:
    return

  # Make sure that this testcase is an unreproducible bug. If not, bail out.
  if not testcase.one_time_crasher_flag:
    return

  # Make sure that this testcase has an associated bug. If not, bail out.
  if not testcase.bug_information:
    return

  # If this testcase was manually uploaded, don't change issue state as our
  # reproduction result might be incorrect.
  if testcase.uploader_email:
    return

  # Make sure that there is an associated bug and it is in open state.
  if not issue or not issue.is_open:
    return

  # Skip closing if flag is set.
  skip_auto_close = data_handler.get_value_from_job_definition(
      testcase.job_type, 'SKIP_AUTO_CLOSE_ISSUE')
  if skip_auto_close:
    return

  # Check if there are any reproducible open testcases are associated with
  # this bug. If yes, return.
  similar_testcase = data_types.Testcase.query(
      data_types.Testcase.bug_information == testcase.bug_information,
      ndb_utils.is_true(data_types.Testcase.open),
      ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag)).get()
  if similar_testcase:
    return

  # Make sure that testcase is atleast older than
  # |UNREPRODUCIBLE_TESTCASE_WITH_BUG_DEADLINE|, otherwise it will be seen in
  # crash stats anyway.
  if (testcase.timestamp and not dates.time_has_expired(
      testcase.timestamp,
      days=data_types.UNREPRODUCIBLE_TESTCASE_WITH_BUG_DEADLINE)):
    return

  # Handle testcase that turned from reproducible to unreproducible. Account
  # for the recent progression task run time.
  last_tested_crash_time = testcase.get_metadata('last_tested_crash_time')
  if (last_tested_crash_time and not dates.time_has_expired(
      last_tested_crash_time,
      days=data_types.UNREPRODUCIBLE_TESTCASE_WITH_BUG_DEADLINE)):
    return

  # Make that there is no crash seen in the deadline period.
  if get_crash_occurrence_platforms(
      testcase, data_types.UNREPRODUCIBLE_TESTCASE_WITH_BUG_DEADLINE):
    return

  # As a last check, do the expensive call of actually checking all issue
  # comments to make sure we we didn't get called out on issue mistriage.
  if issue_tracker_utils.was_label_added(issue, policy.label('wrong')):
    return

  # Close associated issue and testcase.
  comment = ('ClusterFuzz testcase %d is flaky and no longer crashes, '
             'so closing issue.' % testcase.key.id())
  if utils.is_oss_fuzz():
    comment += OSS_FUZZ_INCORRECT_COMMENT
  else:
    comment = _append_generic_incorrect_comment(comment, policy, issue,
                                                ' and re-open the issue.')

  skip_auto_close = data_handler.get_value_from_job_definition(
      testcase.job_type, 'SKIP_AUTO_CLOSE_ISSUE')
  if not skip_auto_close:
    issue.status = policy.status('wontfix')

  issue.save(new_comment=comment, notify=True)
  testcase.fixed = 'NA'
  testcase.open = False
  testcase.put()

  logs.log('Closed unreproducible testcase %d and associated issue.' %
           testcase.key.id())


def mark_na_testcase_issues_as_wontfix(policy, testcase, issue):
  """Mark issues for testcases with fixed == 'NA' as fixed."""
  # Check for for closed, NA testcases.
  if testcase.open or testcase.fixed != 'NA':
    return

  # Nothing to be done if no issue is attached, or if issue is already closed.
  if not issue or not issue.is_open:
    return

  # Make sure that no other testcases associated with this issue are open.
  similar_testcase = data_types.Testcase.query(
      data_types.Testcase.bug_information == testcase.bug_information,
      ndb_utils.is_true(data_types.Testcase.open),
      ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag)).get()
  if similar_testcase:
    return

  # Make that there is no crash seen in the deadline period.
  if get_crash_occurrence_platforms(
      testcase, data_types.UNREPRODUCIBLE_TESTCASE_WITH_BUG_DEADLINE):
    return

  # As a last check, do the expensive call of actually checking all issue
  # comments to make sure we we didn't get called out on issue mistriage.
  if issue_tracker_utils.was_label_added(issue, policy.label('wrong')):
    return

  comment = (f'ClusterFuzz testcase {testcase.key.id()} is closed as invalid, '
             'so closing issue.')

  skip_auto_close = data_handler.get_value_from_job_definition(
      testcase.job_type, 'SKIP_AUTO_CLOSE_ISSUE')
  if not skip_auto_close:
    issue.status = policy.status('wontfix')

  issue.save(new_comment=comment, notify=True)
  logs.log(
      f'Closing issue {issue.id} for invalid testcase {testcase.key.id()}.')


def mark_testcase_as_triaged_if_needed(testcase, issue):
  """Mark testcase as triage complete if both testcase and associated issue
  are closed."""
  # Check if testcase is open. If yes, bail out.
  if testcase.open:
    return

  # Check if there is an associated bug in open state. If yes, bail out.
  if issue:
    # Get latest issue object to ensure our update went through.
    issue = issue_tracker_utils.get_issue_for_testcase(testcase)
    if issue.is_open:
      return

  testcase.triaged = True
  testcase.put()


def mark_testcase_as_closed_if_issue_is_closed(policy, testcase, issue):
  """Mark testcase as closed if the associated issue is closed."""
  # If the testcase is already closed, no more work to do.
  if not testcase.open:
    return

  # If there is no associated issue, then bail out.
  if not issue or not testcase.bug_information:
    return

  # If the issue is still open, no work needs to be done. Bail out.
  if issue.is_open:
    return

  # Make sure we passed our deadline based on issue closed timestamp.
  if (issue.closed_time and not dates.time_has_expired(
      issue.closed_time,
      days=data_types.CLOSE_TESTCASE_WITH_CLOSED_BUG_DEADLINE)):
    return

  # If the issue has an ignore label, don't close the testcase and bail out.
  # This helps to prevent new bugs from getting filed for legit WontFix cases.
  if issue_tracker_utils.was_label_added(issue, policy.label('ignore')):
    return

  testcase.open = False
  testcase.fixed = 'NA'
  testcase.put()
  logs.log('Closed testcase %d with issue closed.' % testcase.key.id())


def mark_testcase_as_closed_if_job_is_invalid(testcase, jobs):
  """Mark testcase as closed if the associated job type does not exist."""
  # If the testcase is already closed, no more work to do.
  if not testcase.open:
    return

  # Check if the testcase job name is in the list of jobs.
  if testcase.job_type in jobs:
    return

  testcase.open = False
  testcase.fixed = 'NA'
  testcase.put()
  logs.log('Closed testcase %d with invalid job.' % testcase.key.id())


def notify_closed_issue_if_testcase_is_open(policy, testcase, issue):
  """Notify closed issue if associated testcase is still open after a certain
  time period."""
  needs_feedback_label = policy.label('needs_feedback')
  if not needs_feedback_label:
    return

  # If the testcase is already closed, no more work to do.
  if not testcase.open:
    return

  # Check testcase status, so as to skip unreproducible uploads.
  if testcase.status not in ['Processed', 'Duplicate']:
    return

  # If there is no associated issue, then bail out.
  if not issue or not testcase.bug_information:
    return

  # If the issue is still open, no work needs to be done. Bail out.
  if issue.is_open:
    return

  # If we have already passed our deadline based on issue closed timestamp,
  # no need to notify. We will close the testcase instead.
  if (issue.closed_time and not dates.time_has_expired(
      issue.closed_time,
      days=data_types.NOTIFY_CLOSED_BUG_WITH_OPEN_TESTCASE_DEADLINE)):
    return

  # Check if there is ignore label on issue already. If yes, bail out.
  if issue_tracker_utils.was_label_added(issue, policy.label('ignore')):
    return

  # Check if we did add the notification comment already. If yes, bail out.
  if issue_tracker_utils.was_label_added(issue, needs_feedback_label):
    return

  issue.labels.add(needs_feedback_label)

  if issue.status in [policy.status('fixed'), policy.status('verified')]:
    issue_comment = (
        'ClusterFuzz testcase {id} is still reproducing on tip-of-tree build '
        '(trunk).\n\nPlease re-test your fix against this testcase and if the '
        'fix was incorrect or incomplete, please re-open the bug.'
    ).format(id=testcase.key.id())

    wrong_label = policy.label('wrong')
    if wrong_label:
      issue_comment += (
          (' Otherwise, ignore this notification and add the '
           '{label_text}.'
          ).format(label_text=issue.issue_tracker.label_text(wrong_label)))
  else:
    # Covers WontFix, Archived cases.
    issue_comment = (
        'ClusterFuzz testcase {id} is still reproducing on tip-of-tree build '
        '(trunk).\n\nIf this testcase was not reproducible locally or '
        'unworkable, ignore this notification and we will file another '
        'bug soon with hopefully a better and workable testcase.\n\n'.format(
            id=testcase.key.id()))
    ignore_label = policy.label('ignore')
    if ignore_label:
      issue_comment += (
          'Otherwise, if this is not intended to be fixed (e.g. this is an '
          'intentional crash), please add the {label_text} to '
          'prevent future bug filing with similar crash stacktrace.'.format(
              label_text=issue.issue_tracker.label_text(ignore_label)))

  issue.save(new_comment=issue_comment, notify=True)
  logs.log('Notified closed issue for open testcase %d.' % testcase.key.id())


def notify_issue_if_testcase_is_invalid(policy, testcase, issue):
  """Leave comments on associated issues when test cases are no longer valid."""
  invalid_fuzzer_label = policy.label('invalid_fuzzer')
  if not invalid_fuzzer_label:
    return

  if not issue or not testcase.bug_information:
    return

  # If the issue is closed, there's no work to do.
  if not issue.is_open:
    return

  # Currently, this only happens if a test case relies on a fuzzer that has
  # been deleted. This can be modified if more cases are needed in the future.
  if not testcase.get_metadata('fuzzer_was_deleted'):
    return

  # Check if we added this message once. If yes, bail out.
  if issue_tracker_utils.was_label_added(issue, invalid_fuzzer_label):
    return

  issue_comment = (
      'ClusterFuzz testcase %d is associated with an obsolete fuzzer and can '
      'no longer be processed. Please close the issue if it is no longer '
      'actionable.') % testcase.key.id()
  issue.labels.add(invalid_fuzzer_label)
  issue.save(new_comment=issue_comment, notify=True)

  logs.log('Closed issue %d for invalid testcase %d.' % (issue.id,
                                                         testcase.key.id()))


def _send_email_to_uploader(testcase_id, to_email, content):
  """Send email to uploader when all the testcase tasks are finished."""
  subject = 'Your testcase upload %d analysis is complete.' % testcase_id
  content_with_footer = (
      '%s\n\n'
      'If you suspect that the result above is incorrect, '
      'try re-doing that job on the testcase report page.') % content.strip()
  html_content = content_with_footer.replace('\n', '<br>')

  mail.send(to_email, subject, html_content)


def _get_severity_from_labels(security_severity_label, labels):
  """Get the severity from the label list."""
  pattern = issue_filer.get_label_pattern(security_severity_label)
  for label in labels:
    match = pattern.match(label)
    if match:
      return severity_analyzer.string_to_severity(match.group(1))

  return data_types.SecuritySeverity.MISSING


def _update_issue_security_severity_and_get_comment(policy, testcase, issue):
  """Apply a new security severity label if none exists on issue already
  and return a comment on this addition. If a label already exists and does
  not match security severity label on issue, then just return a comment on
  what the recommended severity is."""
  security_severity_label = policy.label('security_severity')
  if not security_severity_label:
    return ''

  if not data_types.SecuritySeverity.is_valid(testcase.security_severity):
    return ''

  issue_severity = _get_severity_from_labels(security_severity_label,
                                             issue.labels)

  recommended_severity = issue_filer.apply_substitutions(
      policy, security_severity_label, testcase)
  if not recommended_severity:
    return ''

  recommended_severity = recommended_severity[0]
  if issue_severity == data_types.SecuritySeverity.MISSING:
    issue.labels.add(recommended_severity)
    return ('\n\nA recommended severity was added to this bug. '
            'Please change the severity if it is inaccurate.')
  if issue_severity != testcase.security_severity:
    return (
        '\n\nThe recommended severity (%s) is different from what was assigned '
        'to the bug. Please double check the accuracy of the assigned '
        'severity.' % recommended_severity)

  return ''


def _update_issue_when_uploaded_testcase_is_processed(
    policy, testcase, issue, description, update_bug_summary, notify):
  """Add issue comment when uploaded testcase is processed."""
  if update_bug_summary and testcase.is_crash():
    issue.title = data_handler.get_issue_summary(testcase)

  # Impact labels like impacting head/beta/stable only apply for Chromium.
  if testcase.project_name == 'chromium':
    issue_filer.update_issue_impact_labels(testcase, issue)

  # Add severity labels for all project types.
  comment = description + _update_issue_security_severity_and_get_comment(
      policy, testcase, issue)
  issue.save(new_comment=comment, notify=notify)


def notify_uploader_when_testcase_is_processed(policy, testcase, issue):
  """Notify uploader by email when all the testcase tasks are finished."""
  testcase_id = testcase.key.id()

  # Check if this is a user upload. If not, bail out.
  upload_metadata = data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.testcase_id == testcase_id).get()
  if not upload_metadata:
    return

  # Check that we have a valid email to send the notification. If not, bail out.
  to_email = upload_metadata.uploader_email
  if not to_email:
    return

  # If this is a bundled archive with multiple testcases, then don't send email
  # for individual testcases.
  if upload_metadata.bundled:
    return

  # Check if the notification is already sent once. If yes, bail out.
  if data_handler.is_notification_sent(testcase_id, to_email):
    return

  # Make sure all testcase taks are done (e.g. minimization, regression, etc).
  if not data_handler.critical_tasks_completed(testcase):
    return

  notify = not upload_metadata.quiet_flag
  # If the same issue was specified at time of upload, update it.
  if (issue and str(issue.id) == upload_metadata.bug_information and
      not testcase.duplicate_of):
    issue_description = data_handler.get_issue_description(testcase)
    _update_issue_when_uploaded_testcase_is_processed(
        policy, testcase, issue, issue_description,
        upload_metadata.bug_summary_update_flag, notify)

  if notify:
    issue_description_without_crash_state = data_handler.get_issue_description(
        testcase, hide_crash_state=True)
    _send_email_to_uploader(testcase_id, to_email,
                            issue_description_without_crash_state)

  # Make sure to create notification entry, as we use this to update bug.
  data_handler.create_notification_entry(testcase_id, to_email)


def update_os_labels(policy, testcase, issue):
  """Add OS labels to issue."""
  os_label = policy.label('os')
  if not os_label:
    return

  if not issue:
    return

  platforms = get_crash_occurrence_platforms(testcase)
  platforms = platforms.union(get_platforms_from_testcase_variants(testcase))
  logs.log(
      'Found %d platforms for the testcase %d.' % (len(platforms),
                                                   testcase.key.id()),
      platforms=platforms)
  for platform in platforms:
    label = os_label.replace('%PLATFORM%', platform.capitalize())
    if not issue_tracker_utils.was_label_added(issue, label):
      issue.labels.add(label)

  issue.save(notify=False)
  logs.log('Updated labels of issue %d.' % issue.id, labels=issue.labels)


def update_fuzz_blocker_label(policy, testcase, issue,
                              top_crashes_by_project_and_platform_map):
  """Add top crash label to issue."""
  fuzz_blocker_label = policy.label('fuzz_blocker')
  if not fuzz_blocker_label:
    return

  if not issue:
    return

  if not testcase.open:
    return

  top_crash_platforms = get_top_crash_platforms(
      testcase, top_crashes_by_project_and_platform_map)
  if not top_crash_platforms:
    # Not a top crasher, bail out.
    return

  if issue_tracker_utils.was_label_added(issue, fuzz_blocker_label):
    # Issue was already marked a top crasher, bail out.
    return

  if len(top_crash_platforms) == 1:
    platform_message = '%s platform' % top_crash_platforms[0]
  else:
    platform_message = '%s and %s platforms' % (', '.join(
        top_crash_platforms[:-1]), top_crash_platforms[-1])

  fuzzer_name = (
      testcase.get_metadata('fuzzer_binary_name') or testcase.fuzzer_name)
  update_message = (
      'This crash occurs very frequently on %s and is likely preventing the '
      'fuzzer %s from making much progress. Fixing this will allow more bugs '
      'to be found.' % (platform_message, fuzzer_name))
  if utils.is_oss_fuzz():
    update_message += OSS_FUZZ_INCORRECT_COMMENT
  elif utils.is_chromium():
    update_message += '\n\nMarking this bug as a blocker for next Beta release.'
    update_message = _append_generic_incorrect_comment(
        update_message,
        policy,
        issue,
        ' and remove the {label_text}.'.format(
            label_text=issue.issue_tracker.label_text(
                data_types.CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL)))
    issue.labels.add(data_types.CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL)

    # Update with the next beta for trunk, and remove existing milestone label.
    beta_milestone_label = (
        'M-%d' % build_info.get_release_milestone('head', testcase.platform))
    if beta_milestone_label not in issue.labels:
      issue.labels.remove_by_prefix('M-')
      issue.labels.add(beta_milestone_label)

  logs.log(update_message)
  issue.labels.add(fuzz_blocker_label)
  issue.save(new_comment=update_message, notify=True)


def update_component_labels(testcase, issue):
  """Add components to the issue if needed."""
  if not issue:
    return

  components = _get_predator_result_item(
      testcase, 'suspected_components', default=[])

  # Remove components already in issue or whose more specific variants exist.
  filtered_components = []
  for component in components:
    found_component_in_issue = any(
        component == issue_component or issue_component.startswith(component +
                                                                   '>')
        for issue_component in issue.components)
    if not found_component_in_issue:
      filtered_components.append(component)

  if not filtered_components:
    # If there are no new components to add, then we shouldn't make any changes
    # to issue.
    return

  # Don't run on issues we've already applied automatic components to in case
  # labels are removed manually. This may cause issues in the event that we
  # rerun a test case, but it seems like a reasonable tradeoff to avoid spam.
  if issue_tracker_utils.was_label_added(
      issue, data_types.CHROMIUM_ISSUE_PREDATOR_AUTO_COMPONENTS_LABEL):
    return

  for filtered_component in filtered_components:
    issue.components.add(filtered_component)

  issue.labels.add(data_types.CHROMIUM_ISSUE_PREDATOR_AUTO_COMPONENTS_LABEL)
  issue_comment = (
      'Automatically applying components based on crash stacktrace and '
      'information from OWNERS files.\n\n'
      'If this is incorrect, please apply the {label_text}.'.format(
          label_text=issue.issue_tracker.label_text(
              data_types.CHROMIUM_ISSUE_PREDATOR_WRONG_COMPONENTS_LABEL)))
  issue.save(new_comment=issue_comment, notify=True)


def update_issue_ccs_from_owners_file(policy, testcase, issue):
  """Add cc to an issue based on owners list from owners file. This is
  currently applicable to fuzz targets only."""
  auto_cc_label = policy.label('auto_cc_from_owners')
  if not auto_cc_label:
    return

  if not issue or not issue.is_open:
    return

  if testcase.get_metadata('has_issue_ccs_from_owners_file'):
    return

  ccs_list = utils.parse_delimited(
      testcase.get_metadata('issue_owners', ''),
      delimiter=',',
      strip=True,
      remove_empty=True)
  if not ccs_list:
    return

  # If we've assigned the ccs before, it likely means we were incorrect.
  # Don't try again for this particular issue.
  if issue_tracker_utils.was_label_added(issue, auto_cc_label):
    return

  ccs_added = False
  actions = list(issue.actions)
  for cc in ccs_list:
    if cc in issue.ccs:
      continue

    # If cc was previously manually removed from the cc list, we assume that
    # they were incorrectly added. Don't try to add them again.
    cc_was_removed = any(cc in action.ccs.removed for action in actions)
    if cc_was_removed:
      continue

    issue.ccs.add(cc)
    ccs_added = True

  if not ccs_added:
    # Everyone we'd expect to see has already been cced on the issue. No need
    # to spam it with another comment. Also, set the metadata to avoid doing
    # this again.
    testcase.set_metadata('has_issue_ccs_from_owners_file', True)
    return

  issue_comment = (
      'Automatically adding ccs based on OWNERS file / target commit history.')
  if utils.is_oss_fuzz():
    issue_comment += OSS_FUZZ_INCORRECT_COMMENT + '.'
  else:
    issue_comment = _append_generic_incorrect_comment(issue_comment, policy,
                                                      issue, '.')

  issue.labels.add(auto_cc_label)
  issue.save(new_comment=issue_comment, notify=True)


def update_issue_labels_for_flaky_testcase(policy, testcase, issue):
  """Update issue reproducibility label when testcase becomes flaky or
  unreproducible."""
  if not issue or not issue.is_open:
    return

  # If the testcase is reproducible, then no change is needed. Bail out.
  if not testcase.one_time_crasher_flag:
    return

  # Make sure that no other reproducible testcases associated with this issue
  # are open. If yes, no need to update label.
  similar_reproducible_testcase = data_types.Testcase.query(
      data_types.Testcase.bug_information == testcase.bug_information,
      ndb_utils.is_true(data_types.Testcase.open),
      ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag)).get()
  if similar_reproducible_testcase:
    return

  reproducible_label = policy.label('reproducible')
  unreproducible_label = policy.label('unreproducible')
  if not reproducible_label or not unreproducible_label:
    return

  # Make sure that this issue is not already marked Unreproducible.
  if unreproducible_label in issue.labels:
    return

  issue.labels.remove(reproducible_label)
  issue.labels.add(unreproducible_label)
  comment = ('ClusterFuzz testcase {testcase_id} appears to be flaky, '
             'updating reproducibility {label_type}.'.format(
                 testcase_id=testcase.key.id(),
                 label_type=issue.issue_tracker.label_type))
  issue.save(new_comment=comment)


def update_issue_owner_and_ccs_from_predator_results(policy,
                                                     testcase,
                                                     issue,
                                                     only_allow_ccs=False):
  """Assign the issue to an appropriate owner if possible."""
  if not issue or not issue.is_open:
    return

  # If the issue already has an owner, we don't need to update the bug.
  if issue.assignee:
    return

  # If there are more than 3 suspected CLs, we can't be confident in the
  # results. Just skip any sort of notification to CL authors in this case.
  suspected_cls = _get_predator_result_item(testcase, 'suspected_cls')
  if not suspected_cls or len(suspected_cls) > 3:
    return

  # If we've assigned an owner or cc once before, it likely means we were
  # incorrect. Don't try again for this particular issue.
  if (issue_tracker_utils.was_label_added(
      issue, data_types.CHROMIUM_ISSUE_PREDATOR_AUTO_OWNER_LABEL) or
      issue_tracker_utils.was_label_added(
          issue, data_types.CHROMIUM_ISSUE_PREDATOR_AUTO_CC_LABEL)):
    return

  # Validate that the suspected CLs have all of the information we need before
  # continuing. This allows us to assume that they are well-formed later,
  # avoiding any potential exceptions that would interrupt this task.
  for suspected_cl in suspected_cls:
    url = suspected_cl.get('url')
    description = suspected_cl.get('description')
    author = suspected_cl.get('author')
    if not url or not description or not author:
      logs.log_error(
          'Suspected CL for testcase %d is missing required information.' %
          testcase.key.id())
      return

  if len(suspected_cls) == 1 and not only_allow_ccs:
    suspected_cl = suspected_cls[0]

    # If this owner has already been assigned before but has since been removed,
    # don't assign it to them again.
    for action in issue.actions:
      if action.assignee == suspected_cls[0]['author']:
        return

    # We have high confidence for the single-CL case, so we assign the owner.
    issue.labels.add(data_types.CHROMIUM_ISSUE_PREDATOR_AUTO_OWNER_LABEL)
    issue.assignee = suspected_cl['author']
    issue.status = policy.status('assigned')
    issue_comment = (
        'Automatically assigning owner based on suspected regression '
        'changelist %s (%s).\n\n'
        'If this is incorrect, please let us know why and apply the %s '
        'label. If you aren\'t the correct owner for this issue, please '
        'unassign yourself as soon as possible so it can be re-triaged.' %
        (suspected_cl['url'], suspected_cl['description'],
         data_types.CHROMIUM_ISSUE_PREDATOR_WRONG_CL_LABEL))

  else:
    if testcase.get_metadata('has_issue_ccs_from_predator_results'):
      return

    issue_comment = (
        'Automatically adding ccs based on suspected regression changelists:'
        '\n\n')
    ccs_added = False

    for suspected_cl in suspected_cls:
      # Update the comment with the suspected CL, regardless of whether or not
      # we're ccing the author. This might, for example, catch the attention of
      # someone who has already been cced.
      author = suspected_cl['author']
      issue_comment += '%s by %s - %s\n\n' % (suspected_cl['description'],
                                              author, suspected_cl['url'])
      if author in issue.ccs:
        continue

      # If an author has previously been manually removed from the cc list,
      # we assume they were incorrectly added. Don't try to add them again.
      author_was_removed = False
      for action in issue.actions:
        if author in action.ccs.removed:
          author_was_removed = True
          break

      if author_was_removed:
        continue

      issue.ccs.add(author)
      ccs_added = True

    if not ccs_added:
      # Everyone we'd expect to see has already been cced on the issue. No need
      # to spam it with another comment. Also, set the metadata to avoid doing
      # this again.
      testcase.set_metadata('has_issue_ccs_from_owners_file', True)
      return

    issue.labels.add(data_types.CHROMIUM_ISSUE_PREDATOR_AUTO_CC_LABEL)
    issue_comment += ((
        'If this is incorrect, please let us know why and apply the '
        '{label_text}.').format(
            label_text=issue.issue_tracker.label_text(
                data_types.CHROMIUM_ISSUE_PREDATOR_WRONG_CL_LABEL)))

  try:
    issue.save(new_comment=issue_comment, notify=True)
  except HttpError:
    # If we see such an error when we aren't setting an owner, it's unexpected.
    if only_allow_ccs or not issue.assignee:
      logs.log_error(
          'Unable to update issue for test case %d.' % testcase.key.id())
      return

    # Retry without setting the owner. They may not be a chromium project
    # member, in which case we can try falling back to cc.
    issue = issue_tracker_utils.get_issue_for_testcase(testcase)
    update_issue_owner_and_ccs_from_predator_results(
        policy, testcase, issue, only_allow_ccs=True)


def cleanup_unused_heartbeats():
  """Clean up unused heartbeat entities."""
  cutoff_time = utils.utcnow() - datetime.timedelta(
      days=UNUSED_HEARTBEAT_THRESHOLD)
  unused_heartbeats = ndb_utils.get_all_from_query(
      data_types.Heartbeat.query(
          data_types.Heartbeat.last_beat_time < cutoff_time),
      keys_only=True)

  ndb_utils.delete_multi(unused_heartbeats)


class Handler(base_handler.Handler):
  """Cleanup."""

  @handler.cron()
  def get(self):
    cleanup_testcases_and_issues()
    cleanup_reports_metadata()
    leak_blacklist.cleanup_global_blacklist()
    cleanup_unused_fuzz_targets_and_jobs()
    cleanup_unused_heartbeats()

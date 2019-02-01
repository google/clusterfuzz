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

import datetime
import json
import random

from google.appengine.api import mail
from googleapiclient.errors import HttpError

from base import dates
from base import errors
from base import memoize
from base import utils
from chrome import build_info
from crash_analysis import crash_comparer
from datastore import data_handler
from datastore import data_types
from datastore import ndb
from datastore import ndb_utils
from fuzzing import leak_blacklist
from handlers import base_handler
from issue_management import issue_tracker_utils
from libs import handler
from metrics import crash_stats
from metrics import logs

INTERNAL_INCORRECT_COMMENT = ('\n\nIf this is incorrect, please add %s label' %
                              data_types.ISSUE_MISTRIAGED_LABEL)

OSS_FUZZ_INCORRECT_COMMENT = ('\n\nIf this is incorrect, please file a bug on '
                              'https://github.com/google/oss-fuzz/issues/new')

AUTO_CC_LIMIT = 5
TOP_CRASHES_LIMIT = 5
TOP_CRASHES_DAYS_LOOKBEHIND = 7
TOP_CRASHES_MIN_THRESHOLD = 50 * TOP_CRASHES_DAYS_LOOKBEHIND
TOP_CRASHES_IGNORE_CRASH_TYPES = [
    'Hang', 'Out-of-memory', 'Stack-overflow', 'Timeout'
]
TOP_CRASHES_IGNORE_CRASH_STATES = ['NULL']

# FIXME: Remove from this list once these crashes are fixed.
TOP_CRASHES_IGNORE_CRASH_STATE_KEYWORDS = [
    'Zygote', '__printf_chk', 'gtk_', 'sandbox::'
]

FUZZ_TARGET_UNUSED_THRESHOLD = 7
UNUSED_HEARTBEAT_THRESHOLD = 15


def _get_predator_result_item(testcase, key, default=None):
  """Return the suspected components for a test case."""
  predator_result = testcase.get_metadata('predator_result')
  if not predator_result:
    return default

  return predator_result['result'].get(key, default)


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
  ndb.delete_multi(uploaded_reports)


def cleanup_testcases_and_issues():
  """Clean up unneeded open testcases and their associated issues."""
  jobs = data_handler.get_all_job_type_names()
  testcase_keys = ndb_utils.get_all_from_query(
      data_types.Testcase.query(
          ndb_utils.is_false(data_types.Testcase.triaged)),
      keys_only=True)
  top_crashes_by_project_and_platform_map = (
      get_top_crashes_for_all_projects_and_platforms())

  for testcase_key in testcase_keys:
    try:
      testcase = data_handler.get_testcase_by_id(testcase_key.id())
    except errors.InvalidTestcaseError:
      # Already deleted.
      continue

    issue = get_issue_for_testcase(testcase)

    # Issue updates.
    update_os_labels(testcase, issue)
    update_fuzz_blocker_label(testcase, issue,
                              top_crashes_by_project_and_platform_map)
    update_component_labels(testcase, issue)
    update_issue_ccs_from_owners_file(testcase, issue)
    update_issue_owner_and_ccs_from_predator_results(testcase, issue)

    # Testcase marking rules.
    mark_duplicate_testcase_as_closed_with_no_issue(testcase)
    mark_issue_as_closed_if_testcase_is_fixed(testcase, issue)
    mark_testcase_as_closed_if_issue_is_closed(testcase, issue)
    mark_testcase_as_closed_if_job_is_invalid(testcase, jobs)
    mark_unreproducible_testcase_as_fixed_if_issue_is_closed(testcase, issue)
    mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        testcase, issue)

    # Notification, to be done at end after testcase state is updated from
    # previous rules.
    notify_closed_issue_if_testcase_is_open(testcase, issue)
    notify_issue_if_testcase_is_invalid(testcase, issue)
    notify_uploader_when_testcase_is_processed(testcase, issue)

    # Mark testcase as triage complete if both testcase and associated issue
    # are closed. This also need to be done before the deletion rules.
    mark_testcase_as_triaged_if_needed(testcase, issue)

    # Testcase deletion rules.
    delete_unreproducible_testcase_with_no_issue(testcase)


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

  ndb.delete_multi(to_delete)


def get_jobs_and_platforms_for_top_crashes():
  """Return list of jobs and platforms to use for picking top crashes."""
  jobs = set()
  platforms = set()

  all_jobs = ndb_utils.get_all_from_model(data_types.Job)
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

    jobs.add(job.name)
    platforms.add(job_platform_to_real_platform(job.platform))

  return jobs, platforms


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
      platform = group['name'].split(':')[0].capitalize()
      platforms.add(platform)
  return list(platforms)


def get_crash_occurrence_platforms(testcase, lookbehind_days=1):
  """Get platforms from crash stats for a testcase."""
  return _get_crash_occurrence_platforms_from_crash_parameters(
      testcase.crash_type, testcase.crash_state, testcase.security_flag,
      testcase.project_name, lookbehind_days)


def get_top_crashes_for_all_projects_and_platforms():
  """Return top crashes for all projects and platforms."""
  last_hour = crash_stats.get_last_successful_hour()
  if not last_hour:
    # No crash stats available, skip.
    return {}

  jobs, platforms = get_jobs_and_platforms_for_top_crashes()
  project_names = data_handler.get_all_project_names()
  top_crashes_by_project_and_platform_map = {}

  for project_name in project_names:
    top_crashes_by_project_and_platform_map[project_name] = {}

    for platform in platforms:
      where_clause = (
          'crash_type NOT IN UNNEST(%s) AND '
          'crash_state NOT IN UNNEST(%s) AND '
          'job_type IN UNNEST(%s) AND '
          'platform LIKE %s AND '
          'project = %s' %
          (json.dumps(TOP_CRASHES_IGNORE_CRASH_TYPES),
           json.dumps(TOP_CRASHES_IGNORE_CRASH_STATES), json.dumps(list(jobs)),
           json.dumps(platform.lower() + '%'), json.dumps(project_name)))

      for keyword in TOP_CRASHES_IGNORE_CRASH_STATE_KEYWORDS:
        where_clause += ' AND crash_state NOT LIKE "%%%s%%"' % keyword

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
      if rows:
        rows = [s for s in rows if s['totalCount'] >= TOP_CRASHES_MIN_THRESHOLD]
      top_crashes_by_project_and_platform_map[project_name][platform] = (
          rows or [])

  return top_crashes_by_project_and_platform_map


def get_top_crash_platforms(testcase, top_crashes_by_project_and_platform_map):
  """Return list of platforms where this testcase is a top crasher."""
  if testcase.project_name not in top_crashes_by_project_and_platform_map:
    return []

  top_crashes_by_platform_map = top_crashes_by_project_and_platform_map[
      testcase.project_name]
  top_crash_platforms = set()
  for platform in top_crashes_by_platform_map.keys():
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


def get_issue_for_testcase(testcase):
  """Return issue object associated with testcase."""
  if not testcase.bug_information:
    return None

  issue_tracker_manager = issue_tracker_utils.get_issue_tracker_manager(
      testcase=testcase, use_cache=True)
  if not issue_tracker_manager:
    return None

  try:
    issue_id = int(testcase.bug_information)
    issue = issue_tracker_manager.get_original_issue(issue_id)
  except:
    logs.log_error(
        'Error occurred when fetching issue %s.' % testcase.bug_information)
    return None

  return issue


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


def mark_issue_as_closed_if_testcase_is_fixed(testcase, issue):
  """Mark an issue as fixed if all of its associated reproducible testcase are
  fixed."""
  # If there is no associated issue, then bail out.
  if not issue or not testcase.bug_information:
    return

  # If the issue is closed in a status other than Fixed, like Duplicate, WontFix
  # or Archived, we shouldn't change it. Bail out.
  if not issue.open and issue.status != 'Fixed':
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
  if (issue.has_comment_with_label(data_types.ISSUE_VERIFIED_LABEL) or
      issue.has_comment_with_label(data_types.ISSUE_MISTRIAGED_LABEL)):
    return

  issue.add_label(data_types.ISSUE_VERIFIED_LABEL)
  comment = ('ClusterFuzz testcase %d is verified as fixed, '
             'so closing issue as verified.' % testcase.key.id())
  if utils.is_oss_fuzz():
    comment += OSS_FUZZ_INCORRECT_COMMENT
  else:
    comment += INTERNAL_INCORRECT_COMMENT
    comment += ' and re-open the issue.'

  issue.comment = comment
  issue.status = 'Verified'
  issue.open = False
  issue.save(send_email=True)
  logs.log(
      'Closed issue %d for fixed testcase %d.' % (issue.id, testcase.key.id()))


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
  if not issue or issue.open:
    return

  testcase.fixed = 'NA'
  testcase.open = False
  testcase.put()
  logs.log('Closed unreproducible testcase %d with issue closed.' %
           testcase.key.id())


def mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
    testcase, issue):
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
  if not issue or not issue.open:
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
  if issue.has_comment_with_label(data_types.ISSUE_MISTRIAGED_LABEL):
    return

  # Close associated issue and testcase.
  comment = ('ClusterFuzz testcase %d is flaky and no longer crashes, '
             'so closing issue.' % testcase.key.id())
  if utils.is_oss_fuzz():
    comment += OSS_FUZZ_INCORRECT_COMMENT
  else:
    comment += INTERNAL_INCORRECT_COMMENT
    comment += ' and re-open the issue.'

  issue.comment = comment
  issue.status = 'WontFix'
  issue.open = False
  issue.save(send_email=True)
  testcase.fixed = 'NA'
  testcase.open = False
  testcase.put()

  logs.log('Closed unreproducible testcase %d and associated issue.' %
           testcase.key.id())


def mark_testcase_as_triaged_if_needed(testcase, issue):
  """Mark testcase as triage complete if both testcase and associated issue
  are closed."""
  # Check if testcase is open. If yes, bail out.
  if testcase.open:
    return

  # Check if there is an associated bug in open state. If yes, bail out.
  if issue:
    # Get latest issue object to ensure our update went through.
    issue = get_issue_for_testcase(testcase)
    if issue.open:
      return

  testcase.triaged = True
  testcase.put()


def mark_testcase_as_closed_if_issue_is_closed(testcase, issue):
  """Mark testcase as closed if the associated issue is closed."""
  # If the testcase is already closed, no more work to do.
  if not testcase.open:
    return

  # If there is no associated issue, then bail out.
  if not issue or not testcase.bug_information:
    return

  # If the issue is still open, no work needs to be done. Bail out.
  if issue.open:
    return

  # Make sure we passed our deadline based on issue closed timestamp.
  if (issue.closed and not dates.time_has_expired(
      issue.closed, days=data_types.CLOSE_TESTCASE_WITH_CLOSED_BUG_DEADLINE)):
    return

  # If the issue has an ignore label, don't close the testcase and bail out.
  # This helps to prevent new bugs from getting filed for legit WontFix cases.
  if issue.has_comment_with_label(data_types.ISSUE_IGNORE_LABEL):
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


def notify_closed_issue_if_testcase_is_open(testcase, issue):
  """Notify closed issue if associated testcase is still open after a certain
  time period."""
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
  if issue.open:
    return

  # If we have already passed our deadline based on issue closed timestamp,
  # no need to notify. We will close the testcase instead.
  if (issue.closed and not dates.time_has_expired(
      issue.closed,
      days=data_types.NOTIFY_CLOSED_BUG_WITH_OPEN_TESTCASE_DEADLINE)):
    return

  # Check if there is ignore label on issue already. If yes, bail out.
  if issue.has_comment_with_label(data_types.ISSUE_IGNORE_LABEL):
    return

  # Check if we did add the notification comment already. If yes, bail out.
  if issue.has_comment_with_label(data_types.ISSUE_NEEDS_FEEDBACK_LABEL):
    return

  issue.add_label(data_types.ISSUE_NEEDS_FEEDBACK_LABEL)
  if issue.status in ['Fixed', 'Verified']:
    issue.comment = (
        'ClusterFuzz testcase %d is still reproducing on tip-of-tree build '
        '(trunk).\n\nPlease re-test your fix against this testcase and if the '
        'fix was incorrect or incomplete, please re-open the bug. Otherwise, '
        'ignore this notification and add %s label.' %
        (testcase.key.id(), data_types.ISSUE_MISTRIAGED_LABEL))
  else:
    # Covers WontFix, Archived cases.
    issue.comment = (
        'ClusterFuzz testcase %d is still reproducing on tip-of-tree build '
        '(trunk).\n\nIf this testcase was not reproducible locally or '
        'unworkable, ignore this notification and we will file another '
        'bug soon with hopefully a better and workable testcase.\n\n'
        'Otherwise, if this is not intended to be fixed (e.g. this is an '
        'intentional crash), please add %s label to prevent future bug filing '
        'with similar crash stacktrace.' % (testcase.key.id(),
                                            data_types.ISSUE_IGNORE_LABEL))
  issue.save(send_email=True)
  logs.log('Notified closed issue for open testcase %d.' % testcase.key.id())


def notify_issue_if_testcase_is_invalid(testcase, issue):
  """Leave comments on associated issues when test cases are no longer valid."""
  if not issue or not testcase.bug_information:
    return

  # If the issue is closed, there's no work to do.
  if not issue.open:
    return

  # Currently, this only happens if a test case relies on a fuzzer that has
  # been deleted. This can be modified if more cases are needed in the future.
  if not testcase.get_metadata('fuzzer_was_deleted'):
    return

  # Check if we added this message once. If yes, bail out.
  if issue.has_comment_with_label(data_types.ISSUE_INVALID_FUZZER_LABEL):
    return

  issue.comment = (
      'ClusterFuzz testcase %d is associated with an obsolete fuzzer and can '
      'no longer be processed. Please close the issue if it is no longer '
      'actionable.') % testcase.key.id()
  issue.add_label(data_types.ISSUE_INVALID_FUZZER_LABEL)
  issue.save(send_email=True)

  logs.log('Closed issue %d for invalid testcase %d.' % (issue.id,
                                                         testcase.key.id()))


def _send_email_to_uploader(testcase_id, to_email, content):
  """Send email to uploader when all the testcase tasks are finished."""
  # Based on https://cloud.google.com/appengine/docs/standard/go/mail/.
  sender = 'noreply@{app_id}.appspotmail.com'.format(
      app_id=utils.get_application_id())

  subject = 'Your testcase upload %d analysis is complete.' % testcase_id
  body = (
      '%s\n\n'
      'If you suspect that the result above is incorrect, '
      'try re-doing that job on the testcase report page.') % content.strip()

  try:
    mail.send_mail(sender=sender, to=to_email, subject=subject, body=body)
  except Exception:
    logs.log_error('Failed to send email that testcase %d is fully processed.' %
                   testcase_id)


def _update_issue_when_uploaded_testcase_is_processed(
    testcase, issue, description, upload_metadata):
  """Add issue comment when uploaded testcase is processed."""
  issue.comment = description

  # Update the summary in the following cases:
  # 1. Upload metadata indicates that we need to do so.
  # 2. We have a valid crash state.
  # 3. Crash state != 'NULL' which is unhelpful for title.
  if (upload_metadata.bug_summary_update_flag and testcase.crash_state and
      testcase.crash_state != 'NULL'):
    issue.summary = data_handler.get_issue_summary(testcase)

  # Add severity labels for all project types.
  data_handler.update_issue_severity_labels(testcase, issue)

  # Impact labels like impacting head/beta/stable only apply for Chromium.
  if testcase.project_name == 'chromium':
    data_handler.update_issue_impact_labels(testcase, issue)

  issue.save()


def notify_uploader_when_testcase_is_processed(testcase, issue):
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

  description = data_handler.get_issue_description(testcase)
  if issue:
    _update_issue_when_uploaded_testcase_is_processed(
        testcase, issue, description, upload_metadata)

  _send_email_to_uploader(testcase_id, to_email, description)
  data_handler.create_notification_entry(testcase_id, to_email)


def update_os_labels(testcase, issue):
  """Add OS labels to issue."""
  if not issue:
    return

  platforms = get_crash_occurrence_platforms(testcase)
  logs.log(
      'Found %d platforms for the testcase %d.' % (len(platforms),
                                                   testcase.key.id()),
      platforms=platforms)
  for platform in platforms:
    os_label = 'OS-%s' % platform
    if not issue.has_comment_with_label(os_label):
      issue.add_label(os_label)

  if issue.dirty:
    issue.save(send_email=False)
    logs.log('Updated labels of issue %d.' % issue.id, labels=issue.labels)


def update_fuzz_blocker_label(testcase, issue,
                              top_crashes_by_project_and_platform_map):
  """Add top crash label to issue."""
  if not issue:
    return

  if not testcase.open:
    return

  top_crash_platforms = get_top_crash_platforms(
      testcase, top_crashes_by_project_and_platform_map)
  if not top_crash_platforms:
    # Not a top crasher, bail out.
    return

  if issue.has_comment_with_label(data_types.ISSUE_FUZZ_BLOCKER_LABEL):
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
  else:
    update_message += '\n\nMarking this bug as a blocker for next Beta release.'
    update_message += INTERNAL_INCORRECT_COMMENT
    update_message += (
        ' and remove the %s label.' % data_types.ISSUE_RELEASEBLOCK_BETA_LABEL)
    issue.add_label(data_types.ISSUE_RELEASEBLOCK_BETA_LABEL)

    # Update with the next beta for trunk, and remove existing milestone label.
    beta_milestone_label = (
        'M-%d' % build_info.get_release_milestone('head', testcase.platform))
    if not issue.has_label(beta_milestone_label):
      issue.remove_label_by_prefix('M-')
      issue.add_label(beta_milestone_label)

  logs.log(update_message)
  issue.add_label(data_types.ISSUE_FUZZ_BLOCKER_LABEL)
  issue.comment = update_message
  issue.save(send_email=True)


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
  if issue.has_comment_with_label(
      data_types.ISSUE_PREDATOR_AUTO_COMPONENTS_LABEL):
    return

  for filtered_component in filtered_components:
    issue.add_component(filtered_component)

  issue.add_label(data_types.ISSUE_PREDATOR_AUTO_COMPONENTS_LABEL)
  issue.comment = (
      'Automatically applying components based on crash stacktrace and '
      'information from OWNERS files.\n\n'
      'If this is incorrect, please apply the %s label.' %
      data_types.ISSUE_PREDATOR_WRONG_COMPONENTS_LABEL)
  issue.save(send_email=True)


def update_issue_ccs_from_owners_file(testcase, issue):
  """Add cc to an issue based on owners list from owners file. This is
  currently applicable to fuzz targets only."""
  if not issue or not issue.open:
    return

  # If we've assigned the ccs before, it likely means we were incorrect.
  # Don't try again for this particular issue.
  if issue.has_comment_with_label(data_types.ISSUE_CLUSTERFUZZ_AUTO_CC_LABEL):
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

  ccs_added = False
  comments = issue.get_comments()
  for cc in random.sample(ccs_list, min(AUTO_CC_LIMIT, len(ccs_list))):
    if issue.has_cc(cc):
      continue

    # If cc was previously manually removed from the cc list, we assume that
    # they were incorrectly added. Don't try to add them again.
    cc_was_removed = any(('-%s' % cc) in comment.cc for comment in comments)
    if cc_was_removed:
      continue

    issue.add_cc(cc)
    ccs_added = True

  if not ccs_added:
    # Everyone we'd expect to see has already been cced on the issue. No need
    # to spam it with another comment. Also, set the metadata to avoid doing
    # this again.
    testcase.set_metadata('has_issue_ccs_from_owners_file', True)
    return

  issue.comment = (
      'Automatically adding ccs based on OWNERS file / target commit history.')
  if utils.is_oss_fuzz():
    issue.comment += OSS_FUZZ_INCORRECT_COMMENT
  else:
    issue.comment += INTERNAL_INCORRECT_COMMENT
  issue.comment += '.'
  issue.add_label(data_types.ISSUE_CLUSTERFUZZ_AUTO_CC_LABEL)
  issue.save(send_email=True)


def update_issue_owner_and_ccs_from_predator_results(testcase,
                                                     issue,
                                                     only_allow_ccs=False):
  """Assign the issue to an appropriate owner if possible."""
  if not issue or not issue.open:
    return

  # If the issue already has an owner, we don't need to update the bug.
  if issue.owner:
    return

  # If we've assigned an owner or cc once before, it likely means we were
  # incorrect. Don't try again for this particular issue.
  if (issue.has_comment_with_label(data_types.ISSUE_PREDATOR_AUTO_OWNER_LABEL)
      or issue.has_comment_with_label(data_types.ISSUE_PREDATOR_AUTO_CC_LABEL)):
    return

  # If there are more than 3 suspected CLs, we can't be confident in the
  # results. Just skip any sort of notification to CL authors in this case.
  suspected_cls = _get_predator_result_item(testcase, 'suspected_cls')
  if not suspected_cls or len(suspected_cls) > 3:
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
    for comment in issue.get_comments():
      if comment.owner == suspected_cls[0]['author']:
        return

    # We have high confidence for the single-CL case, so we assign the owner.
    issue.add_label(data_types.ISSUE_PREDATOR_AUTO_OWNER_LABEL)
    issue.owner = suspected_cl['author']
    issue.status = 'Assigned'
    issue.comment = (
        'Automatically assigning owner based on suspected regression '
        'changelist %s (%s).\n\n'
        'If this is incorrect, please let us know why and apply the %s '
        'label. If you aren\'t the correct owner for this issue, please '
        'unassign yourself as soon as possible so it can be re-triaged.' %
        (suspected_cl['url'], suspected_cl['description'],
         data_types.ISSUE_PREDATOR_WRONG_CL_LABEL))

  else:
    if testcase.get_metadata('has_issue_ccs_from_predator_results'):
      return

    comment_to_add = (
        'Automatically adding ccs based on suspected regression changelists:'
        '\n\n')
    ccs_added = False

    for suspected_cl in suspected_cls:
      # Update the comment with the suspected CL, regardless of whether or not
      # we're ccing the author. This might, for example, catch the attention of
      # someone who has already been cced.
      author = suspected_cl['author']
      comment_to_add += '%s by %s - %s\n\n' % (suspected_cl['description'],
                                               author, suspected_cl['url'])
      if issue.has_cc(author):
        continue

      # If an author has previously been manually removed from the cc list,
      # we assume they were incorrectly added. Don't try to add them again.
      author_was_removed = False
      for comment in issue.get_comments():
        if '-%s' % author in comment.cc:
          author_was_removed = True
          break

      if author_was_removed:
        continue

      issue.add_cc(author)
      ccs_added = True

    if not ccs_added:
      # Everyone we'd expect to see has already been cced on the issue. No need
      # to spam it with another comment. Also, set the metadata to avoid doing
      # this again.
      testcase.set_metadata('has_issue_ccs_from_owners_file', True)
      return

    issue.add_label(data_types.ISSUE_PREDATOR_AUTO_CC_LABEL)
    comment_to_add += (
        'If this is incorrect, please let us know why and apply the %s label.' %
        data_types.ISSUE_PREDATOR_WRONG_CL_LABEL)
    issue.comment = comment_to_add

  try:
    issue.save(send_email=True)
  except HttpError:
    # If we see such an error when we aren't setting an owner, it's unexpected.
    if only_allow_ccs or not issue.owner:
      logs.log_error(
          'Unable to update issue for test case %d.' % testcase.key.id())
      return

    # Retry without setting the owner. They may not be a chromium project
    # member, in which case we can try falling back to cc.
    issue = get_issue_for_testcase(testcase)
    update_issue_owner_and_ccs_from_predator_results(
        testcase, issue, only_allow_ccs=True)


def cleanup_unused_heartbeats():
  """Clean up unused heartbeat entities."""
  cutoff_time = utils.utcnow() - datetime.timedelta(
      days=UNUSED_HEARTBEAT_THRESHOLD)
  unused_heartbeats = ndb_utils.get_all_from_query(
      data_types.Heartbeat.query(
          data_types.Heartbeat.last_beat_time < cutoff_time),
      keys_only=True)

  ndb.delete_multi(unused_heartbeats)


class Handler(base_handler.Handler):
  """Cleanup."""

  @handler.check_cron()
  def get(self):
    cleanup_testcases_and_issues()
    cleanup_reports_metadata()
    leak_blacklist.cleanup_global_blacklist()
    cleanup_unused_fuzz_targets_and_jobs()
    cleanup_unused_heartbeats()

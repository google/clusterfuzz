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
"""Automated bug filing."""

import datetime
import itertools
import json

from clusterfuzz._internal.base import dates
from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.issue_management import issue_filer
from clusterfuzz._internal.issue_management import issue_tracker_policy
from clusterfuzz._internal.issue_management import issue_tracker_utils
from clusterfuzz._internal.metrics import crash_stats
from clusterfuzz._internal.metrics import logs

from . import grouper

MAX_BUGS_PER_PROJECT_PER_24HRS_DEFAULT = 100
UNREPRODUCIBLE_CRASH_IGNORE_CRASH_TYPES = [
    'Out-of-memory', 'Stack-overflow', 'Timeout'
]
TRIAGE_MESSAGE_KEY = 'triage_message'


def _add_triage_message(testcase, message):
  """Add a triage message."""
  if testcase.get_metadata(TRIAGE_MESSAGE_KEY) == message:
    # Message already exists, skip update.
    return
  # Re-fetch testcase to get latest entity and avoid race condition in updates.
  testcase = data_handler.get_testcase_by_id(testcase.key.id())
  testcase.set_metadata(TRIAGE_MESSAGE_KEY, message)


def _create_filed_bug_metadata(testcase):
  """Create a dummy bug entry for a test case."""
  metadata = data_types.FiledBug()
  metadata.timestamp = datetime.datetime.utcnow()
  metadata.testcase_id = testcase.key.id()
  metadata.bug_information = int(testcase.bug_information)
  metadata.group_id = testcase.group_id
  metadata.crash_type = testcase.crash_type
  metadata.crash_state = testcase.crash_state
  metadata.security_flag = testcase.security_flag
  metadata.platform_id = testcase.platform_id
  metadata.project_name = testcase.project_name
  metadata.job_type = testcase.job_type
  metadata.put()


def _get_excluded_jobs():
  """Return list of jobs excluded from bug filing."""
  excluded_jobs = []

  jobs = ndb_utils.get_all_from_model(data_types.Job)
  for job in jobs:
    job_environment = job.get_environment()

    # Exclude experimental jobs.
    if utils.string_is_true(job_environment.get('EXPERIMENTAL')):
      excluded_jobs.append(job.name)

  return excluded_jobs


def _is_bug_filed(testcase):
  """Indicate if the bug is already filed."""
  # Check if the testcase is already associated with a bug.
  if testcase.bug_information:
    return True

  # Re-check our stored metadata so that we don't file the same testcase twice.
  is_bug_filed_for_testcase = data_types.FiledBug.query(
      data_types.FiledBug.testcase_id == testcase.key.id()).get()
  if is_bug_filed_for_testcase:
    return True

  return False


def _is_crash_important(testcase):
  """Indicate if the crash is important to file."""
  if not testcase.one_time_crasher_flag:
    # A reproducible crash is an important crash.
    return True

  if testcase.status != 'Processed':
    # A duplicate or unreproducible crash is not an important crash.
    return False

  # Testcase is unreproducible. Only those crashes that are crashing frequently
  # are important.

  if testcase.crash_type in UNREPRODUCIBLE_CRASH_IGNORE_CRASH_TYPES:
    return False

  # Ensure that there is no reproducible testcase in our group.
  if testcase.group_id:
    other_reproducible_testcase = data_types.Testcase.query(
        data_types.Testcase.group_id == testcase.group_id,
        ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag)).get()
    if other_reproducible_testcase:
      # There is another reproducible testcase in our group. So, this crash is
      # not important.
      return False

  # Get crash statistics data on this unreproducible crash for last X days.
  last_hour = crash_stats.get_last_successful_hour()
  if not last_hour:
    # No crash stats available, skip.
    return False

  _, rows = crash_stats.get(
      end=last_hour,
      block='day',
      days=data_types.FILE_CONSISTENT_UNREPRODUCIBLE_TESTCASE_DEADLINE,
      group_by='reproducible_flag',
      where_clause=(
          'crash_type = %s AND crash_state = %s AND security_flag = %s' %
          (json.dumps(testcase.crash_type), json.dumps(testcase.crash_state),
           json.dumps(testcase.security_flag))),
      group_having_clause='',
      sort_by='total_count',
      offset=0,
      limit=1)

  # Calculate total crash count and crash days count.
  crash_days_indices = set([])
  total_crash_count = 0
  for row in rows:
    if 'groups' not in row:
      continue

    total_crash_count += row['totalCount']
    for group in row['groups']:
      for index in group['indices']:
        crash_days_indices.add(index['hour'])

  crash_days_count = len(crash_days_indices)

  # Only those unreproducible testcases are important that happened atleast once
  # everyday for the last X days and total crash count exceeded our threshold
  # limit.
  return (crash_days_count ==
          data_types.FILE_CONSISTENT_UNREPRODUCIBLE_TESTCASE_DEADLINE and
          total_crash_count >=
          data_types.FILE_UNREPRODUCIBLE_TESTCASE_MIN_CRASH_THRESHOLD)


def _check_and_update_similar_bug(testcase, issue_tracker):
  """Get list of similar open issues and ones that were recently closed."""
  # Get similar testcases from the same group.
  similar_testcases_from_group = []
  if testcase.group_id:
    group_query = data_types.Testcase.query(
        data_types.Testcase.group_id == testcase.group_id)
    similar_testcases_from_group = ndb_utils.get_all_from_query(
        group_query, batch_size=data_types.TESTCASE_ENTITY_QUERY_LIMIT // 2)

  # Get testcases with the same crash params. These might not be in the a group
  # if they were just fixed.
  same_crash_params_query = data_types.Testcase.query(
      data_types.Testcase.crash_type == testcase.crash_type,
      data_types.Testcase.crash_state == testcase.crash_state,
      data_types.Testcase.security_flag == testcase.security_flag,
      data_types.Testcase.project_name == testcase.project_name,
      data_types.Testcase.status == 'Processed')

  similar_testcases_from_query = ndb_utils.get_all_from_query(
      same_crash_params_query,
      batch_size=data_types.TESTCASE_ENTITY_QUERY_LIMIT // 2)
  for similar_testcase in itertools.chain(similar_testcases_from_group,
                                          similar_testcases_from_query):
    # Exclude ourself from comparison.
    if similar_testcase.key.id() == testcase.key.id():
      continue

    # Exclude similar testcases without bug information.
    if not similar_testcase.bug_information:
      continue

    # Get the issue object given its ID.
    issue = issue_tracker.get_issue(similar_testcase.bug_information)
    if not issue:
      continue

    # If the reproducible issue is not verified yet, bug is still valid and
    # might be caused by non-availability of latest builds. In that case,
    # don't file a new bug yet.
    if similar_testcase.open and not similar_testcase.one_time_crasher_flag:
      return True

    # If the issue is still open, no need to file a duplicate bug.
    if issue.is_open:
      return True

    # If the issue indicates that this crash needs to be ignored, no need to
    # file another one.
    policy = issue_tracker_policy.get(issue_tracker.project)
    ignore_label = policy.label('ignore')
    if ignore_label in issue.labels:
      _add_triage_message(
          testcase,
          ('Skipping filing a bug since similar testcase ({testcase_id}) in '
           'issue ({issue_id}) is blacklisted with {ignore_label} label.'
          ).format(
              testcase_id=similar_testcase.key.id(),
              issue_id=issue.id,
              ignore_label=ignore_label))
      return True

    # If this testcase is not reproducible, and a previous similar
    # non-reproducible bug was previously filed, don't file it again to avoid
    # spam.
    if (testcase.one_time_crasher_flag and
        similar_testcase.one_time_crasher_flag):
      _add_triage_message(
          testcase,
          'Skipping filing unreproducible bug since one was already filed '
          f'({similar_testcase.key.id()}).')
      return True

    # If the issue is recently closed, wait certain time period to make sure
    # our fixed verification has completed.
    if (issue.closed_time and not dates.time_has_expired(
        issue.closed_time, hours=data_types.MIN_ELAPSED_TIME_SINCE_FIXED)):
      _add_triage_message(
          testcase,
          ('Delaying filing a bug since similar testcase '
           '({testcase_id}) in issue ({issue_id}) was just fixed.').format(
               testcase_id=similar_testcase.key.id(), issue_id=issue.id))
      return True

  return False


def _file_issue(testcase, issue_tracker, throttler):
  """File an issue for the testcase."""
  filed = False
  file_exception = None

  if throttler.should_throttle(testcase):
    _add_triage_message(testcase, 'Skipping filing as it is throttled.')
    return False

  if crash_analyzer.is_experimental_crash(testcase.crash_type):
    logs.log(f'Skipping bug filing for {testcase.key.id()} as it '
             'has an experimental crash type.')
    _add_triage_message(
        testcase, 'Skipping filing as this is an experimental crash type.')
    return False

  try:
    _, file_exception = issue_filer.file_issue(testcase, issue_tracker)
    filed = True
  except Exception as e:
    file_exception = e

  if file_exception:
    logs.log_error(f'Failed to file issue for testcase {testcase.key.id()}.')
    _add_triage_message(
        testcase,
        f'Failed to file issue due to exception: {str(file_exception)}')

  return filed


def main():
  """Files bugs."""
  try:
    logs.log('Grouping testcases.')
    grouper.group_testcases()
    logs.log('Grouping done.')
  except:
    logs.log_error('Error occurred while grouping test cases.')
    return False

  # Free up memory after group task run.
  utils.python_gc()

  # Get a list of jobs excluded from bug filing.
  excluded_jobs = _get_excluded_jobs()

  # Get a list of all jobs. This is used to filter testcases whose jobs have
  # been removed.
  all_jobs = data_handler.get_all_job_type_names()

  throttler = Throttler()

  for testcase_id in data_handler.get_open_testcase_id_iterator():
    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      # Already deleted.
      continue

    # Skip if testcase's job is removed.
    if testcase.job_type not in all_jobs:
      continue

    # Skip if testcase's job is in exclusions list.
    if testcase.job_type in excluded_jobs:
      continue

    # Skip if we are running progression task at this time.
    if testcase.get_metadata('progression_pending'):
      continue

    # If the testcase has a bug filed already, no triage is needed.
    if _is_bug_filed(testcase):
      continue

    # Check if the crash is important, i.e. it is either a reproducible crash
    # or an unreproducible crash happening frequently.
    if not _is_crash_important(testcase):
      continue

    # Require that all tasks like minimizaton, regression testing, etc have
    # finished.
    if not data_handler.critical_tasks_completed(testcase):
      continue

    # For testcases that are not part of a group, wait an additional time to
    # make sure it is grouped.
    # The grouper runs prior to this step in the same cron, but there is a
    # window of time where new testcases can come in after the grouper starts.
    # This delay needs to be longer than the maximum time the grouper can take
    # to account for that.
    # FIXME: In future, grouping might be dependent on regression range, so we
    # would have to add an additional wait time.
    # TODO(ochang): Remove this after verifying that the `ran_grouper`
    # metadata works well.
    if not testcase.group_id and not dates.time_has_expired(
        testcase.timestamp, hours=data_types.MIN_ELAPSED_TIME_SINCE_REPORT):
      continue

    if not testcase.get_metadata('ran_grouper'):
      # Testcase should be considered by the grouper first before filing.
      continue

    # If this project does not have an associated issue tracker, we cannot
    # file this crash anywhere.
    issue_tracker = issue_tracker_utils.get_issue_tracker_for_testcase(testcase)
    if not issue_tracker:
      issue_filer.notify_issue_update(testcase, 'new')
      continue

    # If there are similar issues to this test case already filed or recently
    # closed, skip filing a duplicate bug.
    if _check_and_update_similar_bug(testcase, issue_tracker):
      continue

    # Clean up old triage messages that would be not applicable now.
    testcase.delete_metadata(TRIAGE_MESSAGE_KEY, update_testcase=False)

    # File the bug first and then create filed bug metadata.
    if not _file_issue(testcase, issue_tracker, throttler):
      continue

    _create_filed_bug_metadata(testcase)
    issue_filer.notify_issue_update(testcase, 'new')

    logs.log('Filed new issue %s for testcase %d.' % (testcase.bug_information,
                                                      testcase_id))

  logs.log('Triage testcases succeeded.')
  return True


class Throttler:
  """Bug throttler"""

  def __init__(self):
    self._bug_filed_per_job_per_24hrs = {}
    self._bug_filed_per_project_per_24hrs = {}
    self._max_bugs_per_job_per_24hrs = {}
    self._max_bugs_per_project_per_24hrs = {}
    self._bug_throttling_cutoff = datetime.datetime.now() - datetime.timedelta(
        hours=24)

  def _query_job_bugs_filed_count(self, job_type):
    """Gets the number of bugs that have been filed for a given job
    within a given time period."""
    return data_types.FiledBug.query(
        data_types.FiledBug.job_type == job_type and
        data_types.FiledBug.timestamp >= self._bug_throttling_cutoff).count()

  def _query_project_bugs_filed_count(self, project_name):
    """Gets the number of bugs that have been filed for a given project
    within a given time period."""
    return data_types.FiledBug.query(
        data_types.FiledBug.project_name == project_name and
        data_types.FiledBug.timestamp >= self._bug_throttling_cutoff).count()

  def _get_job_bugs_filing_max(self, job_type):
    """Gets the maximum number of bugs that can be filed for a given job."""
    if job_type in self._max_bugs_per_job_per_24hrs:
      return self._max_bugs_per_job_per_24hrs[job_type]

    max_bugs = None
    job = data_types.Job.query(data_types.Job.name == job_type).get()
    if job and 'MAX_BUGS_PER_24HRS' in job.get_environment():
      try:
        max_bugs = int(job.get_environment()['MAX_BUGS_PER_24HRS'])
      except Exception:
        logs.log_error('Invalid environment value of \'MAX_BUGS_PER_24HRS\' '
                       f'for job type {job_type}.')

    self._max_bugs_per_job_per_24hrs[job_type] = max_bugs
    return max_bugs

  def _get_project_bugs_filing_max(self, job_type):
    """Gets the maximum number of bugs that can be filed per project."""
    project = data_handler.get_project_name(job_type)
    if project in self._max_bugs_per_project_per_24hrs:
      return self._max_bugs_per_project_per_24hrs[project]

    issue_tracker_config = local_config.IssueTrackerConfig()
    issue_tracker_name = data_handler.get_issue_tracker_name()
    config = issue_tracker_config.get(issue_tracker_name, {})
    max_bugs = MAX_BUGS_PER_PROJECT_PER_24HRS_DEFAULT
    try:
      max_bugs = int(config.get('max_bugs_per_project_per_24hrs', max_bugs))
    except:
      logs.log_error(
          'Invalid config value of \'max_bugs_per_project_per_24hrs\' '
          f'for issue tracker {issue_tracker_name}')

    self._max_bugs_per_project_per_24hrs[project] = max_bugs
    return max_bugs

  def should_throttle(self, testcase):
    """Returns whether the current bug needs to be throttled."""
    job_bugs_filing_max = self._get_job_bugs_filing_max(testcase.job_type)

    # Check if the job type has a bug filing limit.
    if job_bugs_filing_max is not None:
      # Get the number of bugs filed for the current job in the past 24 hours.
      # First check the cache, then query the datastore if not exists.
      count_per_job = self._bug_filed_per_job_per_24hrs.get(
          testcase.job_type) or self._query_job_bugs_filed_count(
              testcase.job_type)
      if count_per_job < job_bugs_filing_max:
        self._bug_filed_per_job_per_24hrs[testcase.job_type] = count_per_job + 1
        return False
      logs.log(
          f'Skipping bug filing for {testcase.key.id()} as it is throttled.\n'
          f'{count_per_job} bugs have been filed fom '
          f'{self._bug_throttling_cutoff} '
          f'to {datetime.datetime.now()} for job {testcase.job_type}')
      return True

    # Check if the current bug has exceeded the maximum number of bugs
    # that can be filed per project.
    count_per_project = self._bug_filed_per_project_per_24hrs.get(
        testcase.project_name) or self._query_project_bugs_filed_count(
            testcase.project_name)
    if count_per_project < self._get_project_bugs_filing_max(testcase.job_type):
      self._bug_filed_per_project_per_24hrs[testcase.project_name] = (
          count_per_project + 1)
      return False

    logs.log(
        f'Skipping bug filing for {testcase.key.id()} as it is throttled.\n'
        f'{count_per_project} bugs have been filed from '
        f'{self._bug_throttling_cutoff} '
        f'to {datetime.datetime.now()} for project {testcase.project_name}')
    return True

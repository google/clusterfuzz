# Copyright 2023 Google LLC
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
"""Bug throttling."""

import datetime

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs

MAX_BUGS_PER_PROJECT_PER_24HRS_DEFAULT = 100


class Throttler:
  """Bug throttler"""

  def __init__(self):
    self.bug_filed_per_job_per_24hrs = {}
    self.bug_filed_per_project_per_24hrs = {}
    self.max_bugs_per_job_per_24hrs = {}
    self.max_bugs_per_project_per_24hrs = {}
    self.bug_throttling_cutoff = datetime.datetime.now() - datetime.timedelta(
        hours=24)

  def _query_job_bugs_filed_count(self, job_type):
    """Gets the number of bugs that have been filed for a given job
    within a given time period."""
    return data_types.FiledBug.query(
        data_types.FiledBug.job_type == job_type and
        data_types.FiledBug.timestamp >= self.bug_throttling_cutoff).count()

  def _query_project_bugs_filed_count(self, project_name):
    """Gets the number of bugs that have been filed for a given project
    within a given time period."""
    return data_types.FiledBug.query(
        data_types.FiledBug.project_name == project_name and
        data_types.FiledBug.timestamp >= self.bug_throttling_cutoff).count()

  def _get_job_bugs_filing_max(self, job_type):
    """Gets the maximum number of bugs that can be filed for a given job."""
    if job_type in self.max_bugs_per_job_per_24hrs:
      return self.max_bugs_per_job_per_24hrs[job_type]

    max_bugs = None
    job = data_types.Job.query(data_types.Job.name == job_type).get()
    if job and 'MAX_BUGS_PER_24HRS' in job.get_environment():
      try:
        max_bugs = int(job.get_environment()['MAX_BUGS_PER_24HRS'])
      except Exception:
        logs.log_error('Invalid environment value of \'MAX_BUGS_PER_24HRS\' '
                       f'for job type {job_type}.')

    self.max_bugs_per_job_per_24hrs[job_type] = max_bugs
    return max_bugs

  def _get_project_bugs_filing_max(self, job_type):
    """Gets the maximum number of bugs that can be filed per project."""
    project = data_handler.get_project_name(job_type)
    if project in self.max_bugs_per_project_per_24hrs:
      return self.max_bugs_per_project_per_24hrs[project]

    issue_tracker_config = local_config.IssueTrackerConfig()
    config = issue_tracker_config.get(data_handler.get_issue_tracker_name())
    max_bugs = MAX_BUGS_PER_PROJECT_PER_24HRS_DEFAULT
    try:
      max_bugs = int(config.get('max_bugs_per_project_per_24hrs'))
    except:
      logs.log_error(
          'Invalid config value of \'max_bugs_per_project_per_24hrs\'')

    self.max_bugs_per_project_per_24hrs[project] = max_bugs
    return max_bugs

  def should_throttle(self, testcase):
    """Returns whether the current bug needs to be throttled."""
    job_bugs_filing_max = self._get_job_bugs_filing_max(testcase.job_type)

    # Check if the job type has a bug filing limit.
    if job_bugs_filing_max is not None:
      # Get the number of bugs filed for the current job in the past 24 hours.
      # First check the cache, then query the datastore if not exists.
      count_per_job = self.bug_filed_per_job_per_24hrs.get(
          testcase.job_type) or self._query_job_bugs_filed_count(
              testcase.job_type)
      if count_per_job < job_bugs_filing_max:
        self.bug_filed_per_job_per_24hrs[testcase.job_type] = count_per_job + 1
        return False
      logs.log(
          f'Skipping bug filing for {testcase.key.id()} as it is throttled.\n'
          f'{count_per_job} bugs have been filed fom '
          f'{self.bug_throttling_cutoff} '
          f'to {datetime.datetime.now()} for job {testcase.job_type}')
      return True

    # Check if the current bug has exceeded the maximum number of bugs
    # that can be filed per project.
    count_per_project = self.bug_filed_per_project_per_24hrs.get(
        testcase.project_name) or self._query_project_bugs_filed_count(
            testcase.project_name)
    if count_per_project < self._get_project_bugs_filing_max(
        self.max_bugs_per_project_per_24hrs):
      self.bug_filed_per_project_per_24hrs[testcase.project_name] = (
          count_per_project + 1)
      return False

    logs.log(
        f'Skipping bug filing for {testcase.key.id()} as it is throttled.\n'
        f'{count_per_project} bugs have been filed from '
        f'{self.bug_throttling_cutoff} '
        f'to {datetime.datetime.now()} for project {testcase.project_name}')
    return True

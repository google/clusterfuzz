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
"""Handler used for adding new CC's to filed oss-fuzz bugs."""

import logging

from clusterfuzz._internal.base import external_users
from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from handlers import base_handler
from libs import handler
from libs.issue_management import issue_filer
from libs.issue_management import issue_tracker_policy
from libs.issue_management import issue_tracker_utils


def get_open_testcases_with_bugs():
  """Return iterator to open testcases with bugs."""
  return data_types.Testcase.query(
      ndb_utils.is_true(data_types.Testcase.open),
      data_types.Testcase.status == 'Processed',
      data_types.Testcase.bug_information != '').order(  # pylint: disable=g-explicit-bool-comparison
          data_types.Testcase.bug_information, data_types.Testcase.key)


class Handler(base_handler.Handler):
  """Cron handler for adding new CC's to oss-fuzz bugs.."""

  @handler.cron()
  def get(self):
    """Handle a cron job."""

    @memoize.wrap(memoize.FifoInMemory(256))
    def cc_users_for_job(job_type, security_flag):
      """Return users to CC for a job."""
      # Memoized per cron run.
      return external_users.cc_users_for_job(job_type, security_flag)

    for testcase in get_open_testcases_with_bugs():
      issue_tracker = issue_tracker_utils.get_issue_tracker_for_testcase(
          testcase)
      if not issue_tracker:
        logging.error('Failed to get issue tracker manager for %s',
                      testcase.key.id())
        continue

      policy = issue_tracker_policy.get(issue_tracker.project)
      reported_label = policy.label('reported')
      if not reported_label:
        return

      reported_pattern = issue_filer.get_label_pattern(reported_label)

      try:
        issue = issue_tracker.get_original_issue(testcase.bug_information)
      except:
        logging.error('Error occurred when fetching issue %s.',
                      testcase.bug_information)
        continue

      if not issue or not issue.is_open:
        continue

      ccs = cc_users_for_job(testcase.job_type, testcase.security_flag)
      new_ccs = [cc for cc in ccs if cc not in issue.ccs]
      if not new_ccs:
        # Nothing to do.
        continue

      for cc in new_ccs:
        logging.info('CCing %s on %s', cc, issue.id)
        issue.ccs.add(cc)

      comment = None

      if not issue.labels.has_with_pattern(reported_pattern):
        # Add reported label and deadline comment if necessary.
        for result in issue_filer.apply_substitutions(policy, reported_label,
                                                      testcase):
          issue.labels.add(result)

        if policy.label('restrict_view') in issue.labels:
          logging.info('Adding deadline comment on %s', issue.id)
          comment = policy.deadline_policy_message

      issue.save(new_comment=comment, notify=True)

# Copyright 2022 Google LLC
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
"""github_metadata_backfiller.py backtracks GitHub issues filed in the past,
        update their information to cloud storage if missing
        and close issues when necessary."""

from clusterfuzz._internal.datastore import data_types
from libs.issue_management import issue_tracker_utils
from libs.issue_management import oss_fuzz_github


def _get_testcase(bug_information):
  """Retrieve testcase based on its bug information."""
  candidates = list(
      data_types.Testcase.query(
          data_types.Testcase.bug_information == bug_information))
  if not candidates:
    print('No candidate found when '
          'querying bug information {bug_information}\n')
  elif len(candidates) > 1:
    print('Multiple candidates found when '
          f'querying bug information {bug_information}:\n')
    for testcase in candidates:
      print(f'  {testcase.key.id()}')
  else:
    return candidates[0]
  return None


def _get_bug_information(issue):
  """Given a GitHub issue, parse its corresponding bug information."""
  bug_information = issue.title[len(oss_fuzz_github.ISSUE_TITTLE_TEXT_PREFIX) +
                                1:]
  if bug_information.isdigit():
    return bug_information
  return None


def _testcase_information_verified(testcase, issue):
  """Verify if a testcase correctly stores its GitHub issue information."""
  if testcase.github_repo_id == issue.repository.id and \
          testcase.github_issue_num == issue.number:
    print(f'Testcase {testcase.bug_information} was properly stored.')
    return True

  if testcase.github_repo_id is None and testcase.github_issue_num is None:
    print(f'Testcase {testcase.bug_information} was not stored.')
  else:
    print(f'Testcase {testcase.bug_information} stored '
          f'is inconsistent with GitHub:\n'
          f'  Issue number  (Storage) {testcase.github_issue_num} '
          f'!= {issue.number} (GitHub)\n'
          f'  Repository ID (Storage) {testcase.github_repo_id} '
          f'!= {issue.repository.id} (GitHub).')
  return False


def execute(args):
  """Backtrack GitHub issues filed in the past,
    update their information in gcloud, and close them when necessary."""
  issue_tracker = issue_tracker_utils.get_issue_tracker('oss-fuzz')
  for issue in oss_fuzz_github.get_my_issues():
    print('========================================')
    # Track testcase.
    bug_information = _get_bug_information(issue)
    if not bug_information:
      print('Unable to extract bug information: '
            f'Repo {issue.repository.id} Issue {issue.number}.\n'
            f'Issue title: {issue.title}.\n'
            f'Issue url: {issue.url}.')
      continue
    testcase = _get_testcase(bug_information)

    # Update testcase.
    if not _testcase_information_verified(testcase, issue):
      print(
          f'Updating testcase (bug information: {testcase.bug_information}):\n'
          f'  Issue number  {issue.number}\n'
          f'  Repository ID {issue.repository.id}\n')
      if args.non_dry_run:
        oss_fuzz_github.update_testcase_properties(testcase, issue.repository,
                                                   issue)
        testcase.put()

    # Backclose issues.
    if issue.state == 'closed':
      continue
    monorail_issue = issue_tracker.get_original_issue(bug_information)
    if monorail_issue.is_open:
      continue
    print(f'Closing testcase (bug information: {testcase.bug_information}):\n'
          f'  Issue number  {issue.number}\n'
          f'  Repository ID {issue.repository.id}\n')
    if args.non_dry_run:
      oss_fuzz_github.close_issue(testcase)

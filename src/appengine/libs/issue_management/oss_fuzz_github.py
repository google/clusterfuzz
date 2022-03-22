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
"""Helper functions to file GitHub issues."""

import github

from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.metrics import logs

TESTCASE_REPORT_URL = 'https://{domain}/testcase?key={testcase_id}'

MONORAIL_URL = (
    'https://bugs.chromium.org/p/oss-fuzz/detail?id={bug_information}')

OSS_FUZZ_ISSUE_URL = 'https://github.com/google/oss-fuzz/issues/new'

ISSUE_TITTLE_TEXT = 'OSS-Fuzz issue {bug_information}'

ISSUE_CONTENT_TEXT = ('OSS-Fuzz has found a bug in this project. Please see '
                      f'{TESTCASE_REPORT_URL}'
                      'for details and reproducers.'
                      '\n\n'
                      'This issue is mirrored from '
                      f'{MONORAIL_URL} '
                      'and will auto-close if the status changes there.'
                      '\n\n'
                      'If you have trouble accessing this report, '
                      f'please file an issue at {OSS_FUZZ_ISSUE_URL}.'
                      '\n')

ISSUE_ClOSE_COMMENT_TEXT = ('OSS-Fuzz has closed this bug. Please see '
                            f'{MONORAIL_URL} '
                            'for details.')


def get_issue_title(testcase):
  """Generate the title of the issue"""
  return ISSUE_TITTLE_TEXT.format(bug_information=testcase.bug_information)


def get_issue_body(testcase):
  """Generate the body of the issue"""
  return ISSUE_CONTENT_TEXT.format(
      domain=data_handler.get_domain(),
      testcase_id=testcase.key.id,
      bug_information=testcase.bug_information)


def get_issue_close_comment(testcase):
  """Generate the closing comment of the issue"""
  return ISSUE_ClOSE_COMMENT_TEXT.format(
      bug_information=testcase.bug_information)


def get_access():
  """Get access to GitHub with the oss-fuzz personal access token"""
  token = db_config.get_value('oss_fuzz_robot_github_personal_access_token')
  if not token:
    logs.log_error('Unable to get oss-fuzz-robot personal access token.')
    return None
  return github.Github(token)


def filing_enabled(testcase):
  """Check if the project YAML file requires to file a GitHub issue."""
  require_issue = data_handler.get_value_from_job_definition(
      testcase.job_type, 'FILE_GITHUB_ISSUE', default='False')
  return require_issue.lower() == 'true'


def get_repo(testcase, access):
  """Get the GitHub repository to file the issue"""
  repo_url = data_handler.get_value_from_job_definition(testcase.job_type,
                                                        'MAIN_REPO', '')
  if not repo_url:
    logs.log_error('Unable to fetch the MAIN_REPO URL from job definition.')
    return None
  repo_name = repo_url.removeprefix('https://github.com/')

  try:
    target_repo = access.get_repo(repo_name)
  except github.UnknownObjectException:
    logs.log_error(f'Unable to locate GitHub repository '
                   f'named {repo_name} from URL: {repo_url}.')
    target_repo = None
  return target_repo


def post_issue(repo, testcase):
  """Post the issue to the Github repo of the project."""
  issue_title = get_issue_title(testcase)
  issue_body = get_issue_body(testcase)
  return repo.create_issue(title=issue_title, body=issue_body)


def update_testcase_properties(testcase, repo, issue):
  """Update the GitHub-related properties in the FiledBug entity."""
  testcase.repo_id = repo.id
  testcase.issue_num = issue.number


def file_issue(testcase):
  """File an issue to the GitHub repo of the project"""
  if not filing_enabled(testcase):
    return

  access = get_access()
  if not access:
    logs.log_error('Unable to access GitHub account and file the issue.')
    return
  repo = get_repo(testcase, access)
  if not repo:
    logs.log_error('Unable to locate GitHub repository and file the issue.')
    return
  issue = post_issue(repo, testcase)
  update_testcase_properties(testcase, repo, issue)


def issue_recorded(testcase):
  """Verify the issue has been filed."""
  return testcase.github_repo_id is not None \
      and testcase.github_issue_num is not None


def get_issue(testcase, access):
  """Locate the issue of the testcase."""
  repo_id = testcase.github_repo_id
  issue_num = testcase.github_issue_num
  try:
    repo = access.get_repo(repo_id)
  except github.UnknownObjectException:
    logs.log_error(f'Unable to locate the GitHub repository id {repo_id}.')
    return None

  try:
    target_issue = repo.get_issue(issue_num)
  except github.UnknownObjectException:
    logs.log_error(f'Unable to locate the GitHub issue number {issue_num}.')
    target_issue = None
  return target_issue


def close_issue_with_comment(testcase, issue):
  """Generate closing comment, comment, and close the GitHub issue."""
  issue_close_comment = get_issue_close_comment(testcase)
  issue.create_comment(issue_close_comment)
  issue.edit(state='closed')


def close_issue(testcase):
  """Close the issue on GitHub, when the same issue is closed on Monorail."""
  if not issue_recorded(testcase):
    return
  access = get_access()
  if not access:
    logs.log_error(f'Unable to access GitHub account and close the issue.')
    return
  issue = get_issue(testcase, access)
  if not issue:
    logs.log_error(f'Unable to locate and close the issue.')
    return
  close_issue_with_comment(testcase, issue)
  logs.log(f'Closed issue number {testcase.github_issue_num} '
           f'in GitHub repository {testcase.github_repo_id}.')

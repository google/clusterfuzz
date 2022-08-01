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
"""GitHub issue filer tests."""

import unittest

import mock

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from libs.issue_management import oss_fuzz_github

REPO_NAME = 'sample/sample'
MAIN_REPO = f'https://github.com/{REPO_NAME}'
MAIN_REPO_SUFFIX = f'https://github.com/{REPO_NAME}.git'
JOB1_ENVIRONMENT = f'MAIN_REPO = {MAIN_REPO}\n' \
                   'FILE_GITHUB_ISSUE = True'

JOB2_ENVIRONMENT = f'MAIN_REPO = {MAIN_REPO}\n' \
                   'FILE_GITHUB_ISSUE = False'

JOB3_ENVIRONMENT = f'MAIN_REPO = {MAIN_REPO}\n'

JOB4_ENVIRONMENT = f'MAIN_REPO = {MAIN_REPO_SUFFIX}\n' \
                  'FILE_GITHUB_ISSUE = True'

GITHUB_REPO_ID = 100
GITHUB_ISSUE_NUM = 200
GITHUB_ACCESS_TOKEN = 'SECRET'


@test_utils.with_cloud_emulators('datastore')
class OSSFuzzGithubTests(unittest.TestCase):
  """Tests for the GitHub issue filer."""

  def setUp(self):
    """Prepare testcases to file to GitHub."""
    data_types.Job(
        name='job1', environment_string=JOB1_ENVIRONMENT,
        platform='linux').put()

    data_types.Job(
        name='job2', environment_string=JOB2_ENVIRONMENT,
        platform='linux').put()

    data_types.Job(
        name='job3', environment_string=JOB3_ENVIRONMENT,
        platform='linux').put()

    data_types.Job(
        name='job4', environment_string=JOB4_ENVIRONMENT,
        platform='linux').put()

    testcase_args1 = {
        'bug_information': '300',
    }

    testcase_args2 = {
        'bug_information': '300',
        'github_repo_id': GITHUB_REPO_ID,
        'github_issue_num': GITHUB_ISSUE_NUM,
    }

    self.testcase1 = data_types.Testcase(job_type='job1', **testcase_args1)
    self.testcase1.put()

    self.testcase2 = data_types.Testcase(job_type='job2', **testcase_args1)
    self.testcase2.put()

    self.testcase3 = data_types.Testcase(job_type='job3', **testcase_args1)
    self.testcase3.put()

    self.testcase4 = data_types.Testcase(job_type='job1', **testcase_args2)
    self.testcase4.put()

    self.testcase5 = data_types.Testcase(job_type='job4', **testcase_args1)
    self.testcase5.put()

    test_helpers.patch(self, [
        'clusterfuzz._internal.config.db_config.get_value',
    ])
    self.mock.get_value.return_value = GITHUB_ACCESS_TOKEN

  @mock.patch('libs.issue_management.oss_fuzz_github.github')
  def test_file_issue(self, mock_github):
    """File testcase to GitHub."""
    mock_github.Github().get_repo.return_value = mock.MagicMock(
        id=GITHUB_REPO_ID)
    mock_github.Github().get_repo().create_issue.return_value = mock.MagicMock(
        number=GITHUB_ISSUE_NUM)

    for testcase in [self.testcase1, self.testcase5]:
      oss_fuzz_github.file_issue(testcase)

      mock_github.Github.assert_called_with(GITHUB_ACCESS_TOKEN)
      mock_github.Github().get_repo.assert_called_with(REPO_NAME)
      mock_github.Github().get_repo().create_issue.assert_called_once_with(
          title=oss_fuzz_github.get_issue_title(testcase),
          body=oss_fuzz_github.get_issue_body(testcase))
      self.assertEqual(testcase.github_repo_id, GITHUB_REPO_ID)
      self.assertEqual(testcase.github_issue_num, GITHUB_ISSUE_NUM)
      mock_github.reset_mock()

  @mock.patch('libs.issue_management.oss_fuzz_github.github')
  def test_not_file_issue(self, mock_github):
    """Disable file testcase to GitHub with environment setting."""
    oss_fuzz_github.file_issue(self.testcase2)
    # TODO (Dongge):
    # Move testcase3 to test_file_issue after roll out
    oss_fuzz_github.file_issue(self.testcase3)

    mock_github.Github().get_repo().create_issue.assert_not_called()

  @mock.patch('libs.issue_management.oss_fuzz_github.github')
  def test_file_issue_to_repo_disabled_issues(self, mock_github):
    """File an issue to a repo that has disabled issues."""
    mock_github.Github().get_repo.return_value = mock.MagicMock(
        has_issues=False)

    oss_fuzz_github.file_issue(self.testcase1)

    mock_github.Github().get_repo().create_issue.assert_not_called()

  @mock.patch('libs.issue_management.oss_fuzz_github.github')
  def test_close_issue(self, mock_github):
    """Close GitHub testcase."""
    mock_github.Github().get_repo.return_value = mock.MagicMock(
        id=GITHUB_REPO_ID)
    mock_github.Github().get_repo().get_issue.return_value = mock.MagicMock(
        number=GITHUB_ISSUE_NUM, state='open')

    oss_fuzz_github.close_issue(self.testcase4)

    mock_github.Github().get_repo().get_issue(
    ).create_comment.assert_called_once_with(
        oss_fuzz_github.get_issue_close_comment(self.testcase4))
    mock_github.Github().get_repo().get_issue().edit.assert_called_once_with(
        state='closed')

  @mock.patch('libs.issue_management.oss_fuzz_github.github')
  def test_close_issue_of_repo_disabled_issues(self, mock_github):
    """Close an issue of a repo that has disabled issues."""
    mock_github.Github().get_repo.return_value = mock.MagicMock(
        has_issues=False)

    oss_fuzz_github.file_issue(self.testcase1)

    mock_github.Github().get_repo().get_issue.assert_not_called()

  @mock.patch('libs.issue_management.oss_fuzz_github.github')
  def test_close_closed_issue(self, mock_github):
    """Not close GitHub testcases that have been closed."""
    mock_github.Github().get_repo.return_value = mock.MagicMock(
        id=GITHUB_REPO_ID)
    mock_github.Github().get_repo().get_issue.return_value = mock.MagicMock(
        number=GITHUB_ISSUE_NUM, state='closed')

    oss_fuzz_github.close_issue(self.testcase4)

    mock_github.Github().get_repo().get_issue(
    ).create_comment.assert_not_called()

  @mock.patch('libs.issue_management.oss_fuzz_github.github')
  def test_close_unrecorded_issue(self, mock_github):
    """Not close GitHub testcases that are not recorded."""
    mock_github.Github().get_repo.return_value = mock.MagicMock(
        id=GITHUB_REPO_ID)
    mock_github.Github().get_repo().get_issue.return_value = mock.MagicMock(
        number=GITHUB_ISSUE_NUM, state='open')

    oss_fuzz_github.close_issue(self.testcase1)

    mock_github.Github().get_repo().get_issue(
    ).create_comment.assert_not_called()

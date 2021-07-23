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
"""Tests for monorail issue management."""

import datetime
import unittest

import mock
import six

from clusterfuzz._internal.tests.test_libs import helpers
from libs.issue_management import monorail
from libs.issue_management.monorail import issue_tracker_manager
from libs.issue_management.monorail.comment import Comment as MonorailComment
from libs.issue_management.monorail.issue import Issue as MonorailIssue


class IssueTrackerManager(issue_tracker_manager.IssueTrackerManager):
  """Mock issue tracker manager."""

  def __init__(self, project_name, mock_issues):
    # pylint: disable=super-init-not-called
    self.project_name = project_name
    self.last_issue = None
    self.mock_issues = mock_issues

  def get_issue(self, issue_id):
    issue = self.mock_issues.get(issue_id)
    if not issue:
      return None

    issue.itm = self
    return issue

  def save(self, issue, *args, **kwargs):  # pylint: disable=unused-argument,arguments-differ
    self.last_issue = issue


class MonorailTests(unittest.TestCase):
  """Tests for the monorail issue tracker."""

  def setUp(self):
    helpers.patch(self, [
        'libs.issue_management.monorail.issue_tracker_manager.'
        'IssueTrackerManager.get_issues',
    ])

    mock_issue = MonorailIssue()
    mock_issue.id = 1337
    mock_issue.summary = 'summary'
    mock_issue.body = 'body'
    mock_issue.owner = 'owner'
    mock_issue.reporter = 'reporter'
    mock_issue.status = 'New'
    mock_issue.add_label('label1')
    mock_issue.add_label('label2')
    mock_issue.add_component('A>B')
    mock_issue.add_component('C>D')
    mock_issue.add_cc('cc@cc.com')

    mock_comment0 = MonorailComment()
    mock_comment0.author = 'author'
    mock_comment0.cc = ['-removed@cc.com', 'cc@cc.com']
    mock_comment0.labels = ['-label0', 'label1']
    mock_comment0.components = ['-E>F', 'A>B']
    mock_comment0.comment = 'comment'
    mock_comment0.summary = 'summary'
    mock_comment0.status = 'status'
    mock_comment0.owner = 'owner'

    mock_comment1 = MonorailComment()
    mock_comment1.author = 'author'
    mock_comment1.comment = 'comment'

    mock_issue.comments = [
        mock_comment0,
        mock_comment1,
    ]

    mock_issue_merged = MonorailIssue()
    mock_issue_merged.id = 1338
    mock_issue_merged.merged_into = 1337
    mock_issue_merged.merged_into_project = 'project'
    mock_issue_merged.closed = datetime.datetime(2019, 1, 1)

    mock_issue_merged_another_project = MonorailIssue()
    mock_issue_merged_another_project.id = 1339
    mock_issue_merged_another_project.merged_into = 1
    mock_issue_merged_another_project.merged_into_project = 'different-project'

    mock_issues = {
        1337: mock_issue,
        1338: mock_issue_merged,
        1339: mock_issue_merged_another_project,
    }

    self.itm = IssueTrackerManager('project', mock_issues)
    self.issue_tracker = monorail.IssueTracker(self.itm)

  def test_get_issue(self):
    """Test get_issue."""
    self.assertIsNone(self.issue_tracker.get_issue(1))

    issue = self.issue_tracker.get_issue(1337)
    self.assertEqual(1337, issue.id)
    self.assertEqual('summary', issue.title)
    self.assertEqual('body', issue.body)
    self.assertEqual('owner', issue.assignee)
    self.assertEqual('reporter', issue.reporter)
    self.assertEqual('New', issue.status)
    self.assertIsNone(issue.merged_into)

    six.assertCountEqual(self, [
        'label1',
        'label2',
    ], issue.labels)
    six.assertCountEqual(self, [
        'A>B',
        'C>D',
    ], issue.components)
    six.assertCountEqual(self, [
        'cc@cc.com',
    ], issue.ccs)

    issue = self.issue_tracker.get_issue(1338)
    self.assertEqual(1338, issue.id)
    self.assertEqual(datetime.datetime(2019, 1, 1), issue.closed_time)

  def test_new_issue(self):
    """Test new_issue."""
    issue = self.issue_tracker.new_issue()
    issue.assignee = 'owner'
    issue.title = 'summary'
    issue.body = 'body'
    issue.assignee = 'owner'
    issue.reporter = 'reporter'
    issue.status = 'New'
    issue.labels.add('label1')
    issue.labels.add('label2')
    issue.components.add('A>B')
    issue.components.add('C>D')
    issue.ccs.add('cc@cc.com')
    issue.save(new_comment='comment')

    monorail_issue = self.itm.last_issue

    self.assertEqual('summary', monorail_issue.summary)
    self.assertEqual('body', monorail_issue.body)
    self.assertEqual('owner', monorail_issue.owner)
    self.assertEqual('reporter', monorail_issue.reporter)
    self.assertEqual('New', monorail_issue.status)
    self.assertEqual('comment', monorail_issue.comment)

    six.assertCountEqual(self, [
        'label1',
        'label2',
    ], monorail_issue.labels)
    six.assertCountEqual(self, [
        'A>B',
        'C>D',
    ], monorail_issue.components)
    six.assertCountEqual(self, [
        'cc@cc.com',
    ], monorail_issue.cc)

  def test_actions(self):
    """Test actions."""
    issue = self.issue_tracker.get_issue(1337)
    actions = list(issue.actions)
    self.assertEqual(2, len(actions))

    self.assertEqual('summary', actions[0].title)
    self.assertEqual('comment', actions[0].comment)
    self.assertEqual('owner', actions[0].assignee)
    self.assertEqual('status', actions[0].status)
    six.assertCountEqual(self, ['cc@cc.com'], actions[0].ccs.added)
    six.assertCountEqual(self, ['removed@cc.com'], actions[0].ccs.removed)
    six.assertCountEqual(self, ['label1'], actions[0].labels.added)
    six.assertCountEqual(self, ['label0'], actions[0].labels.removed)
    six.assertCountEqual(self, ['A>B'], actions[0].components.added)
    six.assertCountEqual(self, ['E>F'], actions[0].components.removed)

    self.assertIsNone(actions[1].title)
    self.assertEqual('comment', actions[1].comment)
    self.assertIsNone(actions[1].assignee)
    self.assertIsNone(actions[1].status)
    six.assertCountEqual(self, [], actions[1].ccs.added)
    six.assertCountEqual(self, [], actions[1].ccs.removed)
    six.assertCountEqual(self, [], actions[1].labels.added)
    six.assertCountEqual(self, [], actions[1].labels.removed)
    six.assertCountEqual(self, [], actions[1].components.added)
    six.assertCountEqual(self, [], actions[1].components.removed)

  def test_modify_labels(self):
    """Test modifying labels."""
    issue = self.issue_tracker.get_issue(1337)
    issue.labels.add('Label3')
    issue.labels.remove('laBel1')
    six.assertCountEqual(self, ['label2', 'Label3'], issue.labels)
    issue.save()

    six.assertCountEqual(self, ['label2', 'Label3', '-laBel1'],
                         self.itm.last_issue.labels)

  def test_modify_components(self):
    """Test modifying labels."""
    issue = self.issue_tracker.get_issue(1337)
    issue.components.add('Y>Z')
    issue.components.remove('a>B')
    six.assertCountEqual(self, ['C>D', 'Y>Z'], issue.components)
    issue.save()

    six.assertCountEqual(self, ['-a>B', 'C>D', 'Y>Z'],
                         self.itm.last_issue.components)

  def test_get_original_issue(self):
    """Test get_original_issue."""
    issue = self.issue_tracker.get_original_issue(1338)
    self.assertEqual(1337, issue.id)

  def test_find_issues(self):
    """Test find_issues."""
    issue0 = MonorailIssue()
    issue0.id = 1

    issue1 = MonorailIssue()
    issue1.id = 2
    self.mock.get_issues.return_value = [
        issue0,
        issue1,
    ]
    issues = self.issue_tracker.find_issues(
        keywords=['one', 'two'], only_open=True)
    six.assertCountEqual(self, [1, 2], [issue.id for issue in issues])

    self.mock.get_issues.assert_has_calls([
        mock.call(mock.ANY, '"one" "two"', can='open'),
    ])

    issues = self.issue_tracker.find_issues(
        keywords=['one', 'two'], only_open=False)
    six.assertCountEqual(self, [1, 2], [issue.id for issue in issues])

    self.mock.get_issues.assert_has_calls([
        mock.call(mock.ANY, '"one" "two"', can='all'),
    ])

  def test_find_issues_url(self):
    """Test find_issues_url."""
    url = self.issue_tracker.find_issues_url(
        keywords=['one', 'two'], only_open=False)
    self.assertEqual(
        'https://bugs.chromium.org/p/project/issues/list'
        '?can_id=1&q=%22one%22+%22two%22', url)

    url = self.issue_tracker.find_issues_url(
        keywords=['one', 'two'], only_open=True)
    self.assertEqual(
        'https://bugs.chromium.org/p/project/issues/list'
        '?can_id=2&q=%22one%22+%22two%22', url)

  def test_issue_url(self):
    """Test issue_url."""
    issue_url = self.issue_tracker.issue_url(1337)
    self.assertEqual(
        'https://bugs.chromium.org/p/project/issues/detail?id=1337', issue_url)

  def test_merged_into_different_project(self):
    """Test merged_into for a different issue tracker project."""
    issue = self.issue_tracker.get_issue(1339)
    self.assertIsNone(issue.merged_into)

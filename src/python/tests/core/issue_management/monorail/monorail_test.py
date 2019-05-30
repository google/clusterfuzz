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

from builtins import object
import unittest

from issue_management import monorail
from issue_management.issue import Issue as MonorailIssue


class IssueTrackerManager(object):
  """Mock issue tracker manager."""

  def __init__(self, project_name, mock_issues):
    self.project_name = project_name
    self.last_issue = None
    self.mock_issues = mock_issues

  def get_issue(self, issue_id):
    return self.mock_issues.get(issue_id)

  def save(self, issue, *args, **kwargs):  # pylint: disable=unused-argument
    self.last_issue = issue


class IssueFilerTests(unittest.TestCase):
  """Tests for the issue filer."""

  def setUp(self):
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

    mock_issues = {
        1337: mock_issue,
    }

    self.itm = IssueTrackerManager('name', mock_issues)
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

    self.assertItemsEqual([
        'label1',
        'label2',
    ], issue.labels)
    self.assertItemsEqual([
        'A>B',
        'C>D',
    ], issue.components)
    self.assertItemsEqual([
        'cc@cc.com',
    ], issue.ccs)

  def test_new_issue(self):
    """Test new_issue."""
    issue = self.issue_tracker.new_issue()
    issue.assignee = 'owner'
    issue.title = 'summary'
    issue.body = 'body'
    issue.assignee = 'owner'
    issue.reporter = 'reporter'
    issue.status = 'New'
    issue.labels.append('label1')
    issue.labels.append('label2')
    issue.components.append('A>B')
    issue.components.append('C>D')
    issue.ccs.append('cc@cc.com')
    issue.save()

    monorail_issue = self.itm.last_issue

    self.assertEqual('summary', monorail_issue.summary)
    self.assertEqual('body', monorail_issue.body)
    self.assertEqual('owner', monorail_issue.owner)
    self.assertEqual('reporter', monorail_issue.reporter)
    self.assertEqual('New', monorail_issue.status)

    self.assertItemsEqual([
        'label1',
        'label2',
    ], monorail_issue.labels)
    self.assertItemsEqual([
        'A>B',
        'C>D',
    ], monorail_issue.components)
    self.assertItemsEqual([
        'cc@cc.com',
    ], monorail_issue.cc)

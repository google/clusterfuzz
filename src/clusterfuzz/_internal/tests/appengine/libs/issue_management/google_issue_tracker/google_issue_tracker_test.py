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
"""Tests for issue_tracker."""

import datetime
import unittest
from unittest import mock

from clusterfuzz._internal.issue_management import google_issue_tracker
from clusterfuzz._internal.issue_management.google_issue_tracker import \
    issue_tracker
from clusterfuzz._internal.issue_management.google_issue_tracker import client

TEST_CONFIG = {
    'default_component_id': 1337,
}

BASIC_ISSUE = {
    'issueId': '68828938',
    'issueState': {
        'componentId': '29002',
        'type': 'BUG',
        'status': 'NEW',
        'priority': 'P2',
        'severity': 'S2',
        'title': 'test',
        'reporter': {
            'emailAddress': 'user1@google.com',
            'userGaiaStatus': 'ACTIVE'
        },
        'assignee': {
            'emailAddress': 'assignee@google.com',
            'userGaiaStatus': 'ACTIVE'
        },
        'retention': 'COMPONENT_DEFAULT',
    },
    'createdTime': '2019-06-25T01:29:30.021Z',
    'modifiedTime': '2019-06-25T01:29:30.021Z',
    'userData': {},
    'accessLimit': {
        'accessLevel': 'INTERNAL'
    },
    'etag': 'TmpnNE1qZzVNemd0TUMweA==',
    'lastModifier': {
        'emailAddress': 'user1@google.com',
        'userGaiaStatus': 'ACTIVE'
    },
}


class GoogleIssueTrackerTest(unittest.TestCase):
  """issue_tracker tests."""

  def setUp(self):
    self.client_patcher = mock.patch('clusterfuzz._internal.issue_management.' +
                                     'google_issue_tracker.client.build')
    self.client_patcher.start()
    self.client = client.build()
    self.issue_tracker = google_issue_tracker.get_issue_tracker(
        'google-issue-tracker', TEST_CONFIG)

  def tearDown(self):
    self.client_patcher.stop()

  def test_get_issue(self):
    """Test a basic get_issue."""
    self.client.issues().get().execute.return_value = BASIC_ISSUE
    self.client.issues().issueUpdates().list().execute.return_value = {
        'issueUpdates': [{
            'author': {
                'emailAddress': 'user1@google.com',
                'userGaiaStatus': 'ACTIVE',
            },
            'timestamp': '2019-06-25T01:29:30.021Z',
            'issueComment': {
                'comment': 'test body',
                'lastEditor': {
                    'emailAddress': 'user1@google.com',
                    'userGaiaStatus': 'ACTIVE',
                },
                'modifiedTime': '2019-06-25T01:29:30.021Z',
                'entityStatus': {},
                'issueId': '68828938',
                'commentNumber': 1,
                'formattingMode': 'PLAIN',
            },
            'commentNumber': 1,
            'fieldUpdates': [],
        },],
        'totalSize':
            1,
    }
    issue = self.issue_tracker.get_issue(68828938)
    self.assertEqual(68828938, issue.id)
    self.assertEqual('test', issue.title)
    self.assertEqual('user1@google.com', issue.reporter)
    self.assertEqual('assignee@google.com', issue.assignee)
    self.assertIsNone(issue.merged_into)
    self.assertIsNone(issue.closed_time)
    self.assertTrue(issue.is_open)
    self.assertEqual('NEW', issue.status)
    self.assertCountEqual([], issue.labels)
    self.assertCountEqual(['29002'], issue.components)
    self.assertCountEqual([], issue.ccs)
    self.assertEqual('test body', issue.body)

  def test_closed(self):
    """Test a closed issue."""
    self.client.issues().get().execute.return_value = {
        'issueId': '68823061',
        'issueState': {
            'componentId': '29002',
            'type': 'BUG',
            'status': 'VERIFIED',
            'priority': 'P2',
            'severity': 'S2',
            'title': 'test',
        },
        'createdTime': '2019-06-24T03:40:37.741Z',
        'modifiedTime': '2019-06-24T06:40:07.672Z',
        'resolvedTime': '2019-06-24T06:40:07.672Z',
        'verifiedTime': '2019-06-24T06:40:07.672Z',
        'userData': {},
        'accessLimit': {
            'accessLevel': 'INTERNAL'
        },
        'version': 21,
        'etag': 'TmpnNE1qTXdOakV0TWpFdE5nPT0=',
        'lastModifier': {
            'emailAddress': 'user1@google.com',
            'userGaiaStatus': 'ACTIVE',
        },
    }
    issue = self.issue_tracker.get_issue(68828938)
    self.assertFalse(issue.is_open)
    self.assertEqual(
        datetime.datetime(2019, 6, 24, 6, 40, 7, 672), issue.closed_time)

  def test_get_labels(self):
    """Test getting labels."""
    self.client.issues().get().execute.return_value = {
        'issueId': '68823253',
        'issueState': {
            'componentId': '29002',
            'type': 'BUG',
            'status': 'NEW',
            'priority': 'P2',
            'severity': 'S2',
            'title': 'test',
            'hotlistIds': [
                '1337',
                '9001',
                '12345',
                '54321',
            ],
        },
    }
    issue = self.issue_tracker.get_issue(68823253)
    self.assertCountEqual(
        [
            '12345',
            '1337',
            '54321',
            '9001',
        ],
        issue.labels,
    )

  def test_get_ccs(self):
    """Test getting CCs."""
    self.client.issues().get().execute.return_value = {
        'issueId': '68823253',
        'issueState': {
            'componentId':
                '29002',
            'type':
                'BUG',
            'status':
                'NEW',
            'priority':
                'P2',
            'severity':
                'S2',
            'title':
                'test',
            'ccs': [
                {
                    'emailAddress': 'user1@google.com',
                    'userGaiaStatus': 'ACTIVE'
                },
                {
                    'emailAddress': 'user2@google.com',
                    'userGaiaStatus': 'ACTIVE'
                },
            ],
        },
    }
    issue = self.issue_tracker.get_issue(68823253)
    self.assertCountEqual(
        [
            'user1@google.com',
            'user2@google.com',
        ],
        issue.ccs,
    )

  def test_new_issue(self):
    """Test basic new issue creation."""
    issue = self.issue_tracker.new_issue()
    issue.reporter = 'reporter@google.com'
    issue.assignee = 'assignee@google.com'
    issue.body = 'issue body'
    issue.ccs.add('cc@google.com')
    issue.components.add('9001')
    issue.labels.add('12345')
    issue.status = 'ASSIGNED'
    issue.title = 'issue title'
    issue.save()
    self.client.issues().create.assert_has_calls([
        mock.call(
            body={
                'issueComment': {
                    'comment': 'issue body'
                },
                'issueState': {
                    'status': 'ASSIGNED',
                    'reporter': {
                        'emailAddress': 'reporter@google.com'
                    },
                    'title': 'issue title',
                    'access_limit': {
                        'access_level':
                            issue_tracker.IssueAccessLevel.LIMIT_NONE
                    },
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'collaborators': [],
                    'assignee': {
                        'emailAddress': 'assignee@google.com'
                    },
                    'componentId': 9001,
                    'hotlistIds': [12345],
                    'type': 'BUG',
                },
            },
            templateOptions_applyTemplate=True,
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_update_issue(self):
    """Test updating an existing issue."""
    self.client.issues().get().execute.return_value = BASIC_ISSUE
    self.client.issues().modify().execute.return_value = {
        'issueId': '68828938',
        'issueState': {
            'componentId':
                '9001',
            'type':
                'ASSIGNED',
            'status':
                'NEW',
            'priority':
                'P2',
            'severity':
                'S2',
            'title':
                'issue title2',
            'access_limit': {
                'access_level': issue_tracker.IssueAccessLevel.LIMIT_NONE
            },
            'reporter': {
                'emailAddress': 'reporter@google.com',
                'userGaiaStatus': 'ACTIVE',
            },
            'assignee': {
                'emailAddress': 'assignee2@google.com',
                'userGaiaStatus': 'ACTIVE',
            },
            'retention':
                'COMPONENT_DEFAULT',
            'ccs': [{
                'emailAddress': 'cc@google.com',
                'userGaiaStatus': 'ACTIVE'
            },],
            'hotlistIds': ['12345',],
        },
        'createdTime': '2019-06-25T01:29:30.021Z',
        'modifiedTime': '2019-06-25T01:29:30.021Z',
        'userData': {},
        'accessLimit': {
            'accessLevel': 'INTERNAL'
        },
        'lastModifier': {
            'emailAddress': 'user1@google.com',
            'userGaiaStatus': 'ACTIVE',
        },
    }
    issue = self.issue_tracker.get_issue(68828938)
    issue.reporter = 'reporter@google.com'
    issue.assignee = 'assignee2@google.com'
    issue.ccs.add('cc@google.com')
    issue.components.add('9001')
    issue.labels.add('12345')
    issue.status = 'ASSIGNED'
    issue.title = 'issue title2'
    issue.save()
    self.assertEqual(68828938, issue.id)
    self.client.issues().modify.assert_has_calls([
        mock.call(
            body={
                'add': {
                    'status': 'ASSIGNED',
                    'assignee': {
                        'emailAddress': 'assignee2@google.com'
                    },
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'reporter': {
                        'emailAddress': 'reporter@google.com'
                    },
                    'title': 'issue title2',
                },
                'removeMask': '',
                'addMask': 'status,assignee,reporter,title,ccs',
                'remove': {},
                'significanceOverride': 'MAJOR',
            },
            issueId='68828938',
        ),
        mock.call().execute(http=None, num_retries=3),
    ])
    self.client.hotlists().createEntries.assert_has_calls([
        mock.call(
            body={'hotlistEntry': {
                'issueId': '68828938'
            }}, hotlistId='12345'),
        mock.call().execute(http=None, num_retries=3),
    ])
    self.client.issues().move.assert_has_calls([
        mock.call(body={'componentId': 9001}, issueId='68828938'),
        mock.call().execute(http=None, num_retries=3),
    ])
    # Update again, removing the label we just added.
    issue.labels.remove('12345')
    issue.save()
    self.assertEqual(68828938, issue.id)
    self.client.hotlists().entries().delete.assert_has_calls([
        mock.call(hotlistId='12345', issueId='68828938'),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_find_issues_url(self):
    """Test find_issues_url."""
    url = self.issue_tracker.find_issues_url(
        keywords=['abc', 'def'], only_open=True)
    self.assertEqual(
        'https://issuetracker.googleapis.com/v1/'
        'issues?q=%22abc%22+%22def%22+status%3Aopen',
        url,
    )
    url = self.issue_tracker.find_issues_url(
        keywords=['abc', 'def'], only_open=False)
    self.assertEqual(
        'https://issuetracker.googleapis.com/v1/issues?q=%22abc%22+%22def%22',
        url)

  def test_issue_url(self):
    """Test issue_url."""
    url = self.issue_tracker.issue_url(123)
    self.assertEqual('https://issuetracker.googleapis.com/v1/issues/123', url)

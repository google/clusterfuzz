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

EXTENSION_FIELDS = {
    '_ext_collaborators': ['superman@krypton.com', 'batman@gotham.com'],
    '_ext_issue_access_limit': issue_tracker.IssueAccessLevel.LIMIT_VIEW,
}
TEST_CONFIG = {
    'default_component_id': 1337,
    'type': 'google-issue-tracker',
    'url': 'https://issues.chromium.org/issues',
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
    self.assertCountEqual([], issue.components)
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
            'severity': 'S4',
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
            'severity': 'S4',
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
                    'accessLimit': {
                        'accessLevel': issue_tracker.IssueAccessLevel.LIMIT_NONE
                    },
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'collaborators': [],
                    'assignee': {
                        'emailAddress': 'assignee@google.com'
                    },
                    'componentId': 1337,
                    'hotlistIds': [12345],
                    'type': 'BUG',
                    'severity': 'S4',
                },
            },
            templateOptions_applyTemplate=True,
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_new_issue_with_limit_view_label(self):
    """Test basic new issue creation with a limit view label."""
    issue = self.issue_tracker.new_issue()
    issue.reporter = 'reporter@google.com'
    issue.assignee = 'assignee@google.com'
    issue.body = 'issue body'
    issue.ccs.add('cc@google.com')
    issue.labels.add('12345')
    issue.labels.add('LIMIT_VIEW_TRUSTED')
    issue.status = 'ASSIGNED'
    issue.title = 'issue title'
    issue.save()
    self.client.issues().create.assert_has_calls([
        mock.call(
            body={
                'issueState': {
                    'componentId': 1337,
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'collaborators': [],
                    'hotlistIds': [12345],
                    'accessLimit': {
                        'accessLevel':
                            issue_tracker.IssueAccessLevel.LIMIT_VIEW_TRUSTED
                    },
                    'reporter': {
                        'emailAddress': 'reporter@google.com'
                    },
                    'assignee': {
                        'emailAddress': 'assignee@google.com'
                    },
                    'status': 'ASSIGNED',
                    'title': 'issue title',
                    'type': 'BUG',
                    'severity': 'S4'
                },
                'issueComment': {
                    'comment': 'issue body'
                }
            },
            templateOptions_applyTemplate=True,
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_new_issue_with_os_foundin_releaseblock_labels(self):
    """Test new issue creation with os, foundin, releaseblock labels."""
    issue = self.issue_tracker.new_issue()
    issue.reporter = 'reporter@google.com'
    issue.assignee = 'assignee@google.com'
    issue.body = 'issue body'
    issue.ccs.add('cc@google.com')
    issue.labels.add('12345')
    issue.labels.add('OS-Linux')
    issue.labels.add('OS-Android')
    issue.labels.add('FoundIn-123')
    issue.labels.add('FoundIn-789')
    issue.labels.add('ReleaseBlock-Dev')
    issue.labels.add('ReleaseBlock-Beta')
    issue.status = 'ASSIGNED'
    issue.title = 'issue title'
    issue.save()
    self.client.issues().create.assert_has_calls([
        mock.call(
            body={
                'issueState': {
                    'componentId':
                        1337,
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'collaborators': [],
                    'hotlistIds': [12345],
                    'accessLimit': {
                        'accessLevel': issue_tracker.IssueAccessLevel.LIMIT_NONE
                    },
                    'reporter': {
                        'emailAddress': 'reporter@google.com'
                    },
                    'assignee': {
                        'emailAddress': 'assignee@google.com'
                    },
                    'status':
                        'ASSIGNED',
                    'title':
                        'issue title',
                    'type':
                        'BUG',
                    'customFields': [
                        {
                            'customFieldId': '1223084',
                            'repeatedEnumValue': {
                                'values': ['Android', 'Linux']
                            }
                        },
                        {
                            'customFieldId': '1223086',
                            'repeatedEnumValue': {
                                'values': ['Dev', 'Beta']
                            }
                        },
                    ],
                    'foundInVersions': ['123', '789'],
                    'severity':
                        'S4',
                },
                'issueComment': {
                    'comment': 'issue body'
                },
            },
            templateOptions_applyTemplate=True,
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_new_issue_with_empty_os_label(self):
    """Test new issue creation with "empty" OS label."""
    issue = self.issue_tracker.new_issue()
    issue.status = 'NEW'
    issue.title = 'issue title'
    issue.labels.add('OS-')
    issue.save()
    self.client.issues().create.assert_has_calls([
        mock.call(
            body={
                'issueState': {
                    'componentId': 1337,
                    'ccs': [],
                    'collaborators': [],
                    'hotlistIds': [],
                    'accessLimit': {
                        'accessLevel': issue_tracker.IssueAccessLevel.LIMIT_NONE
                    },
                    'status': 'NEW',
                    'title': 'issue title',
                    'type': 'BUG',
                    'severity': 'S4',
                },
            },
            templateOptions_applyTemplate=True,
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_new_issue_with_component_tags(self):
    """Test new issue creation with component tags."""
    self.client.components().get().execute.return_value = {
        'componentId': '1456567',
        'name': 'Component ABC',
        'parentComponentId': '1337',
    }
    issue = self.issue_tracker.new_issue()
    issue.reporter = 'reporter@google.com'
    issue.assignee = 'assignee@google.com'
    issue.body = 'issue body'
    issue.ccs.add('cc@google.com')
    issue.labels.add('12345')
    issue.labels.add('FoundIn-123')
    issue.labels.add('FoundIn-789')
    issue.components.add('ABC>DEF')
    issue.components.add('IJK>XYZ')
    issue.components.add('1456567')
    issue.component_id = 987654321
    issue.status = 'ASSIGNED'
    issue.title = 'issue title'
    issue.save()
    self.client.components().get.assert_has_calls([
        mock.call(componentId='1456567'),
        mock.call().execute(http=None, num_retries=3),
    ])
    self.client.issues().create.assert_has_calls([
        mock.call(
            body={
                'issueState': {
                    'componentId':
                        987654321,
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'collaborators': [],
                    'hotlistIds': [12345],
                    'accessLimit': {
                        'accessLevel': issue_tracker.IssueAccessLevel.LIMIT_NONE
                    },
                    'reporter': {
                        'emailAddress': 'reporter@google.com'
                    },
                    'assignee': {
                        'emailAddress': 'assignee@google.com'
                    },
                    'status':
                        'ASSIGNED',
                    'title':
                        'issue title',
                    'type':
                        'BUG',
                    'customFields': [{
                        'customFieldId': '1222907',
                        'repeatedEnumValue': {
                            'values': ['ABC>DEF', 'Component ABC', 'IJK>XYZ']
                        }
                    }],
                    'foundInVersions': ['123', '789'],
                    'severity':
                        'S4',
                },
                'issueComment': {
                    'comment': 'issue body'
                },
            },
            templateOptions_applyTemplate=True,
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_new_security_issue(self):
    """Test creation of security issue."""
    issue = self.issue_tracker.new_issue()

    # Mimic issue_filer's action in setting up the issue
    issue.apply_extension_fields(EXTENSION_FIELDS)

    issue.labels.add('Type-Bug-Security')
    issue.reporter = 'reporter@google.com'
    issue.assignee = 'assignee@google.com'
    issue.body = 'issue body'
    issue.ccs.add('cc@google.com')
    issue.labels.add('12345')
    issue.labels.add('67890')
    issue.status = 'ASSIGNED'
    issue.title = 'issue title'
    issue.save()

    self.client.issues().create.assert_has_calls([
        mock.call(
            body={
                'issueState': {
                    'componentId':
                        1337,
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'collaborators': [
                        {
                            'emailAddress': 'superman@krypton.com'
                        },
                        {
                            'emailAddress': 'batman@gotham.com'
                        },
                    ],
                    'hotlistIds': [12345, 67890],
                    'accessLimit': {
                        'accessLevel':
                            issue_tracker.IssueAccessLevel.LIMIT_VIEW,
                    },
                    'reporter': {
                        'emailAddress': 'reporter@google.com'
                    },
                    'assignee': {
                        'emailAddress': 'assignee@google.com'
                    },
                    'status':
                        'ASSIGNED',
                    'title':
                        'issue title',
                    'type':
                        'Bug-Security',
                    'severity':
                        'S4',
                },
                'issueComment': {
                    'comment': 'issue body'
                },
            },
            templateOptions_applyTemplate=True,
        ),
        mock.call().execute(num_retries=3, http=None),
    ])

  def test_update_issue(self):
    """Test updating an existing issue."""
    self.client.issues().get().execute.return_value = BASIC_ISSUE
    self.client.issues().modify().execute.return_value = {
        'issueId': '68828938',
        'issueState': {
            'componentId':
                '1337',
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
            'accessLimit': {
                'accessLevel': issue_tracker.IssueAccessLevel.LIMIT_NONE
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
    # Update again, removing the label we just added.
    issue.labels.remove('12345')
    issue.save()
    self.assertEqual(68828938, issue.id)
    self.client.hotlists().entries().delete.assert_has_calls([
        mock.call(hotlistId='12345', issueId='68828938'),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_update_issue_with_os_foundin_releaseblock_labels(self):
    """Test updating an existing issue with OS and FoundIn labels."""
    self.client.issues().get().execute.return_value = {
        'issueId': '68828938',
        'issueState': {
            'componentId':
                '29002',
            'type':
                'BUG',
            'customFields': [
                {
                    'customFieldId': '1223084',
                    'repeatedEnumValue': {
                        'values': ['Linux']  # Existing OS-Linux.
                    },
                },
                {
                    'customFieldId': '1223086',
                    'repeatedEnumValue': {
                        'values': ['Dev']  # Existing ReleaseBlock-Dev.
                    },
                },
            ],
            'status':
                'NEW',
            'priority':
                'P2',
            'severity':
                'S2',
            'title':
                'test',
            'reporter': {
                'emailAddress': 'user1@google.com',
                'userGaiaStatus': 'ACTIVE'
            },
            'assignee': {
                'emailAddress': 'assignee@google.com',
                'userGaiaStatus': 'ACTIVE'
            },
            'retention':
                'COMPONENT_DEFAULT',
            'foundInVersions': ['123'],  # Existing FoundIn-123.
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
    issue = self.issue_tracker.get_issue(68828938)
    issue.reporter = 'reporter@google.com'
    issue.assignee = 'assignee2@google.com'
    issue.ccs.add('cc@google.com')
    issue.labels.add('12345')
    issue.status = 'ASSIGNED'
    issue.title = 'issue title2'
    # Adding OS Android here (in addition to the Linux already set).
    issue.labels.add('OS-Android')
    # Adding FoundIn 789 here (in addition to the 123 already set).
    issue.labels.add('FoundIn-789')
    # Adding ReleaseBlock Beta and Stable (in addition to Dev already set).
    issue.labels.add('ReleaseBlock-Beta')
    issue.labels.add('ReleaseBlock-Stable')
    issue.save()

    self.client.issues().modify.assert_has_calls([
        mock.call(
            issueId='68828938',
            body={
                'add': {
                    'status':
                        'ASSIGNED',
                    'assignee': {
                        'emailAddress': 'assignee2@google.com'
                    },
                    'reporter': {
                        'emailAddress': 'reporter@google.com'
                    },
                    'title':
                        'issue title2',
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'customFields': [
                        {
                            'customFieldId': '1223084',
                            'repeatedEnumValue': {
                                'values': ['Android', 'Linux']
                            }
                        },
                        {
                            'customFieldId': '1223086',
                            'repeatedEnumValue': {
                                'values': ['Dev', 'Beta', 'Stable']
                            }
                        },
                    ],
                    'foundInVersions': ['123', '789'],
                },
                'addMask':
                    'status,assignee,reporter,title,ccs,customFields,foundInVersions',
                'remove': {},
                'removeMask':
                    '',
                'significanceOverride':
                    'MAJOR',
            },
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_update_issue_with_empty_os(self):
    """Test updating an existing issue with an "empty" OS label."""
    self.client.issues().get().execute.return_value = {
        'issueId': '68828938',
        'issueState': {
            'componentId':
                '29002',
            'type':
                'BUG',
            'customFields': [
                {
                    'customFieldId': '1223084',
                    'repeatedEnumValue': {
                        'values': ['Linux']  # Existing OS-Linux.
                    },
                },
            ],
            'status':
                'NEW',
            'priority':
                'P2',
            'severity':
                'S2',
            'title':
                'test',
            'reporter': {
                'emailAddress': 'user1@google.com',
                'userGaiaStatus': 'ACTIVE'
            },
            'assignee': {
                'emailAddress': 'assignee@google.com',
                'userGaiaStatus': 'ACTIVE'
            },
            'retention':
                'COMPONENT_DEFAULT',
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

    issue = self.issue_tracker.get_issue(68828938)
    # Adding "empty" OS label here.
    issue.labels.add('OS-')
    # Also add a real OS label to trigger an API call we can compare against.
    issue.labels.add('OS-Android')
    issue.save()

    self.client.issues().modify.assert_has_calls([
        mock.call(
            issueId='68828938',
            body={
                'add': {
                    'customFields': [{
                        'customFieldId': '1223084',
                        'repeatedEnumValue': {
                            'values': ['Android', 'Linux']
                        }
                    },],
                },
                'addMask': 'customFields',
                'remove': {},
                'removeMask': '',
                'significanceOverride': 'MAJOR',
            },
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_update_issue_with_component_tags(self):
    """Test updating an existing issue with component tags."""
    self.client.components().get().execute.return_value = {
        'componentId': '1456567',
        'name': 'Component ABC',
        'parentComponentId': '1337',
    }
    self.client.issues().get().execute.return_value = {
        'issueId':
            '68828938',
        'customFields': [{
            'customFieldId': '1222907',
            'enumValues': ['ABC>DEF', 'Component ABC', 'IJK', 'XYZ'],
        }],
        'issueState': {
            'componentId':
                '29002',
            'type':
                'BUG',
            'customFields': [
                {
                    'customFieldId': '1222907',
                    'repeatedEnumValue': {
                        'values': ['ABC>DEF']  # Existing Component Tag.
                    },
                },
            ],
            'status':
                'NEW',
            'priority':
                'P2',
            'severity':
                'S2',
            'title':
                'test',
            'reporter': {
                'emailAddress': 'user1@google.com',
                'userGaiaStatus': 'ACTIVE'
            },
            'assignee': {
                'emailAddress': 'assignee@google.com',
                'userGaiaStatus': 'ACTIVE'
            },
            'retention':
                'COMPONENT_DEFAULT',
        },
        'createdTime':
            '2019-06-25T01:29:30.021Z',
        'modifiedTime':
            '2019-06-25T01:29:30.021Z',
        'userData': {},
        'accessLimit': {
            'accessLevel': 'INTERNAL'
        },
        'etag':
            'TmpnNE1qZzVNemd0TUMweA==',
        'lastModifier': {
            'emailAddress': 'user1@google.com',
            'userGaiaStatus': 'ACTIVE'
        },
    }
    issue = self.issue_tracker.get_issue(68828938)
    issue.reporter = 'reporter@google.com'
    issue.assignee = 'assignee2@google.com'
    issue.ccs.add('cc@google.com')
    issue.labels.add('12345')
    issue.status = 'ASSIGNED'
    issue.title = 'issue title2'
    # Adding more Component Tags here.
    # Adding component names.
    issue.components.add('IJK')
    issue.components.add('XYZ')
    # Adding component IDs.
    issue.components.add('1456567')
    # Will not be added because does not correspond to a component.
    issue.components.add('1111111')
    # Will be rejected because it is not in allowed enum values.
    issue.components.add('AAA')
    issue.component_id = 987654321
    issue.save()

    self.client.components().get.assert_has_calls([
        mock.call(componentId='1456567'),
        mock.call().execute(http=None, num_retries=3),
    ])
    self.client.issues().modify.assert_has_calls([
        mock.call(
            issueId='68828938',
            body={
                'add': {
                    'status':
                        'ASSIGNED',
                    'assignee': {
                        'emailAddress': 'assignee2@google.com'
                    },
                    'reporter': {
                        'emailAddress': 'reporter@google.com'
                    },
                    'title':
                        'issue title2',
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'customFields': [{
                        'customFieldId': '1222907',
                        'repeatedEnumValue': {
                            'values': [
                                'ABC>DEF', 'Component ABC', 'IJK', 'XYZ'
                            ]
                        }
                    },],
                },
                'addMask': 'status,assignee,reporter,title,ccs,customFields',
                'remove': {},
                'removeMask': '',
                'significanceOverride': 'MAJOR',
            },
        ),
        mock.call().execute(http=None, num_retries=3),
    ])
    self.client.issues().move.assert_has_calls([
        mock.call(
            issueId='68828938',
            body={
                'componentId': 987654321,
                'significanceOverride': 'MAJOR',
            },
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_update_issue_with_severity_label(self):
    """Test updating an existing issue with a new severity label."""
    self.client.issues().get().execute.return_value = BASIC_ISSUE
    self.client.issues().modify().execute.return_value = {
        'issueId': '68828938',
        'issueState': {
            'componentId':
                '1337',
            'type':
                'ASSIGNED',
            'status':
                'NEW',
            'priority':
                'P2',
            'severity':
                'S0',
            'title':
                'issue title2',
            'accessLimit': {
                'accessLevel': issue_tracker.IssueAccessLevel.LIMIT_NONE
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
    issue.labels.add('Security_Severity-Critical')
    issue.save()

    self.assertEqual(68828938, issue.id)
    self.client.issues().modify.assert_has_calls([
        mock.call(
            body={
                'add': {
                    'severity': 'S0'
                },
                'removeMask': '',
                'addMask': 'severity',
                'remove': {},
                'significanceOverride': 'MAJOR',
            },
            issueId='68828938',
        ),
        mock.call().execute(http=None, num_retries=3),
    ])

  def test_update_issue_to_security(self):
    """Test updating an existing issue."""
    self.client.issues().get().execute.return_value = BASIC_ISSUE
    self.client.issues().modify().execute.return_value = {
        'issueId': '68828938',
        'issueState': {
            'componentId':
                '1337',
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

    # Mimic issue_filer's action in setting up the issue
    issue.apply_extension_fields(EXTENSION_FIELDS)

    issue.reporter = 'reporter@google.com'
    issue.assignee = 'assignee2@google.com'
    issue.ccs.add('cc@google.com')
    issue.labels.add('12345')
    issue.status = 'ASSIGNED'
    issue.title = 'issue title2'
    issue.save()
    self.assertEqual(68828938, issue.id)
    self.client.issues().modify.assert_has_calls([
        mock.call(
            issueId='68828938',
            body={
                'add': {
                    'status':
                        'ASSIGNED',
                    'assignee': {
                        'emailAddress': 'assignee2@google.com'
                    },
                    'reporter': {
                        'emailAddress': 'reporter@google.com'
                    },
                    'title':
                        'issue title2',
                    'ccs': [{
                        'emailAddress': 'cc@google.com'
                    }],
                    'collaborators': [
                        {
                            'emailAddress': 'superman@krypton.com'
                        },
                        {
                            'emailAddress': 'batman@gotham.com'
                        },
                    ],
                    'access_limit':
                        issue_tracker.IssueAccessLevel.LIMIT_VIEW,
                },
                'addMask':
                    'status,assignee,reporter,title,' +
                    'ccs,collaborators,access_limit',
                'remove': {},
                'removeMask':
                    '',
                'significanceOverride':
                    'MAJOR',
            },
        ),
        mock.call().execute(num_retries=3, http=None),
    ])

  def test_find_issues_url(self):
    """Test find_issues_url."""
    url = self.issue_tracker.find_issues_url(
        keywords=['abc', 'def'], only_open=True)
    self.assertEqual(
        'https://issues.chromium.org/issues?q=%22abc%22+%22def%22+status%3Aopen',
        url,
    )
    url = self.issue_tracker.find_issues_url(
        keywords=['abc', 'def'], only_open=False)
    self.assertEqual('https://issues.chromium.org/issues?q=%22abc%22+%22def%22',
                     url)

  def test_find_issues_url_with_filters(self):
    """Test find_issues_url."""
    url = self.issue_tracker.find_issues_url_with_filters(
        keywords=['abc', 'def'],
        query_filters=['id:123', 'hotlistid:(4801165|4072748)'],
        only_open=True)
    self.assertEqual(
        'https://issues.chromium.org/issues?q=%22abc%22+%22def%22+id%3A123+hotlistid%3A%284801165%7C4072748%29+status%3Aopen',
        url,
    )
    url = self.issue_tracker.find_issues_url_with_filters(
        keywords=['abc', 'def'],
        query_filters=['id:123', 'hotlistid:(4801165|4072748)'],
        only_open=False)
    self.assertEqual(
        'https://issues.chromium.org/issues?q=%22abc%22+%22def%22+id%3A123+hotlistid%3A%284801165%7C4072748%29',
        url)

  def test_issue_url(self):
    """Test issue_url."""
    url = self.issue_tracker.issue_url(123)
    self.assertEqual('https://issues.chromium.org/issues/123', url)

  def test_get_severity_from_label_value(self):
    """Test _get_severity_from_label_value."""
    testcases = [
        {
            'name': 'Empty input',
            'input': '',
            'expected': 'S4'
        },
        {
            'name': 'Critical input',
            'input': 'Critical',
            'expected': 'S0'
        },
        {
            'name': 'High input',
            'input': 'High',
            'expected': 'S1'
        },
        {
            'name': 'Medium input',
            'input': 'Medium',
            'expected': 'S2'
        },
        {
            'name': 'Low input',
            'input': 'Low',
            'expected': 'S3'
        },
        {
            'name': 'low input',
            'input': 'low',
            'expected': 'S3'
        },
    ]
    for case in testcases:
      # pylint: disable=protected-access
      actual = issue_tracker._get_severity_from_label_value(case['input'])
      self.assertEqual(
          case['expected'], actual, 'failed test %s. expected %s. actual %s' %
          (case['name'], case['expected'], actual))

  def test_get_description(self):
    """Test a basic get_description."""
    self.client.issues().get().execute.return_value = BASIC_ISSUE
    self.client.issues().comments().list().execute.return_value = {
        'issueComments': [
            {
                'comment': 'test body',
                'lastEditor': {
                    'emailAddress': 'user1@google.com',
                    'userGaiaStatus': 'ACTIVE',
                },
                'modifiedTime': '2019-06-25T01:29:30.021Z',
                'issueId': '68828938',
                'commentNumber': 1,
                'formattingMode': 'PLAIN',
            },
            {
                'comment': 'not test body',
                'lastEditor': {
                    'emailAddress': 'user1@google.com',
                    'userGaiaStatus': 'ACTIVE',
                },
                'modifiedTime': '2019-06-25T02:29:30.021Z',
                'issueId': '68828938',
                'commentNumber': 2,
                'formattingMode': 'PLAIN',
            },
        ],
        'totalSize':
            2,
    }
    description = self.issue_tracker.get_description(68828938)
    self.assertEqual('test body', description)

  def test_get_blank_description(self):
    """Test a basic get_description."""
    self.client.issues().get().execute.return_value = BASIC_ISSUE
    self.client.issues().comments().list().execute.return_value = {
        'issueComments': [
            {
                'comment': '',
                'lastEditor': {
                    'emailAddress': 'user1@google.com',
                    'userGaiaStatus': 'ACTIVE',
                },
                'modifiedTime': '2019-06-25T01:29:30.021Z',
                'issueId': '68828938',
                'commentNumber': 1,
                'formattingMode': 'PLAIN',
            },
            {
                'comment': 'not test body',
                'lastEditor': {
                    'emailAddress': 'user1@google.com',
                    'userGaiaStatus': 'ACTIVE',
                },
                'modifiedTime': '2019-06-25T02:29:30.021Z',
                'issueId': '68828938',
                'commentNumber': 2,
                'formattingMode': 'PLAIN',
            },
        ],
        'totalSize':
            2,
    }
    description = self.issue_tracker.get_description(68828938)
    self.assertEqual('', description)

  def test_get_attachment_metadata(self):
    """Test a basic get_attachment_metadata."""
    self.client.issues().get().execute.return_value = BASIC_ISSUE
    self.client.issues().attachments().list().execute.return_value = {
        'attachments': [
            {
                'attachmentId':
                    '60127668',
                'contentType':
                    'text/html',
                'length':
                    '458',
                'filename':
                    'test.html',
                'attachmentDataRef': {
                    'resourceName': 'attachment:373893311:60127668'
                },
                'etag':
                    'TXpjek9Eb3pNekV4TFRZd01USTNOalk0TFRjNE9URTROVFl4TlE9PQ=='
            },
            {
                'attachmentId':
                    '2',
                'contentType':
                    'text/js',
                'length':
                    '125',
                'filename':
                    'test.js',
                'attachmentDataRef': {
                    'resourceName': 'attachment:373893311:2'
                },
                'etag':
                    'TXetagk9Ea3pNekV4TFRZd01USTNOalk0TFRjNE9URTROVFl4TlE9PQ=='
            },
        ],
        'totalSize':
            2,
    }
    attachment_data = self.issue_tracker.get_attachment_metadata(68828938)
    self.assertEqual('test.html', attachment_data[0]['filename'])
    self.assertEqual('text/html', attachment_data[0]['contentType'])
    self.assertEqual(2, len(attachment_data))

  def test_get_no_attachment_metadata(self):
    """Test an empty get_attachment_metadata."""
    self.client.issues().get().execute.return_value = BASIC_ISSUE
    self.client.issues().attachments().list().execute.return_value = {
        'attachments': [],
        'totalSize': 0,
    }
    attachment_data = self.issue_tracker.get_attachment_metadata(68828938)
    self.assertEqual([], attachment_data)

  def test_get_attachment(self):
    """Test a basic get_attachment."""
    self.client.media().download(
        resourceName='attachment:373893311:60127668'
    ).execute.return_value = ({
        'content-type':
            'application/octet-stream',
        'content-length':
            '458',
        'content-disposition':
            'attachment',
        'status':
            '200',
        'content-location':
            'https://issuetracker.googleapis.com/v1/media/attachment:373893311:60127668?alt=media'
    }, b'<!DOCTYPE html>\n<html>hello world</html>')
    attachment = self.issue_tracker.get_attachment(
        'attachment:373893311:60127668')
    self.assertEqual(b'<!DOCTYPE html>\n<html>hello world</html>',
                     attachment[1])

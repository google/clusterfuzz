# Copyright 2024 Google LLC
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
"""Tests for external_testcase_reader."""

import datetime
import unittest
from unittest import mock

from clusterfuzz._internal.issue_management import google_issue_tracker
from clusterfuzz._internal.issue_management.google_issue_tracker import \
    issue_tracker
from clusterfuzz._internal.issue_management.google_issue_tracker import client
from clusterfuzz._internal.cron import external_testcase_reader
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

BASIC_COMMENTS = {
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

BASIC_ATTACHMENT = {
    'attachmentId': '60127668',
    'contentType': 'text/html',
    'length': '458',
    'filename': 'test.html',
    'attachmentDataRef': {
        'resourceName': 'attachment:373893311:60127668'
    },
    'etag': 'TXpjek9Ea3pNekV4TFRZd01USTNOalk0TFRjNE9URTROVFl4TlE9PQ=='
}


class MockIssue():

  def __init__(self, id):
    self.id = id
    self.status = ''

  def save(self, new_comment, notify):
    return None


class ExternalTestcaseReaderTest(unittest.TestCase):
  """external_testcase_reader tests."""

  def setUp(self):
    self.client_patcher = mock.patch('clusterfuzz._internal.issue_management.' +
                                     'google_issue_tracker.client.build')
    self.client_patcher.start()
    self.client = client.build()
    self.issue_tracker = google_issue_tracker.get_issue_tracker(
        'google-issue-tracker', TEST_CONFIG)

  def tearDown(self):
    self.client_patcher.stop()

  def test_close_invalid_issue_basic(self):
    """Test a basic _close_invalid_issue with valid flags."""
    upload_request = MockIssue(123)
    attachment_info = [BASIC_ATTACHMENT]
    description = "--flag-one --flag_two"
    self.assertEqual(
        0,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

  def test_close_invalid_issue_no_flag(self):
    """Test a basic _close_invalid_issue with no flags."""
    upload_request = MockIssue(123)
    attachment_info = [BASIC_ATTACHMENT]
    description = ""
    self.assertEqual(
        0,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

  def test_close_invalid_issue_too_many_attachments(self):
    """Test _close_invalid_issue with too many attachments."""
    upload_request = MockIssue(123)
    attachment_info = [BASIC_ATTACHMENT, BASIC_ATTACHMENT]
    description = ""
    self.assertEqual(
        1,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

  def test_close_invalid_issue_no_attachments(self):
    """Test _close_invalid_issue with no attachments."""
    upload_request = MockIssue(123)
    attachment_info = []
    description = ""
    self.assertEqual(
        1,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

  def test_close_invalid_issue_invalid_content_type(self):
    """Test _close_invalid_issue with an invalid content type."""
    upload_request = MockIssue(123)
    attachment_info = [{
        'attachmentId': '60127668',
        'contentType': 'application/octet-stream',
        'length': '458',
        'filename': 'test.html',
        'attachmentDataRef': {
            'resourceName': 'attachment:373893311:60127668'
        },
        'etag': 'TXpjek9Ea3pNekV4TFRZd01USTNOalk0TFRjNE9URTROVFl4TlE9PQ=='
    }]
    description = ""
    self.assertEqual(
        1,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

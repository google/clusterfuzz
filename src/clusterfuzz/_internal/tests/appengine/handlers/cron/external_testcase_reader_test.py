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

import unittest
from unittest import mock

from clusterfuzz._internal.cron import external_testcase_reader
from clusterfuzz._internal.issue_management.google_issue_tracker import \
    issue_tracker

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


class ExternalTestcaseReaderTest(unittest.TestCase):
  """external_testcase_reader tests."""

  def setUp(self):
    self.mock_basic_issue = mock.MagicMock()
    self.mock_basic_issue.created_time = '2024-06-25T01:29:30.021Z'
    self.mock_basic_issue.status = 'NEW'
    external_testcase_reader.submit_testcase = mock.MagicMock()

  def test_handle_testcases(self):
    """Test a basic handle_testcases where issue is fit for submission."""
    mock_it = mock.create_autospec(issue_tracker.IssueTracker)
    mock_it.find_issues_with_filters.return_value = [self.mock_basic_issue]
    external_testcase_reader.close_issue_if_invalid = mock.MagicMock()
    external_testcase_reader.close_issue_if_invalid.return_value = False

    external_testcase_reader.handle_testcases(mock_it)
    external_testcase_reader.close_issue_if_invalid.assert_called_once()
    mock_it.get_attachment.assert_called_once()
    external_testcase_reader.submit_testcase.assert_called_once()

  def test_handle_testcases_invalid(self):
    """Test a basic handle_testcases where issue is invalid."""
    mock_it = mock.create_autospec(issue_tracker.IssueTracker)
    mock_it.find_issues_with_filters.return_value = [self.mock_basic_issue]
    external_testcase_reader.close_issue_if_invalid = mock.MagicMock()
    external_testcase_reader.close_issue_if_invalid.return_value = True

    external_testcase_reader.handle_testcases(mock_it)
    external_testcase_reader.close_issue_if_invalid.assert_called_once()
    mock_it.get_attachment.assert_not_called()
    external_testcase_reader.submit_testcase.assert_not_called()

  def test_handle_testcases_not_reproducible(self):
    """Test a basic handle_testcases where issue is not reprodiclbe."""
    mock_it = mock.create_autospec(issue_tracker.IssueTracker)
    mock_it.find_issues_with_filters.return_value = [self.mock_basic_issue]
    external_testcase_reader.close_issue_if_not_reproducible = mock.MagicMock()
    external_testcase_reader.close_issue_if_not_reproducible.return_value = True
    external_testcase_reader.close_issue_if_invalid = mock.MagicMock()

    external_testcase_reader.handle_testcases(mock_it)
    external_testcase_reader.close_issue_if_invalid.assert_not_called()
    mock_it.get_attachment.assert_not_called()
    external_testcase_reader.submit_testcase.assert_not_called()

  def test_handle_testcases_no_issues(self):
    """Test a basic handle_testcases that returns no issues."""
    mock_it = mock.create_autospec(issue_tracker.IssueTracker)
    mock_it.find_issues_with_filters.return_value = []
    external_testcase_reader.close_issue_if_invalid = mock.MagicMock()

    external_testcase_reader.handle_testcases(mock_it)
    external_testcase_reader.close_issue_if_invalid.assert_not_called()
    mock_it.get_attachment.assert_not_called()
    external_testcase_reader.submit_testcase.assert_not_called()

  def test_close_issue_if_not_reproducible_true(self):
    """Test a basic close_issue_if_invalid with valid flags."""
    external_testcase_reader.filed_one_day_ago = mock.MagicMock()
    external_testcase_reader.filed_one_day_ago.return_value = True
    self.mock_basic_issue.status = 'ACCEPTED'
    self.assertEqual(
        True,
        external_testcase_reader.close_issue_if_not_reproducible(
            self.mock_basic_issue))

  def test_close_issue_if_invalid_basic(self):
    """Test a basic close_issue_if_invalid with valid flags."""
    attachment_info = [BASIC_ATTACHMENT]
    description = '--flag-one --flag_two'
    self.assertEqual(
        False,
        external_testcase_reader.close_issue_if_invalid(
            self.mock_basic_issue, attachment_info, description))

  def test_close_issue_if_invalid_no_flag(self):
    """Test a basic close_issue_if_invalid with no flags."""
    attachment_info = [BASIC_ATTACHMENT]
    description = ''
    self.assertEqual(
        False,
        external_testcase_reader.close_issue_if_invalid(
            self.mock_basic_issue, attachment_info, description))

  def test_close_issue_if_invalid_too_many_attachments(self):
    """Test close_issue_if_invalid with too many attachments."""
    attachment_info = [BASIC_ATTACHMENT, BASIC_ATTACHMENT]
    description = ''
    self.assertEqual(
        True,
        external_testcase_reader.close_issue_if_invalid(
            self.mock_basic_issue, attachment_info, description))

  def test_close_issue_if_invalid_no_attachments(self):
    """Test close_issue_if_invalid with no attachments."""
    attachment_info = []
    description = ''
    self.assertEqual(
        True,
        external_testcase_reader.close_issue_if_invalid(
            self.mock_basic_issue, attachment_info, description))

  def test_close_issue_if_invalid_invalid_upload(self):
    """Test close_issue_if_invalid with an invalid upload."""
    attachment_info = [{
        'attachmentId': '60127668',
        'contentType': 'application/octet-stream',
        'length': '458',
        'filename': 'test.html',
        'attachmentDataRef': {},
        'etag': 'TXpjek9Ea3pNekV4TFRZd01USTNOalk0TFRjNE9URTROVFl4TlE9PQ=='
    }]
    description = ''
    self.assertEqual(
        True,
        external_testcase_reader.close_issue_if_invalid(
            self.mock_basic_issue, attachment_info, description))

  def test_close_issue_if_invalid_invalid_content_type(self):
    """Test close_issue_if_invalid with an invalid content type."""
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
    description = ''
    self.assertEqual(
        True,
        external_testcase_reader.close_issue_if_invalid(
            self.mock_basic_issue, attachment_info, description))

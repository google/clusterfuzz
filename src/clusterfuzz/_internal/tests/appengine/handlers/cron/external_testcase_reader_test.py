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
from importlib.machinery import SourceFileLoader
from clusterfuzz._internal.cron import external_testcase_reader

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
    self.issue_tracker = mock.MagicMock()
    self.mock_submit_testcase = mock.MagicMock()
    self.mock_close_invalid_issue = mock.MagicMock()

  def test_fetch_and_upload(self):
    """Test a basic _fetch_and_upload."""
    mock_iter = mock.MagicMock()
    mock_iter.__iter__.return_value = [mock.MagicMock()]
    self.issue_tracker.find_issues.return_value = mock_iter
    self.mock_close_invalid_issue.return_value = 0
    external_testcase_reader._close_invalid_issue = self.mock_close_invalid_issue
    external_testcase_reader._submit_testcase = self.mock_submit_testcase

    external_testcase_reader._fetch_and_upload(self.issue_tracker)
    self.mock_close_invalid_issue.assert_called_once()
    self.issue_tracker.get_attachment.assert_called_once()
    self.mock_submit_testcase.assert_called_once()

  def test_fetch_and_upload_invalid(self):
    """Test a basic _fetch_and_upload where issue is invalid."""
    mock_iter = mock.MagicMock()
    mock_iter.__iter__.return_value = [mock.MagicMock()]
    self.issue_tracker.find_issues.return_value = mock_iter
    self.mock_close_invalid_issue.return_value = 1
    external_testcase_reader._close_invalid_issue = self.mock_close_invalid_issue
    external_testcase_reader._submit_testcase = self.mock_submit_testcase

    external_testcase_reader._fetch_and_upload(self.issue_tracker)
    self.mock_close_invalid_issue.assert_called_once()
    self.issue_tracker.get_attachment.assert_not_called()
    self.mock_submit_testcase.assert_not_called()

  def test_fetch_and_upload_no_issues(self):
    """Test a basic _fetch_and_upload that returns no issues."""
    external_testcase_reader._close_invalid_issue = self.mock_close_invalid_issue

    external_testcase_reader._fetch_and_upload(self.issue_tracker)
    self.mock_close_invalid_issue.assert_not_called()
    self.issue_tracker.get_attachment.assert_not_called()
    self.mock_submit_testcase.assert_not_called()

  def test_close_invalid_issue_basic(self):
    """Test a basic _close_invalid_issue with valid flags."""
    upload_request = mock.Mock()
    attachment_info = [BASIC_ATTACHMENT]
    description = "--flag-one --flag_two"
    self.assertEqual(
        0,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

  def test_close_invalid_issue_no_flag(self):
    """Test a basic _close_invalid_issue with no flags."""
    upload_request = mock.Mock()
    attachment_info = [BASIC_ATTACHMENT]
    description = ""
    self.assertEqual(
        0,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

  def test_close_invalid_issue_too_many_attachments(self):
    """Test _close_invalid_issue with too many attachments."""
    upload_request = mock.Mock()
    attachment_info = [BASIC_ATTACHMENT, BASIC_ATTACHMENT]
    description = ""
    self.assertEqual(
        1,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

  def test_close_invalid_issue_no_attachments(self):
    """Test _close_invalid_issue with no attachments."""
    upload_request = mock.Mock()
    attachment_info = []
    description = ""
    self.assertEqual(
        1,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

  def test_close_invalid_issue_invalid_upload(self):
    """Test _close_invalid_issue with an invalid upload."""
    upload_request = mock.Mock()
    attachment_info = [{
        'attachmentId': '60127668',
        'contentType': 'application/octet-stream',
        'length': '458',
        'filename': 'test.html',
        'attachmentDataRef': {},
        'etag': 'TXpjek9Ea3pNekV4TFRZd01USTNOalk0TFRjNE9URTROVFl4TlE9PQ=='
    }]
    description = ""
    self.assertEqual(
        1,
        external_testcase_reader._close_invalid_issue(
            upload_request, attachment_info, description))

  def test_close_invalid_issue_invalid_content_type(self):
    """Test _close_invalid_issue with an invalid content type."""
    upload_request = mock.Mock()
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

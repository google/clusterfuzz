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
BASIC_CONFIG = {
    'vrp-uploaders-bucket': 'bucket-name',
    'vrp-uploaders-blob': 'blob-name',
    'max-report-count-per-run': 5,
    'submitted-buffer-days': 1,
}


@mock.patch.object(
    external_testcase_reader,
    'get_vrp_uploaders',
    return_value=['test-reporter@gmail.com'],
    autospec=True)
@mock.patch.object(external_testcase_reader, 'submit_testcase', autospec=True)
@mock.patch.object(
    external_testcase_reader, 'close_issue_if_invalid', autospec=True)
class ExternalTestcaseReaderTest(unittest.TestCase):
  """external_testcase_reader handle main function tests."""

  def test_handle_testcases(self, mock_close_issue_if_invalid,
                            mock_submit_testcase, _):
    """Test a basic handle_testcases where issue is fit for submission."""
    mock_close_issue_if_invalid.return_value = False
    mock_it = mock.create_autospec(issue_tracker.IssueTracker)
    basic_issue = mock.MagicMock()
    basic_issue.reporter = 'test-reporter@gmail.com'
    mock_it.find_issues_with_filters.side_effect = [[], [basic_issue]]

    external_testcase_reader.handle_testcases(mock_it, BASIC_CONFIG)

    mock_close_issue_if_invalid.assert_called_once()
    mock_it.get_attachment.assert_called_once()
    mock_submit_testcase.assert_called_once()

  def test_handle_testcases_invalid(self, mock_close_issue_if_invalid,
                                    mock_submit_testcase, _):
    """Test a basic handle_testcases where issue is invalid."""
    mock_close_issue_if_invalid.return_value = True
    mock_it = mock.create_autospec(issue_tracker.IssueTracker)
    basic_issue = mock.MagicMock()
    basic_issue.reporter = 'test-reporter@gmail.com'
    mock_it.find_issues_with_filters.side_effect = [[], [basic_issue]]

    external_testcase_reader.handle_testcases(mock_it, BASIC_CONFIG)

    mock_close_issue_if_invalid.assert_called_once()
    mock_it.get_attachment.assert_not_called()
    mock_submit_testcase.assert_not_called()

  def test_handle_testcases_rate_limit(self, mock_close_issue_if_invalid,
                                       mock_submit_testcase, _):
    """Test a handle_testcases where one reporter hits the rate limit."""
    mock_close_issue_if_invalid.return_value = False
    mock_it = mock.create_autospec(issue_tracker.IssueTracker)
    basic_issue = mock.MagicMock()
    basic_issue.reporter = 'test-reporter@gmail.com'
    mock_it.find_issues_with_filters.side_effect = [[], [
        basic_issue, basic_issue, basic_issue, basic_issue, basic_issue,
        basic_issue
    ]]

    external_testcase_reader.handle_testcases(mock_it, BASIC_CONFIG)

    mock_close_issue_if_invalid.assert_called()
    self.assertEqual(mock_it.get_attachment.call_count, 5)
    self.assertEqual(mock_submit_testcase.call_count, 5)

  @mock.patch.object(
      external_testcase_reader,
      'close_issue_if_not_reproducible',
      autospec=True)
  def test_handle_testcases_not_reproducible(
      self, mock_repro, mock_close_issue_if_invalid, mock_submit_testcase, _):
    """Test a basic handle_testcases where issue is not reproducible."""
    mock_repro.return_value = True
    mock_it = mock.create_autospec(issue_tracker.IssueTracker)
    basic_issue = mock.MagicMock()
    basic_issue.reporter.return_value = 'test-reporter@gmail.com'
    mock_it.find_issues_with_filters.side_effect = [[basic_issue], []]

    external_testcase_reader.handle_testcases(mock_it, BASIC_CONFIG)

    mock_close_issue_if_invalid.assert_not_called()
    mock_it.get_attachment.assert_not_called()
    mock_submit_testcase.assert_not_called()

  def test_handle_testcases_no_issues(self, mock_close_issue_if_invalid,
                                      mock_submit_testcase, _):
    """Test a basic handle_testcases that returns no issues."""
    mock_it = mock.create_autospec(issue_tracker.IssueTracker)
    mock_it.find_issues_with_filters.return_value = []

    external_testcase_reader.handle_testcases(mock_it, BASIC_CONFIG)

    mock_close_issue_if_invalid.assert_not_called()
    mock_it.get_attachment.assert_not_called()
    mock_submit_testcase.assert_not_called()


class ExternalTestcaseReaderInvalidIssueTest(unittest.TestCase):
  """external_testcase_reader close_issue_if_invalid tests."""

  def setUp(self):
    self.mock_basic_issue = mock.MagicMock()
    self.mock_basic_issue.created_time = '2024-06-25T01:29:30.021Z'
    self.mock_basic_issue.status = 'NEW'
    self.mock_basic_issue.reporter = 'test-reporter@gmail.com'

  def test_close_issue_if_invalid_basic(self):
    """Test a basic close_issue_if_invalid with valid flags."""
    attachment_info = [BASIC_ATTACHMENT]
    description = '--flag-one --flag_two'

    actual = external_testcase_reader.close_issue_if_invalid(
        self.mock_basic_issue, attachment_info, description,
        ['test-reporter@gmail.com'])

    self.assertEqual(False, actual)

  def test_close_issue_if_invalid_no_flag(self):
    """Test a basic close_issue_if_invalid with no flags."""
    attachment_info = [BASIC_ATTACHMENT]
    description = ''

    actual = external_testcase_reader.close_issue_if_invalid(
        self.mock_basic_issue, attachment_info, description,
        ['test-reporter@gmail.com'])

    self.assertEqual(False, actual)

  def test_close_issue_if_invalid_too_many_attachments(self):
    """Test close_issue_if_invalid with too many attachments."""
    attachment_info = [BASIC_ATTACHMENT, BASIC_ATTACHMENT]
    description = ''

    actual = external_testcase_reader.close_issue_if_invalid(
        self.mock_basic_issue, attachment_info, description,
        ['test-reporter@gmail.com'])

    self.assertEqual(True, actual)

  def test_close_issue_if_invalid_no_attachments(self):
    """Test close_issue_if_invalid with no attachments."""
    attachment_info = []
    description = ''

    actual = external_testcase_reader.close_issue_if_invalid(
        self.mock_basic_issue, attachment_info, description,
        ['test-reporter@gmail.com'])

    self.assertEqual(True, actual)

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

    actual = external_testcase_reader.close_issue_if_invalid(
        self.mock_basic_issue, attachment_info, description,
        ['test-reporter@gmail.com'])

    self.assertEqual(True, actual)

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
    actual = external_testcase_reader.close_issue_if_invalid(
        self.mock_basic_issue, attachment_info, description,
        ['test-reporter@gmail.com'])

    self.assertEqual(True, actual)

  def test_close_issue_if_invalid_no_permission(self):
    """Test close_issue_if_invalid with an no upload permission."""
    attachment_info = [BASIC_ATTACHMENT]
    description = ''
    actual = external_testcase_reader.close_issue_if_invalid(
        self.mock_basic_issue, attachment_info, description, [])

    self.assertEqual(True, actual)


class ExternalTestcaseReaderPermissionTest(unittest.TestCase):
  """external_testcase_reader get_vrp_uploaders tests."""

  def test_get_vrp_uploaders(self):
    """Test get_vrp_uploaders."""
    with mock.patch(
        'src.clusterfuzz._internal.cron.external_testcase_reader.storage.Client'
    ) as mock_storage:
      mock_storage.return_value = mock.MagicMock()
      mock_bucket = mock.MagicMock()
      mock_storage.return_value.bucket.return_value = mock_bucket
      mock_blob = mock.MagicMock()
      mock_bucket.blob.return_value = mock_blob
      mock_blob.download_as_string.return_value = "test-user@google.com,test-user2@chromium.org".encode(
          'utf-8')

      actual = external_testcase_reader.get_vrp_uploaders(BASIC_CONFIG)
      mock_storage.return_value.bucket.assert_called_once_with('bucket-name')
      mock_bucket.blob.assert_called_once_with('blob-name')
      self.assertEqual(actual,
                       ['test-user@google.com', 'test-user2@chromium.org'])

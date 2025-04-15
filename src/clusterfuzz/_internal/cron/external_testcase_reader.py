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
"""Automated ingestion of testcases via IssueTracker."""

import datetime
import re

from google.cloud import storage
import requests

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.issue_management.google_issue_tracker import \
    issue_tracker
from clusterfuzz._internal.metrics import logs

ACCEPTED_FILETYPES = [
    'text/javascript', 'application/pdf', 'text/html', 'application/zip'
]
ISSUETRACKER_ACCEPTED_STATE = 'ACCEPTED'
ISSUETRACKER_WONTFIX_STATE = 'NOT_REPRODUCIBLE'
_CLUSTERFUZZ_GET_URL = (
    'https://clusterfuzz.corp.google.com/upload-testcase/get-url-oauth')
_UPLOAD_URL_PROPERTY = 'uploadUrl'
_TESTCASE_ID_PROPERTY = 'id'


class ExternalTestcaseReaderException(Exception):
  """Error when uploading an externally submitted testcase.."""

  def __init__(self, message):
    super().__init__(message)


def get_vrp_uploaders(config):
  """Checks whether the given reporter has permission to upload."""
  storage_client = storage.Client()
  bucket = storage_client.bucket(config.get('vrp-uploaders-bucket'))
  blob = bucket.blob(config.get('vrp-uploaders-blob'))
  members = blob.download_as_string().decode('utf-8').splitlines()[0].split(',')
  return members


def close_issue_if_invalid(issue, attachment_info, description, vrp_uploaders):
  """Closes any invalid upload requests with a helpful message."""
  comment_message = (
      'Hello, this issue is automatically closed. Please file a new bug after'
      ' fixing the following issues:\n\n')
  invalid = False

  # TODO(pgrace) Remove after testing.
  if issue.id == 373893311:
    return False

  if not issue.reporter in vrp_uploaders:
    comment_message += (
        'You are not authorized to submit testcases to Clusterfuzz.'
        ' If you believe you should be, please reach out to'
        ' clusterfuzz-vrp-uploaders-help@chromium.org for assistance.\n')
    invalid = True

  # Issue must have exactly one attachment.
  if len(attachment_info) != 1:
    comment_message += 'Please provide exactly one attachment.\n'
    invalid = True
  else:
    # Issue must use one of the supported testcase file types.
    if attachment_info[0]['contentType'] not in ACCEPTED_FILETYPES:
      comment_message += (
          'Please provide an attachment of type: html, js, pdf, or zip.\n')
      invalid = True
    if (not attachment_info[0]['attachmentDataRef'] or
        not attachment_info[0]['attachmentDataRef']['resourceName'] or
        not attachment_info[0]['filename']):
      comment_message += \
        'Please check that the attachment uploaded successfully.\n'
      invalid = True

  # Issue must have valid flags as the description.
  flag_format = re.compile(r'^([ ]?\-\-[A-Za-z\-\_]*){50}$')
  if description and flag_format.match(description):
    comment_message += (
        'Please provide flags in the format: "--test_flag_one --testflagtwo",\n'
    )
    invalid = True

  if invalid:
    comment_message += (
        '\nPlease see the new bug template for more information on how to use'
        ' Clusterfuzz direct uploads.')
    issue.status = ISSUETRACKER_WONTFIX_STATE
    issue.save(new_comment=comment_message, notify=True)

  return invalid


def close_issue_if_not_reproducible(issue, config):
  if issue.status == ISSUETRACKER_ACCEPTED_STATE and filed_n_days_ago(
      issue.created_time, config):
    comment_message = ('Clusterfuzz failed to reproduce - '
                       'please check testcase details for more info.')
    issue.status = ISSUETRACKER_WONTFIX_STATE
    issue.save(new_comment=comment_message, notify=True)
    return True
  return False


def filed_n_days_ago(issue_created_time_string, config):
  created_time = datetime.datetime.strptime(issue_created_time_string,
                                            '%Y-%m-%dT%H:%M:%S.%fZ')
  return datetime.datetime.now() - created_time > datetime.timedelta(
      days=config.get('submitted-buffer-days'))


def submit_testcase(issue_id, file, filename, filetype, cmds):
  """Uploads the given testcase file to Clusterfuzz."""
  get_url_response = requests.post(_CLUSTERFUZZ_GET_URL, timeout=10)
  if _UPLOAD_URL_PROPERTY not in get_url_response:
    logs.error('Unexpected response (missing uploadUrl): %s' % get_url_response)
    raise ExternalTestcaseReaderException(
        'Unexpected response (missing uploadUrl): %s' % get_url_response)
  upload_url = get_url_response[_UPLOAD_URL_PROPERTY]

  target = None
  if filetype == 'text/javascript':
    job = 'linux_asan_d8_dbg'
  elif filetype == 'application/pdf':
    job = 'libfuzzer_pdfium_asan'
    # Only libfuzzer_pdfium_asan needs a fuzzer target specified
    target = 'pdfium_xfa_fuzzer'
  elif filetype == 'text/html':
    job = 'linux_asan_chrome_mp'
  elif filetype == 'application/zip':
    job = 'linux_asan_chrome_mp'
  else:
    raise TypeError
  data = {
      'platform': 'Linux',
      'job': job,
      'issue': issue_id,
      'cmd': cmds,
      'file': file,
      'x-goog-meta-filename': filename,
  }

  if target:
    data['target'] = target

  upload_response = requests.post(upload_url, data=data, timeout=10)
  is_error_code = upload_response.status_code != 200
  is_missing_testcase_id = _TESTCASE_ID_PROPERTY not in upload_response
  if is_error_code or is_missing_testcase_id:
    reason = 'missing testcase id' if is_missing_testcase_id else 'failure code'
    msg = 'Unexpected response (%s): %s' % (reason, upload_response)
    logs.error(msg)
    raise ExternalTestcaseReaderException(msg)

  return upload_response


def handle_testcases(tracker, config):
  """Fetches and submits testcases from bugs or closes unnecessary bugs."""

  # Handle bugs that were already submitted and still open.
  older_issues = tracker.find_issues_with_filters(
      keywords=[],
      query_filters=['componentid:1600865', 'status:accepted'],
      only_open=True)
  for issue in older_issues:
    # Close out older bugs that may have failed to reproduce.
    if close_issue_if_not_reproducible(issue, config):
      logs.info('Closing issue %s as it failed to reproduce' & issue.id)

  # Handle new bugs that may need to be submitted.
  issues = tracker.find_issues_with_filters(
      keywords=[],
      query_filters=['componentid:1600865', 'status:new'],
      only_open=True)
  issues_list = list(issues)
  if len(issues_list) == 0:
    return

  vrp_uploaders = get_vrp_uploaders(config)

  # Rudimentary rate limiting -
  # Process only a certain number of bugs per reporter for each job run.
  reporters_map = {}

  for issue in issues_list:
    attachment_metadata = tracker.get_attachment_metadata(issue.id)
    commandline_flags = tracker.get_description(issue.id)
    if reporters_map.get(issue.reporter,
                         0) > config.get('max-report-count-per-run'):
      continue
    reporters_map[issue.reporter] = reporters_map.get(issue.reporter, 1) + 1
    if close_issue_if_invalid(issue, attachment_metadata, commandline_flags,
                              vrp_uploaders):
      logs.info('Closing issue %s as it is invalid' % issue.id)
      continue

    # Submit valid testcases.
    attachment_metadata = attachment_metadata[0]
    attachment = tracker.get_attachment(
        attachment_metadata['attachmentDataRef']['resourceName'])
    submit_testcase(issue.id, attachment, attachment_metadata['filename'],
                    attachment_metadata['contentType'], commandline_flags)
    comment_message = 'Testcase submitted to clusterfuzz'
    issue.status = ISSUETRACKER_ACCEPTED_STATE
    issue.assignee = 'clusterfuzz@chromium.org'
    issue.save(new_comment=comment_message, notify=True)
    logs.info('Submitted testcase file for issue %s' % issue.id)


_ISSUE_TRACKER_URL = 'https://issues.chromium.org/issues'


def main():
  tracker = issue_tracker.IssueTracker('chromium', None, {
      'default_component_id': 1363614,
      'url': _ISSUE_TRACKER_URL
  })
  handle_testcases(tracker, local_config.ExternalTestcaseReaderConfig())


if __name__ == '__main__':
  main()

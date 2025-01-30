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

from appengine.libs import form
from appengine.libs import gcs
from appengine.libs import helpers
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.issue_management.google_issue_tracker import \
    issue_tracker

ACCEPTED_FILETYPES = [
    'text/javascript', 'application/pdf', 'text/html', 'application/zip'
]
ISSUETRACKER_ACCEPTED_STATE = 'ACCEPTED'
ISSUETRACKER_WONTFIX_STATE = 'NOT_REPRODUCIBLE'


def get_vrp_uploaders(config):
  """Checks whether the given reporter has permission to upload."""
  storage_client = storage.Client()
  bucket = storage_client.bucket(config.get('vrp-uploaders-bucket'))
  blob = bucket.blob(config.get('vrp-uploaders-blob'))
  members = blob.download_as_string().decode('utf-8').splitlines()[0].split(',')
  return members


def close_issue_if_invalid(upload_request, attachment_info, description,
                           vrp_uploaders):
  """Closes any invalid upload requests with a helpful message."""
  comment_message = (
      'Hello, this issue is automatically closed. Please file a new bug after'
      ' fixing the following issues:\n\n')
  invalid = False

  # TODO(pgrace) Remove after testing.
  if upload_request.id == 373893311:
    return False

  if not upload_request.reporter in vrp_uploaders:
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
    upload_request.status = ISSUETRACKER_WONTFIX_STATE
    upload_request.save(new_comment=comment_message, notify=True)

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
  if filetype == 'text/javascript':
    job = 'linux_asan_d8_dbg'
  elif filetype == 'application/pdf':
    job = 'libfuzzer_pdfium_asan'
  elif filetype == 'text/html':
    job = 'linux_asan_chrome_mp'
  elif filetype == 'application/zip':
    job = 'linux_asan_chrome_mp'
  else:
    raise TypeError
  upload_info = gcs.prepare_blob_upload()._asdict()

  data = {
      # Content provided by uploader.
      'issue': issue_id,
      'job': job,
      'file': file,
      'cmd': cmds,
      'x-goog-meta-filename': filename,

      # Content generated internally.
      'platform': 'Linux',
      'csrf_token': form.generate_csrf_token(),
      'upload_key': upload_info['key'],
      # TODO(pgrace) Replace with upload_info['bucket'] once testing complete.
      'bucket': 'clusterfuzz-test-bucket',
      'key': upload_info['key'],
      'GoogleAccessId': upload_info['google_access_id'],
      'policy': upload_info['policy'],
      'signature': upload_info['signature'],
  }

  return requests.post(
      'https://clusterfuzz.com/upload-testcase/upload', data=data, timeout=10)


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
      helpers.log('Closing issue {issue_id} as it failed to reproduce',
                  issue.id)

  # Handle new bugs that may need to be submitted.
  issues = tracker.find_issues_with_filters(
      keywords=[],
      query_filters=['componentid:1600865', 'status:new'],
      only_open=True)
  if len(issues) == 0:
    return

  # TODO(pgrace) Cache in redis.
  vrp_uploaders = get_vrp_uploaders(config)

  # Rudimentary rate limiting -
  # Process only a certain number of bugs per reporter for each job run.
  reporters_map = {}

  for issue in issues:
    attachment_metadata = tracker.get_attachment_metadata(issue.id)
    commandline_flags = tracker.get_description(issue.id)
    if reporters_map.get(issue.reporter,
                         0) > config.get('max-report-count-per-run'):
      continue
    reporters_map[issue.reporter] = reporters_map.get(issue.reporter, 1) + 1
    if close_issue_if_invalid(issue, attachment_metadata, commandline_flags,
                              vrp_uploaders):
      helpers.log('Closing issue {issue_id} as it is invalid', issue.id)
      continue

    # Submit valid testcases.
    # TODO(pgrace) replace with 0 once testing is complete
    attachment_metadata = attachment_metadata[6]
    attachment = tracker.get_attachment(
        attachment_metadata['attachmentDataRef']['resourceName'])
    submit_testcase(issue.id, attachment, attachment_metadata['filename'],
                    attachment_metadata['contentType'], commandline_flags)
    comment_message = 'Testcase submitted to clusterfuzz'
    issue.status = ISSUETRACKER_ACCEPTED_STATE
    issue.assignee = 'clusterfuzz@chromium.org'
    issue.save(new_comment=comment_message, notify=True)
    helpers.log('Submitted testcase file for issue {issue_id}', issue.id)


def main():
  tracker = issue_tracker.IssueTracker('chromium', None,
                                       {'default_component_id': 1363614})
  handle_testcases(tracker, local_config.ExternalTestcaseReaderConfig())


if __name__ == '__main__':
  main()

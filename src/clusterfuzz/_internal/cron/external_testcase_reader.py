# Copyright 20204 Google LLC
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

import re
import requests

from appengine.libs.gcs import prepare_blob_upload
from appengine.libs.form import generate_csrf_token
from clusterfuzz._internal.issue_management.google_issue_tracker.issue_tracker \
  import IssueTracker
from libs import helpers


def _close_invalid_issue(upload_request, attachment_info, description):
  """Close any invalid upload requests with a helpful message."""
  comment_messsage = '''
    Hello, this issue is automatically closed. Please file a new bug after
    fixing the following issues:\n\n'''
  valid = True

  # TODO(pgrace) remove after testing
  if upload_request.id == '373893311':
    return 0

  # TODO(pgrace) add secondary check for authorized reporters

  # Issue must have exactly one attachment
  if len(attachment_info) != 1:
    comment_messsage += 'Please provide exactly one attachment.\n'
    valid = False
  else:
    # Issue must use one of the supported testcase file types
    if attachment_info[0]['contentType'] not in \
      ['text/javascript', 'application/pdf', 'text/html', 'application/zip']:
      comment_messsage += \
        'Please provide an attachment of type: html, js, pdf, or zip.\n'
      valid = False

  # Issue must have valid flags as the description
  flag_format = re.compile(r"^([ ]?\-\-[A-Za-z\-\_]*){50}$")
  if flag_format.match(description):
    comment_messsage += \
      'Please provide flags in the format: "--test_flag_one --testflagtwo",\n'
    valid = False

  if not valid:
    comment_messsage += '''
      \n\n Please see the new bug template for more information on how to use
      Clusterfuzz direct uploads.'''
    upload_request.status = 'not_reproducible'
    upload_request.save(new_comment=comment_messsage, notify=True)
    return 1

  return 0


def _submit_testcase(issue_id, file, filename, filetype, cmds):
  """Upload the given testcase file to Clusterfuzz."""
  match filetype:
    case 'text/javascript':
      job = 'linux_asan_d8_dbg'
    case 'application/pdf':
      job = 'libfuzzer_pdfium_asan'
    case 'text/html':
      job =  'linux_asan_chrome_mp'
    case 'application/zip':
      job =  'linux_asan_chrome_mp'
    case _:
      raise TypeError
  upload_info = prepare_blob_upload()._asdict()

  data = {
    # Content provided by uploader
    "issue": issue_id,
    "job": job,
    "file": file,
    "cmd": cmds,
    "x-goog-meta-filename": filename,

    # Content generated internally
    "platform": "Linux",
    "csrf_token": generate_csrf_token(),
    "upload_key": upload_info["key"],
    # TODO(pgrace) replace with upload_info["bucket"] once testing complete
    "bucket":  "clusterfuzz-test-bucket",
    "key":  upload_info["key"],
    "GoogleAccessId":  upload_info["google_access_id"],
    "policy":  upload_info["policy"],
    "signature":  upload_info["signature"],
  }

  return requests.post(
    "https://clusterfuzz.com/upload-testcase/upload", data=data, timeout=10)


if __name__ == '__main__':
  it = IssueTracker('chromium', None, {'default_component_id': 1363614})

  # TODO(pgrace) replace once testing complete with
  # it.get_issues(["componentid:1600865"], is_open=True)
  issues = [it.get_issue(373893311)]

  for issue in issues:
    attachment_metadata = it.get_attachment_metadata(issue.id)
    commandline_flags = it.get_description(issue.id)
    if _close_invalid_issue(issue, attachment_metadata, commandline_flags):
      helpers.log("Closing issue {issue_id} as it is invalid", issue.id)
      continue
    #TODO(pgrace) replace with 0 once upload is confirmed to work
    attachment_metadata = attachment_metadata[6]
    attachment = it.get_attachment(
      attachment_metadata['attachmentDataRef']['resourceName'])
    _submit_testcase(
      issue.id,
      attachment,
      attachment_metadata['filename'],
      attachment_metadata['contentType'],
      commandline_flags)
    helpers.log("Submitted testcase file for issue {issue_id}", issue.id)

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
"""Download files from GCS."""

import os
import urllib.parse

from flask import request

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.google_cloud_utils import blobs
from handlers import base_handler
from libs import access
from libs import gcs
from libs import helpers
from libs.issue_management import issue_tracker_utils


class Handler(base_handler.Handler, gcs.SignedGcsHandler):
  """Download a file from GCS."""

  def _send_blob(self,
                 blob_info,
                 testcase_id,
                 is_minimized=False,
                 fuzzer_binary_name=None):
    """Send the blob."""
    minimized_string = 'minimized-' if is_minimized else ''
    fuzzer_binary_string = (
        fuzzer_binary_name + '-' if fuzzer_binary_name else '')
    if testcase_id:
      _, extension = os.path.splitext(blob_info.filename)
      filename = (
          'clusterfuzz-testcase-'
          '{minimized_string}{fuzzer_binary_string}{testcase_id}{extension}'
      ).format(
          minimized_string=minimized_string,
          fuzzer_binary_string=fuzzer_binary_string,
          testcase_id=testcase_id,
          extension=extension)
    else:
      filename = blob_info.filename

    content_disposition = str('attachment; filename=%s' % filename)
    response = self.serve_gcs_object(blob_info.bucket, blob_info.object_path,
                                     content_disposition)
    response.headers['Content-disposition'] = content_disposition
    return response

  def check_public_testcase(self, blob_info, testcase):
    """Check public testcase."""
    if blob_info.key() != testcase.minimized_keys:
      return False

    if not testcase.bug_information:
      return False

    issue_tracker = issue_tracker_utils.get_issue_tracker_for_testcase(testcase)
    issue = issue_tracker.get_issue(testcase.bug_information)
    if not issue:
      return False

    # If the issue is explicitly marked as view restricted to committers only
    # (OSS-Fuzz only), then don't allow public download.
    if 'restrict-view-commit' in issue.labels:
      return False

    return True

  def get(self, resource=None):
    """Handle a get request with resource."""
    testcase = None
    testcase_id = request.args.get('testcase_id')
    if not testcase_id and not resource:
      raise helpers.EarlyExitException('No file requested.', 400)

    if testcase_id:
      try:
        testcase = data_handler.get_testcase_by_id(testcase_id)
      except errors.InvalidTestcaseError:
        raise helpers.EarlyExitException('Invalid testcase.', 400)

      if not resource:
        if testcase.minimized_keys and testcase.minimized_keys != 'NA':
          resource = testcase.minimized_keys
        else:
          resource = testcase.fuzzed_keys

    fuzzer_binary_name = None
    if testcase:
      fuzzer_binary_name = testcase.get_metadata('fuzzer_binary_name')

    resource = str(urllib.parse.unquote(resource))
    blob_info = blobs.get_blob_info(resource)
    if not blob_info:
      raise helpers.EarlyExitException('File does not exist.', 400)

    if (testcase and testcase.fuzzed_keys != blob_info.key() and
        testcase.minimized_keys != blob_info.key()):
      raise helpers.EarlyExitException('Invalid testcase.', 400)

    if (utils.is_oss_fuzz() and testcase and
        self.check_public_testcase(blob_info, testcase)):
      # Public OSS-Fuzz testcase.
      return self._send_blob(
          blob_info,
          testcase.key.id(),
          is_minimized=True,
          fuzzer_binary_name=fuzzer_binary_name)

    is_minimized = testcase and blob_info.key() == testcase.minimized_keys
    if access.has_access():
      # User has general access.
      return self._send_blob(blob_info, testcase_id, is_minimized,
                             fuzzer_binary_name)

    # If this blobstore file is for a testcase, check if the user has access to
    # the testcase.
    if not testcase:
      raise helpers.AccessDeniedException()

    if access.can_user_access_testcase(testcase):
      return self._send_blob(blob_info, testcase_id, is_minimized,
                             fuzzer_binary_name)

    raise helpers.AccessDeniedException()

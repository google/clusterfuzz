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
"""Handler that serves the testcase file."""

import urllib.parse

from flask import request

from clusterfuzz._internal.google_cloud_utils import blobs
from handlers import base_handler
from libs import access
from libs import gcs
from libs import handler
from libs import helpers

# Blob's filename can be very long. We only preview the last N characters.
# A too long file name can cause an issue with `curl` and `wget`.
PREVIEW_BLOB_FILENAME_LENTGH = 20


def get_testcase_blob_info(testcase):
  """Get testcase file in the binary form."""
  blob_key = testcase.minimized_keys
  using_minimized_keys = True

  if not blob_key or blob_key == 'NA':
    blob_key = testcase.fuzzed_keys
    using_minimized_keys = False

  if not blob_key:
    raise helpers.EarlyExitException(
        "The testcase (%d) doesn't have fuzzed keys." % testcase.key.id(), 400)

  blob_key = str(urllib.parse.unquote(blob_key))

  blob_info = blobs.get_blob_info(blob_key)
  return blob_info, using_minimized_keys


def get(self):
  """Get testcase file and write it to the handler."""
  testcase_id = request.get('id')
  testcase = access.check_access_and_get_testcase(testcase_id)

  blob_info, _ = get_testcase_blob_info(testcase)

  save_as_filename = 'testcase-%s-%s' % (
      testcase.key.id(), blob_info.filename[-PREVIEW_BLOB_FILENAME_LENTGH:])

  content_disposition = str('attachment; filename=%s' % save_as_filename)
  return self.serve_gcs_object(blob_info.bucket, blob_info.object_path,
                               content_disposition)


class Handler(base_handler.Handler, gcs.SignedGcsHandler):
  """Handler that gets the testcase file."""

  @handler.get(handler.HTML)
  @handler.oauth
  def get(self):
    """Serve the testcase file."""
    return get(self)

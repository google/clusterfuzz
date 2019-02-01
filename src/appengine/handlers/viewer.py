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
"""Content viewer."""

from base import utils
from google_cloud_utils import blobs
from handlers import base_handler
from libs import access
from libs import handler
from libs import helpers

MAX_ALLOWED_CONTENT_SIZE = 10 * 1024 * 1024


class Handler(base_handler.Handler):
  """Content Viewer."""

  @handler.get(handler.HTML)
  def get(self):
    """Get the HTML page."""
    key = self.request.get('key')
    if not key:
      raise helpers.EarlyExitException('No key provided.', 400)

    testcase_id = self.request.get('testcase_id')
    if testcase_id:
      testcase = helpers.get_testcase(testcase_id)
      if not access.can_user_access_testcase(testcase):
        raise helpers.AccessDeniedException()

      if key not in [testcase.fuzzed_keys, testcase.minimized_keys]:
        raise helpers.AccessDeniedException()
    else:
      if not access.has_access():
        raise helpers.AccessDeniedException()

    if blobs.get_blob_size(key) > MAX_ALLOWED_CONTENT_SIZE:
      raise helpers.EarlyExitException('Content exceeds max allowed size.', 400)

    try:
      content = unicode(blobs.read_key(key), errors='replace')
    except Exception:
      raise helpers.EarlyExitException('Failed to read content.', 400)

    line_count = len(content.splitlines())
    size = len(content)
    title = '%s, %s' % (utils.get_line_count_string(line_count),
                        utils.get_size_string(size))

    self.render('viewer.html', {'content': content, 'title': title})

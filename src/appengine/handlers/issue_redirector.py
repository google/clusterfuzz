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
"""Handler for redirecting to the issue url (given a testcase). See
  crbug.com/665652 on why we need it."""

from handlers import base_handler
from libs import helpers
from libs.issue_management import issue_tracker_utils


class Handler(base_handler.Handler):
  """Handler that redirects user to the issue URL."""

  def get(self, testcase_id=None):
    """Redirect user to the correct URL."""
    testcase = helpers.get_testcase(testcase_id)
    issue_url = helpers.get_or_exit(
        lambda: issue_tracker_utils.get_issue_url(testcase),
        'Issue tracker for testcase (id=%s) is not found.' % testcase_id,
        'Failed to get the issue tracker URL.')

    return self.redirect(issue_url)

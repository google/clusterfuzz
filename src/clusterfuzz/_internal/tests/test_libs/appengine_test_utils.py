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
"""Generic helper functions useful in tests (App Engine only)."""

import datetime

from clusterfuzz._internal.tests.test_libs import test_utils
from libs.issue_management import monorail
from libs.issue_management.monorail.comment import Comment
from libs.issue_management.monorail.issue import Issue


def create_generic_issue(created_days_ago=28):
  """Returns a simple issue object for use in tests."""
  issue = Issue()
  issue.cc = []
  issue.comment = ''
  issue.comments = []
  issue.components = []
  issue.labels = []
  issue.open = True
  issue.owner = 'owner@chromium.org'
  issue.status = 'Assigned'
  issue.id = 1
  issue.itm = create_issue_tracker_manager()

  # Test issue was created 1 week before the current (mocked) time.
  issue.created = (
      test_utils.CURRENT_TIME - datetime.timedelta(days=created_days_ago))

  return monorail.Issue(issue)


def create_generic_issue_comment(comment_body='Comment.',
                                 author='user@chromium.org',
                                 days_ago=21,
                                 labels=None):
  """Return a simple comment used for testing."""
  comment = Comment()
  comment.comment = comment_body
  comment.author = author
  comment.created = test_utils.CURRENT_TIME - datetime.timedelta(days=days_ago)
  comment.labels = labels

  if comment.labels is None:
    comment.labels = []

  return comment


def create_issue_tracker_manager():
  """Create a fake issue tracker manager."""

  class FakeIssueTrackerManager(object):
    """Mock issue tracker manager."""

    def __init__(self):
      self.project_name = 'test-project'
      self.issues = {}
      self.next_id = 1

    def get_issue(self, issue_id):
      """Get original issue."""
      issue = self.issues.get(issue_id)
      if not issue:
        return None

      issue.itm = self
      return issue

    def get_comments(self, issue):  # pylint: disable=unused-argument
      """Return an empty comment list."""
      return []

    def save(self, issue, *args, **kwargs):  # pylint: disable=unused-argument
      """Save an issue."""
      if issue.new:
        issue.id = self.next_id
        issue.new = False
        self.next_id += 1

      self.issues[issue.id] = issue

  return FakeIssueTrackerManager()

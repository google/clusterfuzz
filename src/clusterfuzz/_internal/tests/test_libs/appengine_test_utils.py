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

from clusterfuzz._internal.issue_management import issue_tracker
from clusterfuzz._internal.tests.test_libs import test_utils


class MockIssue(issue_tracker.Issue):
  """Mock issue."""

  def __init__(self):
    self._id = 1
    self._title = ''
    self._reporter = ''
    self._merged_into = None
    self._closed_time = None
    self._status = 'Assigned'
    self._body = ''
    self._assignee = 'owner@chromium.org'
    self._ccs = issue_tracker.LabelStore()
    self._labels = issue_tracker.LabelStore()
    self._components = issue_tracker.LabelStore()
    self._actions = []
    self.created = None
    self.itm = None
    self.open = True
    self._comment = ''

  @property
  def id(self):
    return self._id

  @id.setter
  def id(self, value):
    self._id = value

  @property
  def title(self):
    return self._title

  @title.setter
  def title(self, value):
    self._title = value

  @property
  def summary(self):
    return self._title

  @summary.setter
  def summary(self, value):
    self._title = value

  @property
  def reporter(self):
    return self._reporter

  @reporter.setter
  def reporter(self, value):
    self._reporter = value

  @property
  def merged_into(self):
    return self._merged_into

  @merged_into.setter
  def merged_into(self, value):
    self._merged_into = value

  @property
  def closed_time(self):
    return self._closed_time

  @closed_time.setter
  def closed_time(self, value):
    self._closed_time = value

  @property
  def is_open(self):
    return self.open

  @property
  def status(self):
    return self._status

  @status.setter
  def status(self, value):
    self._status = value

  @property
  def body(self):
    return self._body

  @body.setter
  def body(self, value):
    self._body = value

  @property
  def comment(self):
    return self._comment

  @comment.setter
  def comment(self, value):
    self._comment = value

  @property
  def assignee(self):
    return self._assignee

  @assignee.setter
  def assignee(self, value):
    self._assignee = value

  @property
  def ccs(self):
    return self._ccs

  @ccs.setter
  def ccs(self, value):
    self._ccs = issue_tracker.LabelStore(value)

  @property
  def labels(self):
    return self._labels

  @labels.setter
  def labels(self, value):
    self._labels = issue_tracker.LabelStore(value)

  @property
  def components(self):
    return self._components

  @components.setter
  def components(self, value):
    self._components = issue_tracker.LabelStore(value)

  @property
  def actions(self):
    return self._actions

  def save(self, new_comment=None, notify=True):
    if new_comment:
      self.comment = new_comment
    if self.itm:
      self.itm.save(self, new_comment=new_comment, notify=notify)


class MockAction(issue_tracker.Action):
  """Mock action."""

  def __init__(self, comment=None, author=None, created=None, labels=None):
    self._comment = comment
    self._author = author
    self._created = created
    self._labels = issue_tracker.ChangeList()
    if labels:
      self._labels.added.extend(labels)

  @property
  def author(self):
    return self._author

  @author.setter
  def author(self, value):
    self._author = value

  @property
  def comment(self):
    return self._comment

  @comment.setter
  def comment(self, value):
    self._comment = value

  @property
  def created(self):
    return self._created

  @created.setter
  def created(self, value):
    self._created = value

  @property
  def title(self):
    return None

  @property
  def status(self):
    return None

  @property
  def assignee(self):
    return None

  @property
  def ccs(self):
    return issue_tracker.ChangeList()

  @property
  def labels(self):
    return self._labels

  @labels.setter
  def labels(self, value):
    self._labels = value

  @property
  def components(self):
    return issue_tracker.ChangeList()


def create_generic_issue(created_days_ago=28):
  """Returns a simple issue object for use in tests."""
  issue = MockIssue()
  issue.id = 1
  issue.itm = create_issue_tracker_manager()

  # Test issue was created 1 week before the current (mocked) time.
  issue.created = (
      test_utils.CURRENT_TIME - datetime.timedelta(days=created_days_ago))

  return issue


def create_generic_issue_comment(comment_body='Comment.',
                                 author='user@chromium.org',
                                 days_ago=21,
                                 labels=None):
  """Return a simple comment used for testing."""
  created = test_utils.CURRENT_TIME - datetime.timedelta(days=days_ago)
  return MockAction(
      comment=comment_body, author=author, created=created, labels=labels)


def create_issue_tracker_manager():
  """Create a fake issue tracker manager."""

  class FakeIssueTrackerManager:
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
      if not issue.id:
        issue.id = self.next_id
        self.next_id += 1

      self.issues[issue.id] = issue

  return FakeIssueTrackerManager()

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Issue tracker interface."""


class LabelStore(object):
  """Label storage which tracks changes. Case insensitive, but preserves
  case."""

  def __init__(self, seq=()):
    self._backing = {}
    self._added = {}
    self._removed = {}

    for item in seq:
      self._backing[item.lower()] = item

  def __iter__(self):
    for value in self._backing.values():
      yield value

  def __contains__(self, item):
    return item.lower() in self._backing

  @property
  def added(self):
    return self._added.values()

  @property
  def removed(self):
    return self._removed.values()

  def add(self, label):
    """Add a new label."""
    if not label:
      return

    label = str(label)
    key = label.lower()
    if key in self._removed:
      del self._removed[key]
    else:
      self._added[key] = label

    self._backing[key] = label

  def remove(self, label):
    """Remove a label."""
    label = str(label)
    key = label.lower()
    if key not in self._backing:
      return

    if key in self._added:
      del self._added[key]
    else:
      self._removed[key] = label

    del self._backing[key]

  def reset_tracking(self):
    """Reset tracking."""
    self._added.clear()
    self._removed.clear()

  def clear(self):
    """Clear the store, and reset tracking."""
    self.reset_tracking()
    self._backing.clear()

  def get_by_prefix(self, prefix):
    """Get labels with the given prefix."""
    for item in self:
      if item.lower().startswith(prefix.lower()):
        yield item

  def has_with_prefix(self, prefix):
    """Return whether if there is an item with the given prefix."""
    return bool(next(self.get_by_prefix(prefix), None))

  def remove_by_prefix(self, prefix):
    """Remove labels with a given prefix."""
    for item in list(self):
      if item.lower().startswith(prefix.lower()):
        self.remove(item)

  def get_by_pattern(self, re_pattern):
    """Get labels with the given pattern."""
    for item in self:
      if re_pattern.match(item):
        yield item

  def has_with_pattern(self, re_pattern):
    """Return whether if there is an item with the given pattern."""
    return bool(next(self.get_by_pattern(re_pattern), None))


class Issue(object):
  """Represents an issue."""

  @property
  def issue_tracker(self):
    """The issue tracker for this issue."""
    raise NotImplementedError

  @property
  def id(self):
    """The issue identifier."""
    raise NotImplementedError

  @property
  def title(self):
    """The issue title."""
    raise NotImplementedError

  @title.setter
  def title(self, new_title):
    raise NotImplementedError

  @property
  def reporter(self):
    """The issue reporter."""
    raise NotImplementedError

  @reporter.setter
  def reporter(self, new_reporter):
    raise NotImplementedError

  @property
  def merged_into(self):
    """The issue that this is merged into."""
    raise NotImplementedError

  @property
  def closed_time(self):
    """When the issue was closed."""
    raise NotImplementedError

  @property
  def is_open(self):
    """Whether the issue is open."""
    raise NotImplementedError

  @property
  def status(self):
    """The issue status."""
    raise NotImplementedError

  @status.setter
  def status(self, new_status):
    raise NotImplementedError

  @property
  def body(self):
    """The issue body."""
    raise NotImplementedError

  @body.setter
  def body(self, new_body):
    raise NotImplementedError

  @property
  def assignee(self):
    """The issue assignee."""
    raise NotImplementedError

  @assignee.setter
  def assignee(self, new_assignee):
    raise NotImplementedError

  @property
  def ccs(self):
    """The issue CC list."""
    raise NotImplementedError

  @property
  def labels(self):
    """The issue labels list."""
    raise NotImplementedError

  @property
  def components(self):
    """The issue component list."""
    raise NotImplementedError

  @property
  def actions(self):
    """Get the issue actions."""
    raise NotImplementedError

  def save(self, new_comment=None, notify=True):
    """Save the issue."""
    raise NotImplementedError


class ChangeList(object):
  """Records a change in a list."""

  def __init__(self):
    self.added = []
    self.removed = []


class Action(object):
  """Represents an action on an issue (e.g. a comment)."""

  @property
  def author(self):
    """The author of the action."""
    raise NotImplementedError

  @property
  def comment(self):
    """Represents a comment."""
    raise NotImplementedError

  @property
  def title(self):
    """The new issue title."""
    raise NotImplementedError

  @property
  def status(self):
    """The new issue status."""
    raise NotImplementedError

  @property
  def assignee(self):
    """The new issue assignee."""
    raise NotImplementedError

  @property
  def ccs(self):
    """The issue CC change list."""
    raise NotImplementedError

  @property
  def labels(self):
    """The issue labels change list."""
    raise NotImplementedError

  @property
  def components(self):
    """The issue component change list."""
    raise NotImplementedError


class IssueTracker(object):
  """Issue tracker interface."""

  @property
  def project(self):
    """Get the project name of this issue tracker."""
    raise NotImplementedError

  @property
  def label_type(self):
    """Label type."""
    return 'label'  # default

  def label_text(self, label):
    """Text for a label (with label type)."""
    return label + ' ' + self.label_type

  def new_issue(self):
    """Create an unsaved new issue."""
    raise NotImplementedError

  def get_issue(self, issue_id):
    """Get the issue with the given ID."""
    raise NotImplementedError

  def get_original_issue(self, issue_id):
    """Retrieve the original issue object traversing the list of duplicates."""
    # Caller might pass |issue_id| as int, so change it to str so that
    # circular chain checks in loop actually work.
    original_issue_id = str(issue_id)
    seen_issue_ids = []
    while True:
      original_issue = self.get_issue(original_issue_id)
      if not original_issue:
        return None

      seen_issue_ids.append(original_issue_id)

      if not original_issue.merged_into:
        # If this is an original issue, no more work to do. Bail out.
        break

      original_issue_id = str(original_issue.merged_into)
      if original_issue_id in seen_issue_ids:
        # Don't traverse a circular chain, break if we realise that.
        break

    return original_issue

  def find_issues(self, keywords=None, only_open=None):
    """Find issues."""
    raise NotImplementedError

  def find_issues_url(self, keywords=None, only_open=None):
    """Find issues (web URL)."""
    raise NotImplementedError

  def issue_url(self, issue_id):
    """Return the issue URL with the given ID."""
    raise NotImplementedError

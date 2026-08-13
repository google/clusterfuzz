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
"""Issue tracker interface."""

import datetime
from typing import Any
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import Pattern
from typing import Union
from typing import ValuesView


class LabelStore:
  """Label storage which tracks changes. Case insensitive, but preserves
  case."""

  def __init__(self, seq: Iterable[str] = ()):
    self._backing: Dict[str, str] = {}
    self._added: Dict[str, str] = {}
    self._removed: Dict[str, str] = {}

    for item in seq:
      self._backing[item.lower()] = item

  def __iter__(self) -> Iterator[str]:
    yield from self._backing.values()

  def __contains__(self, item: str) -> bool:
    return item.lower() in self._backing

  @property
  def added(self) -> ValuesView[str]:
    return self._added.values()

  @property
  def removed(self) -> ValuesView[str]:
    return self._removed.values()

  def add(self, label: Optional[object]) -> None:
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

  def remove(self, label: object) -> None:
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

  def reset_tracking(self) -> None:
    """Reset tracking."""
    self._added.clear()
    self._removed.clear()

  def clear(self) -> None:
    """Clear the store, and reset tracking."""
    self._added.clear()
    self._removed.update(self._backing)
    self._backing.clear()

  def get_by_prefix(self, prefix: str) -> Iterator[str]:
    """Get labels with the given prefix."""
    for item in self:
      if item.lower().startswith(prefix.lower()):
        yield item

  def has_with_prefix(self, prefix: str) -> bool:
    """Return whether if there is an item with the given prefix."""
    return bool(next(self.get_by_prefix(prefix), None))

  def remove_by_prefix(self, prefix: str) -> None:
    """Remove labels with a given prefix."""
    for item in list(self):
      if item.lower().startswith(prefix.lower()):
        self.remove(item)

  def get_by_pattern(self, re_pattern: Pattern[str]) -> Iterator[str]:
    """Get labels with the given pattern."""
    for item in self:
      if re_pattern.match(item):
        yield item

  def has_with_pattern(self, re_pattern: Pattern[str]) -> bool:
    """Return whether if there is an item with the given pattern."""
    return bool(next(self.get_by_pattern(re_pattern), None))


class Issue:
  """Represents an issue."""

  @property
  def issue_tracker(self) -> 'IssueTracker':
    """The issue tracker for this issue."""
    raise NotImplementedError

  @property
  def id(self) -> Optional[int]:
    """The issue identifier."""
    raise NotImplementedError

  @property
  def title(self) -> Optional[str]:
    """The issue title."""
    raise NotImplementedError

  @title.setter
  def title(self, new_title: Optional[str]) -> None:
    raise NotImplementedError

  @property
  def reporter(self) -> Optional[str]:
    """The issue reporter."""
    raise NotImplementedError

  @reporter.setter
  def reporter(self, new_reporter: Optional[str]) -> None:
    raise NotImplementedError

  @property
  def merged_into(self) -> Optional[Union[int, str]]:
    """The issue that this is merged into."""
    raise NotImplementedError

  @property
  def closed_time(self) -> Optional[datetime.datetime]:
    """When the issue was closed."""
    raise NotImplementedError

  @property
  def is_open(self) -> bool:
    """Whether the issue is open."""
    raise NotImplementedError

  @property
  def status(self) -> Optional[str]:
    """The issue status."""
    raise NotImplementedError

  @status.setter
  def status(self, new_status: Optional[str]) -> None:
    raise NotImplementedError

  @property
  def body(self) -> Optional[str]:
    """The issue body."""
    raise NotImplementedError

  @body.setter
  def body(self, new_body: Optional[str]) -> None:
    raise NotImplementedError

  @property
  def assignee(self) -> Optional[str]:
    """The issue assignee."""
    raise NotImplementedError

  @assignee.setter
  def assignee(self, new_assignee: Optional[str]) -> None:
    raise NotImplementedError

  @property
  def ccs(self) -> LabelStore:
    """The issue CC list."""
    raise NotImplementedError

  @property
  def labels(self) -> LabelStore:
    """The issue labels list."""
    raise NotImplementedError

  @property
  def components(self) -> LabelStore:
    """The issue component list."""
    raise NotImplementedError

  @property
  def actions(self) -> Iterable['Action']:
    """Get the issue actions."""
    raise NotImplementedError

  def save(self, new_comment: Optional[str] = None,
           notify: bool = True) -> None:
    """Save the issue."""
    raise NotImplementedError

  @property
  def is_unrestricted(self) -> bool:
    """Whether the issue has no view restrictions (i.e. is public)."""
    return False

  # pylint: disable=unused-argument
  def apply_extension_fields(self, extension_fields: Dict[str, Any]) -> None:
    """Applies _ext_ prefixed extension fields to the issue."""
    return


class ChangeList:
  """Records a change in a list."""

  def __init__(self) -> None:
    self.added: List[str] = []
    self.removed: List[str] = []


class Action:
  """Represents an action on an issue (e.g. a comment)."""

  @property
  def author(self) -> Optional[str]:
    """The author of the action."""
    raise NotImplementedError

  @property
  def comment(self) -> Optional[str]:
    """Represents a comment."""
    raise NotImplementedError

  @property
  def title(self) -> Optional[str]:
    """The new issue title."""
    raise NotImplementedError

  @property
  def status(self) -> Optional[str]:
    """The new issue status."""
    raise NotImplementedError

  @property
  def assignee(self) -> Optional[str]:
    """The new issue assignee."""
    raise NotImplementedError

  @property
  def ccs(self) -> ChangeList:
    """The issue CC change list."""
    raise NotImplementedError

  @property
  def labels(self) -> ChangeList:
    """The issue labels change list."""
    raise NotImplementedError

  @property
  def components(self) -> ChangeList:
    """The issue component change list."""
    raise NotImplementedError


class IssueTracker:
  """Issue tracker interface."""

  @property
  def project(self) -> str:
    """Get the project name of this issue tracker."""
    raise NotImplementedError

  @property
  def label_type(self) -> str:
    """Label type."""
    return 'label'  # default

  def label_text(self, label: str) -> str:
    """Text for a label (with label type)."""
    return label + ' ' + self.label_type

  def new_issue(self) -> Issue:
    """Create an unsaved new issue."""
    raise NotImplementedError

  def get_issue(self, issue_id: Union[int, str]) -> Optional[Issue]:
    """Get the issue with the given ID."""
    raise NotImplementedError

  def get_original_issue(self, issue_id: Union[int, str]) -> Optional[Issue]:
    """Retrieve the original issue object traversing the list of duplicates."""
    # Caller might pass |issue_id| as int, so change it to str so that
    # circular chain checks in loop actually work.
    original_issue_id = str(issue_id)
    seen_issue_ids: List[str] = []
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

  def find_issues(
      self,
      keywords: Optional[Union[str, List[str]]] = None,
      only_open: Optional[bool] = None) -> Optional[Iterable[Issue]]:
    """Find issues."""
    raise NotImplementedError

  def find_issues_with_filters(
      self,
      keywords: Optional[Union[str, List[str]]] = None,
      query_filters: Optional[Any] = None,
      only_open: Optional[bool] = None) -> Optional[Iterable[Issue]]:
    """Find issues."""
    raise NotImplementedError

  def find_issues_url(self,
                      keywords: Optional[Union[str, List[str]]] = None,
                      only_open: Optional[bool] = None) -> Optional[str]:
    """Find issues (web URL)."""
    raise NotImplementedError

  def find_issues_url_with_filters(
      self,
      keywords: Optional[Union[str, List[str]]] = None,
      query_filters: Optional[Any] = None,
      only_open: Optional[bool] = None) -> Optional[str]:
    """Find issues."""
    raise NotImplementedError

  def issue_url(self, issue_id: Union[int, str]) -> Optional[str]:
    """Return the issue URL with the given ID."""
    raise NotImplementedError

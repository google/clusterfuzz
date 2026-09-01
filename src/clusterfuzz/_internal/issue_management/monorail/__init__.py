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
"""Monorail issue tracker."""

import datetime
from typing import Any
from typing import cast
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import Union
import urllib.parse

from clusterfuzz._internal.issue_management import issue_tracker
from clusterfuzz._internal.issue_management.issue_tracker import ChangeList
from clusterfuzz._internal.issue_management.issue_tracker import LabelStore
from clusterfuzz._internal.issue_management.monorail.comment import Comment
from clusterfuzz._internal.issue_management.monorail.issue import \
    Issue as MonorailIssue
# pylint: disable=line-too-long
from clusterfuzz._internal.issue_management.monorail.issue_tracker_manager import \
    IssueTrackerManager

ISSUE_TRACKER_URL: str = (
    'https://bugs.chromium.org/p/{project}/issues/detail?id={id}')
ISSUE_TRACKER_SEARCH_URL: str = (
    'https://bugs.chromium.org/p/{project}/issues/list?{params}')


class Issue(issue_tracker.Issue):
  """Represents an issue."""

  def __init__(self, monorail_issue: MonorailIssue) -> None:
    self._monorail_issue = monorail_issue

    # These mirror the underlying MonorailIssue data structures, to make it more
    # opaque to the client about how issue updates are done. For instance, when
    # a `label` is removed, what actually happens is `-label` is added. This
    # should not be visible to the client.
    self._ccs = LabelStore(self._monorail_issue.cc)
    self._components = LabelStore(self._monorail_issue.components)
    self._labels = LabelStore(self._monorail_issue.labels)

  @property
  def issue_tracker(self) -> 'IssueTracker':
    """The IssueTracker for this issue."""
    assert self._monorail_issue.itm is not None
    return IssueTracker(self._monorail_issue.itm)

  @property
  def id(self) -> Optional[int]:
    """The issue identifier."""
    return self._monorail_issue.id

  @property
  def title(self) -> Optional[str]:
    """The issue title."""
    return self._monorail_issue.summary

  @title.setter
  def title(self, new_title: Optional[str]) -> None:
    self._monorail_issue.summary = new_title

  @property
  def reporter(self) -> Optional[str]:
    """The issue reporter."""
    return self._monorail_issue.reporter

  @reporter.setter
  def reporter(self, new_reporter: Optional[str]) -> None:
    self._monorail_issue.reporter = new_reporter

  @property
  def merged_into(self) -> Optional[Union[int, str]]:
    """The issue that this is merged into."""
    if self._monorail_issue.merged_into_project != self.issue_tracker.project:
      # Don't consider duplicates in a different issue project.
      return None

    return self._monorail_issue.merged_into

  @property
  def is_open(self) -> bool:
    """Whether the issue is open."""
    return self._monorail_issue.open

  @property
  def closed_time(self) -> Optional[datetime.datetime]:
    return self._monorail_issue.closed

  @property
  def status(self) -> Optional[str]:
    """The issue status."""
    return self._monorail_issue.status

  @status.setter
  def status(self, new_status: Optional[str]) -> None:
    self._monorail_issue.status = new_status

  @property
  def body(self) -> Optional[str]:
    """The issue body."""
    return self._monorail_issue.body

  @body.setter
  def body(self, new_body: Optional[str]) -> None:
    self._monorail_issue.body = new_body

  @property
  def assignee(self) -> Optional[str]:
    """The issue assignee."""
    return self._monorail_issue.owner

  @assignee.setter
  def assignee(self, new_assignee: Optional[str]) -> None:
    self._monorail_issue.owner = new_assignee

  @property
  def ccs(self) -> LabelStore:
    """The issue CC list."""
    return self._ccs

  @property
  def labels(self) -> LabelStore:
    """The issue labels list."""
    return self._labels

  @property
  def components(self) -> LabelStore:
    """The issue component list."""
    return self._components

  @property
  def actions(self) -> Iterator['Action']:
    """Get the issue actions."""
    return (
        Action(comment)
        for comment in cast(Iterable[Any], self._monorail_issue.get_comments()))

  def save(self, new_comment: Optional[str] = None,
           notify: bool = True) -> None:
    """Save the issue."""

    # Apply actual label changes to the underlying MonorailIssue.
    for added in self._components.added:
      self._monorail_issue.add_component(added)
    for removed in self._components.removed:
      self._monorail_issue.remove_component(removed)
    self._components.reset_tracking()

    for added in self._ccs.added:
      self._monorail_issue.add_cc(added)
    for removed in self._ccs.removed:
      self._monorail_issue.remove_cc(removed)
    self._ccs.reset_tracking()

    for added in self._labels.added:
      self._monorail_issue.add_label(added)
    for removed in self._labels.removed:
      self._monorail_issue.remove_label(removed)
    self._labels.reset_tracking()

    if new_comment:
      self._monorail_issue.comment = new_comment

    self._monorail_issue.save(send_email=notify)


class Action(issue_tracker.Action):
  """Monorail Action."""

  def __init__(self, monorail_comment: Comment) -> None:
    self._monorail_comment = monorail_comment

  @property
  def author(self) -> Optional[str]:
    """The author of the action."""
    return self._monorail_comment.author

  @property
  def comment(self) -> Optional[str]:
    """Represents a comment."""
    return self._monorail_comment.comment

  @property
  def title(self) -> Optional[str]:
    """The new issue title."""
    return self._monorail_comment.summary

  @property
  def status(self) -> Optional[str]:
    """The new issue status."""
    return self._monorail_comment.status

  @property
  def assignee(self) -> Optional[str]:
    """The new issue assignee."""
    return self._monorail_comment.owner

  @property
  def ccs(self) -> ChangeList:
    """The issue CC change list."""
    return _to_change_list(self._monorail_comment.cc)

  @property
  def labels(self) -> ChangeList:
    """The issue labels change list."""
    return _to_change_list(self._monorail_comment.labels)

  @property
  def components(self) -> ChangeList:
    """The issue component change list."""
    return _to_change_list(self._monorail_comment.components)


class IssueTracker(issue_tracker.IssueTracker):
  """Issue tracker interface."""

  def __init__(self, itm: IssueTrackerManager) -> None:
    self._itm = itm

  @property
  def project(self) -> str:
    return self._itm.project_name

  def new_issue(self) -> Issue:
    monorail_issue = MonorailIssue()
    monorail_issue.itm = self._itm
    return Issue(monorail_issue)

  def get_issue(self, issue_id: Union[int, str]) -> Optional[Issue]:
    monorail_issue = self._itm.get_issue(int(issue_id))
    if not monorail_issue:
      return None

    return Issue(monorail_issue)

  def find_issues(self,
                  keywords: Optional[Union[str, List[str]]] = None,
                  only_open: Optional[bool] = False) -> Optional[List[Issue]]:
    """Find issues."""
    if not keywords:
      return None

    search_text = _get_search_text(keywords)
    if only_open:
      can = IssueTrackerManager.CAN_OPEN
    else:
      can = IssueTrackerManager.CAN_ALL

    issues = self._itm.get_issues(search_text, can=can)
    return [Issue(issue) for issue in issues]

  def find_issues_with_filters(
      self,
      keywords: Optional[Any] = None,
      query_filters: Optional[Any] = None,
      only_open: Optional[bool] = None) -> Optional[List[Issue]]:
    """Find issues given additional filters."""
    # Monorail treats keywords and query filters the same for queries.
    return self.find_issues(
        cast(Any, keywords) + cast(Any, query_filters), only_open)

  def find_issues_url(self,
                      keywords: Optional[Union[str, List[str]]] = None,
                      only_open: Optional[bool] = False) -> Optional[str]:
    """Find issues (web URL)."""
    if not keywords:
      return None

    search_text = _get_search_text(keywords)
    if only_open:
      can = IssueTrackerManager.CAN_OPEN
    else:
      can = IssueTrackerManager.CAN_ALL

    can_id = IssueTrackerManager.CAN_VALUE_TO_ID_MAP.get(can, '')
    return ISSUE_TRACKER_SEARCH_URL.format(
        project=self.project,
        params=urllib.parse.urlencode({
            'can_id': can_id,
            'q': search_text,
        }))

  def find_issues_url_with_filters(
      self,
      keywords: Optional[Any] = None,
      query_filters: Optional[Any] = None,
      only_open: Optional[bool] = None) -> Optional[str]:
    # Monorail treats keywords and query filters the same for queries.
    return self.find_issues_url(
        cast(Any, keywords) + cast(Any, query_filters), only_open)

  def issue_url(self, issue_id: Union[int, str]) -> str:
    """Return the issue URL with the given ID."""
    return ISSUE_TRACKER_URL.format(project=self.project, id=issue_id)


def _to_change_list(monorail_list: Optional[Iterable[str]]) -> ChangeList:
  """Convert a list of changed items to a issue_tracker.ChangeList."""
  change_list = ChangeList()
  if not monorail_list:
    return change_list

  for item in monorail_list:
    if item.startswith('-'):
      change_list.removed.append(item[1:])
    else:
      change_list.added.append(item)

  return change_list


def _get_issue_tracker_manager_for_project(
    project_name: Optional[str]) -> Optional[IssueTrackerManager]:
  """Return monorail issue tracker manager for the given project."""
  # If there is no issue tracker set, bail out.
  if not project_name or project_name == 'disabled':
    return None

  return IssueTrackerManager(project_name=project_name)


def _get_search_text(keywords: Any) -> str:
  """Get search text."""
  search_text = ' '.join(['"{}"'.format(keyword) for keyword in keywords])
  search_text = search_text.replace(':', ' ')
  search_text = search_text.replace('=', ' ')

  return search_text


def get_issue_tracker(project_name: Optional[str],
                      config: Any) -> Optional[IssueTracker]:  # pylint: disable=unused-argument
  """Get the issue tracker for the project name."""
  # TODO(ochang): Make this lazy.
  itm = _get_issue_tracker_manager_for_project(project_name)
  if itm is None:
    return None

  return IssueTracker(itm)

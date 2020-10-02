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

import urllib.parse

from libs.issue_management import issue_tracker
from libs.issue_management.monorail.issue import ChangeList
from libs.issue_management.monorail.issue import Issue as MonorailIssue
from libs.issue_management.monorail.issue_tracker_manager import (
    IssueTrackerManager)

ISSUE_TRACKER_URL = (
    'https://bugs.chromium.org/p/{project}/issues/detail?id={id}')
ISSUE_TRACKER_SEARCH_URL = (
    'https://bugs.chromium.org/p/{project}/issues/list?{params}')


class Issue(issue_tracker.Issue):
  """Represents an issue."""

  def __init__(self, monorail_issue):
    self._monorail_issue = monorail_issue

    # These mirror the underlying MonorailIssue data structures, to make it more
    # opaque to the client about how issue updates are done. For instance, when
    # a `label` is removed, what actually happens is `-label` is added. This
    # should not be visible to the client.
    self._ccs = issue_tracker.LabelStore(self._monorail_issue.cc)
    self._components = issue_tracker.LabelStore(self._monorail_issue.components)
    self._labels = issue_tracker.LabelStore(self._monorail_issue.labels)

  @property
  def issue_tracker(self):
    """The IssueTracker for this issue."""
    return IssueTracker(self._monorail_issue.itm)

  @property
  def id(self):
    """The issue identifier."""
    return self._monorail_issue.id

  @property
  def title(self):
    """The issue title."""
    return self._monorail_issue.summary

  @title.setter
  def title(self, new_title):
    self._monorail_issue.summary = new_title

  @property
  def reporter(self):
    """The issue reporter."""
    return self._monorail_issue.reporter

  @reporter.setter
  def reporter(self, new_reporter):
    self._monorail_issue.reporter = new_reporter

  @property
  def merged_into(self):
    """The issue that this is merged into."""
    if self._monorail_issue.merged_into_project != self.issue_tracker.project:
      # Don't consider duplicates in a different issue project.
      return None

    return self._monorail_issue.merged_into

  @property
  def is_open(self):
    """Whether the issue is open."""
    return self._monorail_issue.open

  @property
  def closed_time(self):
    return self._monorail_issue.closed

  @property
  def status(self):
    """The issue status."""
    return self._monorail_issue.status

  @status.setter
  def status(self, new_status):
    self._monorail_issue.status = new_status

  @property
  def body(self):
    """The issue body."""
    return self._monorail_issue.body

  @body.setter
  def body(self, new_body):
    self._monorail_issue.body = new_body

  @property
  def assignee(self):
    """The issue assignee."""
    return self._monorail_issue.owner

  @assignee.setter
  def assignee(self, new_assignee):
    self._monorail_issue.owner = new_assignee

  @property
  def ccs(self):
    """The issue CC list."""
    return self._ccs

  @property
  def labels(self):
    """The issue labels list."""
    return self._labels

  @property
  def components(self):
    """The issue component list."""
    return self._components

  @property
  def actions(self):
    """Get the issue actions."""
    return (Action(comment) for comment in self._monorail_issue.get_comments())

  def save(self, new_comment=None, notify=True):
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

  def __init__(self, monorail_comment):
    self._monorail_comment = monorail_comment

  @property
  def author(self):
    """The author of the action."""
    return self._monorail_comment.author

  @property
  def comment(self):
    """Represents a comment."""
    return self._monorail_comment.comment

  @property
  def title(self):
    """The new issue title."""
    return self._monorail_comment.summary

  @property
  def status(self):
    """The new issue status."""
    return self._monorail_comment.status

  @property
  def assignee(self):
    """The new issue assignee."""
    return self._monorail_comment.owner

  @property
  def ccs(self):
    """The issue CC change list."""
    return _to_change_list(self._monorail_comment.cc)

  @property
  def labels(self):
    """The issue labels change list."""
    return _to_change_list(self._monorail_comment.labels)

  @property
  def components(self):
    """The issue component change list."""
    return _to_change_list(self._monorail_comment.components)


class IssueTracker(issue_tracker.IssueTracker):
  """Issue tracker interface."""

  def __init__(self, itm):
    self._itm = itm

  @property
  def project(self):
    return self._itm.project_name

  def new_issue(self):
    monorail_issue = MonorailIssue()
    monorail_issue.itm = self._itm
    return Issue(monorail_issue)

  def get_issue(self, issue_id):
    monorail_issue = self._itm.get_issue(int(issue_id))
    if not monorail_issue:
      return None

    return Issue(monorail_issue)

  def find_issues(self, keywords=None, only_open=False):
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

  def find_issues_url(self, keywords=None, only_open=False):
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

  def issue_url(self, issue_id):
    """Return the issue URL with the given ID."""
    return ISSUE_TRACKER_URL.format(project=self.project, id=issue_id)


def _to_change_list(monorail_list):
  """Convert a list of changed items to a issue_tracker.ChangeList."""
  change_list = issue_tracker.ChangeList()
  if not monorail_list:
    return change_list

  for item in monorail_list:
    if item.startswith('-'):
      change_list.removed.append(item[1:])
    else:
      change_list.added.append(item)

  return change_list


def _get_issue_tracker_manager_for_project(project_name):
  """Return monorail issue tracker manager for the given project."""
  # If there is no issue tracker set, bail out.
  if not project_name or project_name == 'disabled':
    return None

  return IssueTrackerManager(project_name=project_name)


def _get_search_text(keywords):
  """Get search text."""
  search_text = ' '.join(['"{}"'.format(keyword) for keyword in keywords])
  search_text = search_text.replace(':', ' ')
  search_text = search_text.replace('=', ' ')

  return search_text


def get_issue_tracker(project_name, config):  # pylint: disable=unused-argument
  """Get the issue tracker for the project name."""
  # TODO(ochang): Make this lazy.
  itm = _get_issue_tracker_manager_for_project(project_name)
  if itm is None:
    return None

  return IssueTracker(itm)

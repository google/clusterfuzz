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

from future import standard_library
standard_library.install_aliases()
from builtins import object

# TODO(ochang): Move all monorail specific files into this directory.
from issue_management import issue_tracker
from issue_management.issue import Issue as MonorailIssue


class Issue(issue_tracker.Issue):
  """Represents an issue."""

  def __init__(self, monorail_issue):
    self._monorail_issue = monorail_issue

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
    return self._monorail_issue.merged_into

  @merged_into.setter
  def merged_into(self, new_merged_into):
    self._monorail_issue.merged_into = new_merged_into

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
    return self._monorail_issue.cc

  @property
  def labels(self):
    """The issue labels list."""
    return self._monorail_issue.labels

  @property
  def components(self):
    """The issue component list."""
    return self._monorail_issue.components

  @property
  def actions(self):
    """Get the issue comments."""
    return (Action(comment) for comment in self._monorail_issue.get_comments())

  def save(self, notify=True):
    """Save the issue."""
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

  def new_issue(self):
    monorail_issue = MonorailIssue()
    monorail_issue.itm = self._itm
    return Issue(monorail_issue)

  def get_issue(self, issue_id):
    monorail_issue = self._itm.get_issue(issue_id)
    if not monorail_issue:
      return None

    return Issue(monorail_issue)


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

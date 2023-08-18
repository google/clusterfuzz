# Copyright 2020 Google LLC
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
"""Jira issue tracker."""

import datetime
from urllib.parse import urljoin

from dateutil import parser

from clusterfuzz._internal.config import db_config
from libs.issue_management import issue_tracker
from libs.issue_management.jira.issue_tracker_manager import IssueTrackerManager


class Issue(issue_tracker.Issue):
  """Represents an issue."""

  def __init__(self, itm, jira_issue):
    self.itm = itm
    self.jira_issue = jira_issue

    self._ccs = issue_tracker.LabelStore(self.itm.get_watchers(self.jira_issue))
    self._components = issue_tracker.LabelStore(
        self.jira_issue.fields.components)
    self._labels = issue_tracker.LabelStore(self.jira_issue.fields.labels)

  @property
  def issue_tracker(self):
    """The IssueTracker for this issue."""
    return IssueTracker(self.itm)

  @property
  def id(self):
    """The issue identifier."""
    return int(self.jira_issue.id)

  @property
  def key(self):
    """The issue key (e.g. FUZZ-123)."""
    return self.jira_issue.key

  @property
  def title(self):
    """The issue title."""
    return self.jira_issue.fields.summary

  @title.setter
  def title(self, new_title):
    self.jira_issue.fields.summary = new_title

  @property
  def reporter(self):
    """The issue reporter."""
    return self.jira_issue.fields.reporter

  @reporter.setter
  def reporter(self, new_reporter):
    self.jira_issue.fields.reporter = new_reporter

  @property
  def is_open(self):
    """Whether the issue is open."""
    return self.jira_issue.fields.resolution is None

  @property
  def closed_time(self):
    return datetime.datetime.fromtimestamp(
        parser.parse(self.jira_issue.fields.resolutiondate).timestamp())

  @property
  def status(self):
    """The issue status."""
    return self.jira_issue.fields.status

  @status.setter
  def status(self, new_status):
    self.jira_issue.fields.status = new_status

  @property
  def body(self):
    """The issue body."""
    return self.jira_issue.fields.description

  @body.setter
  def body(self, new_body):
    self.jira_issue.fields.description = new_body

  @property
  def assignee(self):
    """The issue assignee."""
    return self.jira_issue.fields.assignee

  @assignee.setter
  def assignee(self, new_assignee):
    self.jira_issue.fields.assignee = new_assignee

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

  # FIXME: Add support for notify arguments
  def save(self, new_comment=None, notify=True):  # pylint: disable=unused-argument
    """Save the issue."""
    # add new comment to issue
    if new_comment:
      self.itm.client.add_comment(self.jira_issue, new_comment)

    for added in self._components.added:
      self.components.add(added)
    for removed in self._components.removed:
      self.components.remove(removed)
    self._components.reset_tracking()

    for added in self._ccs.added:
      self.ccs.add(added)
    for removed in self._ccs.removed:
      self.ccs.remove(removed)
    self._ccs.reset_tracking()

    for added in self._labels.added:
      self.labels.add(added)
    for removed in self._labels.removed:
      self.labels.remove(removed)
    self._labels.reset_tracking()

    self.itm.save(self)

  @property
  def actions(self):
    return ()

  @property
  def merged_into(self):
    pass


class IssueTracker(issue_tracker.IssueTracker):
  """Issue tracker interface."""

  def __init__(self, itm):
    self._itm = itm

  @property
  def project(self):
    return self._itm.project_name

  def new_issue(self):
    jira_issue = self._itm.create()
    return Issue(self._itm, jira_issue)

  def get_issue(self, issue_id):
    jira_issue = self._itm.get_issue(issue_id)
    if not jira_issue:
      return None

    return Issue(self._itm, jira_issue)

  def find_issues(self, keywords=None, only_open=False):
    """Find issues."""
    search_text = 'project = {project_name}' + _get_search_text(keywords)
    search_text = search_text.format(project_name=self._itm.project_name)
    if only_open:
      search_text += ' AND resolution = Unresolved'
    issues = self._itm.get_issues(search_text)
    return [Issue(self._itm, issue) for issue in issues]

  def issue_url(self, issue_id):
    """Return the issue URL with the given ID."""
    issue = self.get_issue(issue_id)
    if not issue:
      return None

    config = db_config.get()
    url = urljoin(config.jira_url, f'/browse/{str(issue.key)}')
    return url

  def find_issues_url(self, keywords=None, only_open=None):
    search_text = 'project = {project_name}' + _get_search_text(keywords)
    search_text = search_text.format(project_name=self._itm.project_name)
    if only_open:
      search_text += ' AND resolution = Unresolved'
    config = db_config.get()
    return urljoin(config.jira_url, f'/issues/?jql={search_text}')


def _get_issue_tracker_manager_for_project(project_name):
  """Return jira issue tracker manager for the given project."""
  # If there is no issue tracker set, bail out.
  if not project_name or project_name == 'disabled':
    return None

  return IssueTrackerManager(project_name=project_name)


def get_issue_tracker(project_name, config):  # pylint: disable=unused-argument
  """Get the issue tracker for the project name."""
  itm = _get_issue_tracker_manager_for_project(project_name)
  if itm is None:
    return None

  return IssueTracker(itm)


def _get_search_text(keywords):
  """Get search text."""
  jira_special_characters = '+-&|!(){}[]^~*?\\:'
  search_text = ''
  for keyword in keywords:
    # Replace special characters with whitespace as they are not allowed and
    # can't be searched for.
    stripped_keyword = keyword
    for special_character in jira_special_characters:
      stripped_keyword = stripped_keyword.replace(special_character, ' ')
    # coalesce multiple spaces into one.
    stripped_keyword = ' '.join(stripped_keyword.split())
    search_text += f' AND text ~ "{stripped_keyword}"'

  return search_text

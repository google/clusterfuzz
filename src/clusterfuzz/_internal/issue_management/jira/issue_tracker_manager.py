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
"""Issue tracker manager functions."""

import json

import jira

from clusterfuzz._internal.config import db_config


class IssueTrackerManager(object):
  """Issue tracker manager."""

  def __init__(self, project_name):
    """"Construct an issue tracker manager instance based on parameters."""
    self._client = None
    self.project_name = project_name

  @property
  def client(self):
    """HTTP Client."""
    if self._client is None:
      self._client = self._create_client()

    return self._client

  def _create_client(self):
    """Return a client object for querying the issue tracker."""
    config = db_config.get()
    credentials = json.loads(config.jira_credentials)
    jira_url = config.jira_url
    jira_client = jira.JIRA(
        jira_url, auth=(credentials['username'], credentials['password']))
    return jira_client

  def save(self, issue):
    """Save an issue."""
    if issue.id == -1:
      return self._create(issue)
    return self._update(issue)

  def create(self):
    """Create an issue object locally."""
    raw_fields = {'id': '-1', 'fields': {'components': [], 'labels': []}}
    # Create jira issue object
    jira_issue = jira.resources.Issue({},
                                      jira.resilientsession.ResilientSession(),
                                      raw_fields)
    return jira_issue

  def _transition_issue_status_if_updated(self, issue):
    """Transitions the status of the issue if updated. Jira has a separate
    endpoint to transition status."""
    # Brittle - we should be pulling the equivalent of 'new' from the policy.
    if issue.status == 'Open':
      return
    # This assumes the following:
    # 1. If issue.status is an instance of Resource, the value comes from
    #    Jira directly and has not been changed.
    # 2. If issue.status is not an instance of Resource, the value is a
    #    string and the issue status should be updated.
    # Brittle - we should be pulling the equivalent of 'new' from the policy.
    if not isinstance(issue.status, jira.resources.Resource):
      self.client.transition_issue(issue.jira_issue, transition=issue.status)

  def _add_watchers(self, issue):
    """Add watchers to the ticket. Jira has a separate endpoint to
    add watchers."""

    # Get watchers from LabelStore.
    watchers = list(issue.ccs)

    # Jira weirdness, update watchers this way.
    for watcher in watchers:
      self.client.add_watcher(issue.jira_issue, watcher)

  def _get_issue_fields(self, issue):
    """Get issue fields to populate the ticket"""
    # Get labels from LabelStore.
    labels = list(issue.labels)

    # Get components from LabelStore.
    components = list(issue.components)

    fields = {
        'summary': issue.title,
        'description': issue.body,
        'labels': labels,
        'components': components,
    }

    if issue.assignee is not None:
      if isinstance(issue.assignee, jira.resources.Resource):
        assignee = {'name': issue.assignee.name}
      else:
        assignee = {'name': issue.assignee}
      fields['assignee'] = assignee

    # Again brittle - need to pull these strings from policy.
    if 'Critical - P1' in labels:
      fields['priority'] = {'name': 'Critical - P1'}
    elif 'Major - P2' in labels:
      fields['priority'] = {'name': 'Major - P2'}
    return fields

  def _create(self, issue):
    """Create an issue."""

    fields = self._get_issue_fields(issue)
    jira_issue = self.client.create_issue(fields=fields)
    self._add_watchers(jira_issue)
    issue.jira_issue = jira_issue

  def _update(self, issue):
    """Update an issue."""

    update_fields = self._get_issue_fields(issue)
    self._transition_issue_status_if_updated(issue)
    self._add_watchers(issue)
    issue.jira_issue.update(fields=update_fields)

  def get_watchers(self, issue):
    """Retrieve list of watchers."""
    if issue.id == -1:
      return []
    watchlist = self.client.watchers(issue)
    watchers = []
    for watcher in watchlist.watchers:
      watchers.append(watcher.name)
    return watchers

  def get_issue(self, issue_id):
    """Retrieve an issue object with a specific id."""
    issue = self.client.issue(str(issue_id))
    return issue

  def get_issue_count(self, query_string):
    """Return number of issues for a given query."""
    issues = self.client.search_issues(query_string)
    return len(issues)

  def get_issues(self, query_string, max_results=10000):
    """Return all issues for a given query."""
    issues = self.client.search_issues(query_string, maxResults=max_results)
    return issues

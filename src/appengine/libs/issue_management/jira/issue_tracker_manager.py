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
    self._update(issue)

  def create(self):
    """Create an issue."""
    default_fields = {
        'project': self.project_name,
        'summary': 'Default summary',
        'description': 'Default description',
        'issuetype': {
            'name': 'Bug'
        }
    }

    jira_issue = self.client.create_issue(fields=default_fields)
    return jira_issue

  def _update(self, issue):
    """Update an issue."""

    # Get labels from LabelStore.
    labels = list(issue.labels)

    # Get components from LabelStore.
    components = list(issue.components)

    # Get watchers from LabelStore.
    watchers = list(issue.ccs)

    update_fields = {
        'summary': issue.title,
        'description': issue.body,
        'labels': labels,
        'components': components,
    }

    # Only add status if it has changed.
    # Brittle - we should be pulling the equivalent of 'new' from the policy.
    if issue.status != 'Open':
      status = {'name': issue.status}
      update_fields['status'] = status

    if issue.assignee is not None:
      assignee = {'name': issue.assignee}
      update_fields['assignee'] = assignee

    # Again brittle - need to pull these strings from policy.
    if 'Critical - P1' in labels:
      update_fields['priority'] = {'name': 'Critical - P1'}
    elif 'Major - P2' in labels:
      update_fields['priority'] = {'name': 'Major - P2'}

    # Jira weirdness, update watchers this way.
    for watcher in watchers:
      self.client.add_watcher(issue.jira_issue, watcher)

    issue.jira_issue.update(fields=update_fields)

  def get_watchers(self, issue):
    """Retrieve list of watchers."""
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

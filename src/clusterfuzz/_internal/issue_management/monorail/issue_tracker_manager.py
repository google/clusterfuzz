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
"""Issue tracker manager functions."""

import datetime

from googleapiclient import discovery

from clusterfuzz._internal.base import retry

from . import credential_storage
from .comment import Comment
from .issue import ChangeList
from .issue import Issue

# Default value for issue tracker connection failures.
FAIL_RETRIES = 7
FAIL_WAIT = 1


def convert_entry_to_comment(entry):
  """Convert an issue entry object into a comment object."""
  comment = Comment()
  comment.author = entry['author']['name'] if 'author' in entry else None
  comment.comment = entry['content']
  comment.created = parse_datetime(entry['published'])
  comment.id = entry['id']

  if 'updates' in entry and entry['updates']:
    comment.cc = ChangeList(entry['updates'].get('cc', []))
    comment.components = ChangeList(entry['updates'].get('components', []))
    comment.labels = ChangeList(entry['updates'].get('labels', []))
    comment.owner = entry['updates'].get('owner', None)
    comment.status = entry['updates'].get('status', None)
    comment.summary = entry['updates'].get('summary', None)

  return comment


def convert_entry_to_issue(entry, itm, old_issue=None):
  """Convert an issue entry object into a issue object."""
  if old_issue:
    issue = old_issue
  else:
    issue = Issue()

  issue.blocked_on = [e['issueId'] for e in entry.get('blockedOn', [])]
  issue.blocking = [e['issueId'] for e in entry.get('blocking', [])]
  issue.cc = ChangeList([e['name'] for e in entry.get('cc', [])])
  issue.comments = None
  issue.components = ChangeList(entry.get('components', []))
  issue.created = parse_datetime(entry['published'])
  issue.id = entry['id']
  issue.itm = itm
  issue.labels = ChangeList(entry.get('labels', []))
  issue.new = False
  issue.open = entry['state'] == 'open'
  issue.reporter = entry['author']['name'] if 'author' in entry else None
  issue.stars = entry['stars']
  issue.summary = entry['summary']
  issue.updated = parse_datetime(entry['updated'])

  if entry.get('closed', []):
    issue.closed = parse_datetime(entry.get('closed', []))
  if entry.get('mergedInto'):
    issue.merged_into = entry['mergedInto'].get('issueId')
    issue.merged_into_project = entry['mergedInto'].get('projectId')
  if entry.get('owner', []):
    issue.owner = entry['owner']['name']
  if entry.get('status', []):
    issue.status = entry['status']

  # The issue will be flagged as dirty when most of the above fields are set,
  # so this must be set last.
  issue.dirty = False

  return issue


def parse_datetime(date_string):
  """Parse a date time string into a datetime object."""
  datetime_obj, _, microseconds_string = date_string.partition('.')
  datetime_obj = datetime.datetime.strptime(datetime_obj, '%Y-%m-%dT%H:%M:%S')
  if microseconds_string:
    microseconds = int(microseconds_string.rstrip('Z'), 10)
    return datetime_obj + datetime.timedelta(microseconds=microseconds)

  return datetime_obj


class IssueTrackerManager(object):
  """Issue tracker manager."""

  CAN_ALL = 'all'
  CAN_OPEN = 'open'
  CAN_MY_OPEN_BUGS = 'owned'
  CAN_REPORTED_BY_ME = 'reported'
  CAN_STARRED_BY_ME = 'starred'
  CAN_NEW = 'new'
  CAN_VERIFY = 'to-verify'

  CAN_VALUE_TO_ID_MAP = {
      CAN_ALL: 1,
      CAN_OPEN: 2,
      CAN_MY_OPEN_BUGS: 3,
      CAN_REPORTED_BY_ME: 4,
      CAN_STARRED_BY_ME: 5,
      CAN_NEW: 6
  }

  API_DISCOVERY_URL = ('https://monorail-prod.appspot.com/_ah/api/discovery/'
                       'v1/apis/{api}/{apiVersion}/rest')
  API_NAME = 'monorail'
  API_VERSION = 'v1'

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

  @retry.wrap(
      retries=FAIL_RETRIES,
      delay=FAIL_WAIT,
      function='libs.issue_management.issue_tracker_manager._execute_with_retry'
  )
  def _execute_with_retry(self, query):
    """Execute a query (with retries)."""
    return query.execute()

  @retry.wrap(
      retries=FAIL_RETRIES,
      delay=FAIL_WAIT,
      function='libs.issue_management.issue_tracker_manager._create_client')
  def _create_client(self):
    """Return a client object for querying the issue tracker.

    Includes retry logic to handle occasional 503 backend errors.
    """
    # Pull credentials old-style, using native client id and json.
    credentials = credential_storage.CredentialStorage().get()

    return discovery.build(
        self.API_NAME,
        self.API_VERSION,
        credentials=credentials,
        discoveryServiceUrl=self.API_DISCOVERY_URL,
        cache_discovery=False)

  def save(self, issue, send_email=None):
    """Save an issue and optionally send update notification over email."""
    if send_email is None:
      send_email = issue.send_email

    if issue.new:
      self._create(issue)
    else:
      self._update(issue, send_email)

  def _create(self, issue, send_email=True):
    """Create an issue and optionally send update notification over email."""
    cc = [{'name': user} for user in issue.cc]
    body = {
        'cc': cc,
        'components': issue.components,
        'description': issue.body,
        'labels': issue.labels,
        'projectId': self.project_name,
        'status': issue.status,
        'summary': issue.summary,
    }
    if issue.owner:
      body['owner'] = {'name': issue.owner}

    tmp = self._execute_with_retry(self.client.issues().insert(
        projectId=self.project_name, sendEmail=send_email, body=body))
    issue.id = int(tmp['id'])
    issue.dirty = False
    issue.new = False
    return issue

  def _update(self, issue, send_email=True):
    """Update an issue and optionally send update notification over email."""
    if not issue.dirty:
      return issue
    if not issue.owner:
      issue.owner = ''

    updates = {}
    if 'summary' in issue.changed:
      updates['summary'] = issue.summary
    if 'status' in issue.changed:
      updates['status'] = issue.status
    if 'owner' in issue.changed:
      updates['owner'] = issue.owner
    if issue.labels.is_changed():
      updates['labels'] = list(issue.labels.added)
    if issue.components.is_changed():
      updates['components'] = list(issue.components.added)
    if issue.cc.is_changed():
      updates['cc'] = list(issue.cc.added)

    body = {'id': issue.id, 'updates': updates}
    if 'comment' in issue.changed:
      body['content'] = issue.comment

    self._execute_with_retry(self.client.issues().comments().insert(
        projectId=self.project_name,
        issueId=issue.id,
        sendEmail=send_email,
        body=body))

    # Clear the issue comment once it's been saved (shouldn't be re-used).
    issue.comment = ''
    issue.dirty = False
    return issue

  def add_comment(self, issue_id, comment, send_email=True):
    """Add comment to an issue and potentially send an email update."""
    issue = self.get_issue(issue_id)
    issue.comment = comment
    self.save(issue, send_email)

  def get_comment_count(self, issue_id):
    """Get number of comments for an issue."""
    feed = self._execute_with_retry(self.client.issues().comments().list(
        projectId=self.project_name,
        issueId=issue_id,
        startIndex=1,
        maxResults=0))
    return feed.get('totalResults', '0')

  def get_comments(self, issue_id):
    """Get all comments for an issue."""
    comments = []
    comments_feed = self._execute_with_retry(
        self.client.issues().comments().list(
            projectId=self.project_name, issueId=issue_id))
    comments.extend(
        [convert_entry_to_comment(entry) for entry in comments_feed['items']])
    total_results = comments_feed['totalResults']
    if total_results:
      total_results = comments_feed['totalResults']
    else:
      return comments

    while len(comments) < total_results:
      comments_feed = self._execute_with_retry(
          self.client.issues().comments().list(
              projectId=self.project_name,
              issueId=issue_id,
              startIndex=len(comments)))
      comments.extend(
          [convert_entry_to_comment(entry) for entry in comments_feed['items']])

    return comments

  def get_first_comment(self, issue_id):
    """Get first comment for an issue."""
    feed = self._execute_with_retry(self.client.issues().comments().list(
        projectId=self.project_name,
        issueId=issue_id,
        startIndex=0,
        maxResults=1))
    if 'items' in feed:
      return convert_entry_to_comment(feed['items'][0])

    return None

  def get_last_comment(self, issue_id):
    """Get last comment for an issue."""
    total_results = self.get_comment_count(issue_id)
    feed = self._execute_with_retry(self.client.issues().comments().list(
        projectId=self.project_name,
        issueId=issue_id,
        startIndex=total_results - 1,
        maxResults=1))
    if 'items' in feed:
      return convert_entry_to_comment(feed['items'][0])

    return None

  def get_issue(self, issue_id):
    """Retrieve an issue object with a specific id."""
    entry = self._execute_with_retry(self.client.issues().get(
        projectId=self.project_name, issueId=issue_id))
    return convert_entry_to_issue(entry, self)

  def refresh(self, issue):
    """Refresh an issue object with latest updates."""
    if issue and not issue.new:
      entry = self._execute_with_retry(self.client.issues().get(
          projectId=self.project_name, issueId=issue.id))
      return convert_entry_to_issue(entry, self, old_issue=issue)

    return issue

  def get_all_issues(self):
    """Get all issues for the project."""
    feed = self._execute_with_retry(
        self.client.issues().list(projectId=self.project_name))
    return [convert_entry_to_issue(entry, self) for entry in feed['items']]

  def get_issue_count(self, query_string, can=CAN_ALL):
    """Return number of issues for a given query."""
    feed = self._execute_with_retry(self.client.issues().list(
        can=can,
        projectId=self.project_name,
        q=query_string,
        startIndex=0,
        maxResults=0))
    total_results = feed.get('totalResults', '')
    if total_results:
      return int(total_results)

    return 0

  def get_issues(self, query_string, can=CAN_ALL, max_results=1000):
    """Return all issues for a given query."""
    block_count = 0
    count = 0
    issues = []
    while True:
      result, total = self.get_issues_from_index(
          query_string, can, max_results=max_results, start_index=count)
      count += len(result)

      # Hack, since issue tracker is omitting results randomly.
      block_count += max_results
      issues += result
      if block_count > total:
        break

    return issues

  def get_issues_from_index(self,
                            query_string,
                            can=CAN_ALL,
                            max_results=1000,
                            start_index=0):
    """Retrieve a set of issues for a query from a given start index."""
    feed = self._execute_with_retry(self.client.issues().list(
        projectId=self.project_name,
        q=query_string,
        startIndex=start_index,
        maxResults=max_results,
        can=can))

    if 'items' in feed and feed['items']:
      issues = [convert_entry_to_issue(entry, self) for entry in feed['items']]
      return issues, feed['totalResults']

    return [], 0

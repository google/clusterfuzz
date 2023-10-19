# Copyright 2023 Google LLC
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

# pylint: disable=protected-access
"""Google issue tracker implementation."""

import datetime
import enum
import urllib.parse

from google.auth import exceptions

from clusterfuzz._internal.issue_management import issue_tracker
from clusterfuzz._internal.issue_management.google_issue_tracker import client
from clusterfuzz._internal.metrics import logs

_NUM_RETRIES = 3
_ISSUE_TRACKER_URL = 'https://issuetracker.googleapis.com/v1/issues'


class IssueAccessLevel(enum.Enum):
  LIMIT_NONE = 0
  LIMIT_VIEW = 1
  LIMIT_APPEND = 2
  LIMIT_VIEW_TRUSTED = 3


class IssueTrackerError(Exception):
  """Base issue tracker error."""


class IssueTrackerNotFoundError(IssueTrackerError):
  """Not found error."""


class IssueTrackerPermissionError(IssueTrackerError):
  """Permission error."""


class _SingleComponentStore(issue_tracker.LabelStore):
  """LabelStore that only accepts 1 item."""

  def get_single(self):
    """Get the single component, or None."""
    return next(iter(self), None)

  def add(self, label):
    """Add a component, overwriting the last component added if any."""
    self.clear()
    super(_SingleComponentStore, self).add(label)


def _extract_label(labels, prefix):
  """Extract a label value."""
  for label in labels:
    if not label.startswith(prefix):
      continue
    result = label[len(prefix):]
    labels.remove(label)
    return result
  return None


class Issue(issue_tracker.Issue):
  """Issue tracker issue."""

  def __init__(self, data, is_new, tracker):
    self._data = data
    self._is_new = is_new
    self._issue_tracker = tracker
    ccs = data['issueState'].get('ccs', [])
    self._ccs = issue_tracker.LabelStore(
        [user['emailAddress'] for user in ccs if 'emailAddress' in user])
    collaborators = data['issueState'].get('collaborators', [])
    self._collaborators = issue_tracker.LabelStore([
        user['emailAddress'] for user in collaborators if 'emailAddress' in user
    ])
    labels = [
        str(hotlist_id)
        for hotlist_id in data['issueState'].get('hotlistIds', [])
    ]
    self._labels = issue_tracker.LabelStore(labels)
    components = [str(data['issueState']['componentId'])]
    self._components = _SingleComponentStore(components)
    self._body = None
    self._changed = set()
    self._access_limit = {'access_level': IssueAccessLevel.LIMIT_NONE}

  def _reset_tracking(self):
    """Resets diff tracking."""
    self._changed.clear()
    self._ccs.reset_tracking()
    self._collaborators.reset_tracking()
    self._labels.reset_tracking()
    self._components.reset_tracking()

  @property
  def issue_tracker(self):
    """The issue tracker for this issue."""
    return self._issue_tracker

  @property
  def id(self):
    """The issue identifier."""
    return int(self._data['issueId'])

  @property
  def title(self):
    """The issue title."""
    return self._data['issueState'].get('title')

  @title.setter
  def title(self, new_title):
    self._changed.add('title')
    self._data['issueState']['title'] = new_title

  @property
  def reporter(self):
    """The issue reporter."""
    reporter = self._data['issueState'].get('reporter')
    if not reporter:
      return None
    return reporter['emailAddress']

  @reporter.setter
  def reporter(self, new_reporter):
    self._changed.add('reporter')
    self._data['issueState']['reporter'] = _make_user(new_reporter)

  @property
  def merged_into(self):
    """The issue that this is merged into."""
    return self._data['issueState'].get('canonicalIssueId')

  @property
  def closed_time(self):
    """When the issue was closed."""
    resolved_time = self._data.get('resolvedTime')
    if not resolved_time:
      return None
    return _parse_datetime(resolved_time)

  @property
  def is_open(self):
    """Whether the issue is open."""
    return self.status in ['NEW', 'ASSIGNED', 'ACCEPTED']

  @property
  def status(self):
    """The issue status."""
    return self._data['issueState']['status']

  @status.setter
  def status(self, new_status):
    self._changed.add('status')
    self._data['issueState']['status'] = new_status

  @property
  def body(self):
    """The issue body."""
    if self._body is not None:
      return self._body
    if not self._is_new:
      self._body = ''
      result = self.issue_tracker._execute(self.issue_tracker.client.issues()
                                           .issueUpdates().list(
                                               issueId=str(self.id),
                                               pageSize=1,
                                               sortBy='ASC'))
      if 'issueUpdates' not in result:
        return self._body
      if len(result['issueUpdates']) < 1:
        return self._body
      issue_update = result['issueUpdates'][0]
      if issue_update['commentNumber'] != 1:
        return self._body
      self._body = result['issueUpdates'][0]['issueComment']['comment']
    return self._body

  @body.setter
  def body(self, new_body):
    self._body = new_body

  @property
  def assignee(self):
    """The issue assignee."""
    assignee = self._data['issueState'].get('assignee')
    if not assignee:
      return None
    return assignee['emailAddress']

  @assignee.setter
  def assignee(self, new_assignee):
    self._changed.add('assignee')
    self._data['issueState']['assignee'] = _make_user(new_assignee)

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
    """Gets the issue actions."""
    page_token = None
    while True:
      result = self.issue_tracker._execute(self.issue_tracker.client.issues()
                                           .issueUpdates().list(
                                               issueId=str(self.id),
                                               pageToken=page_token,
                                               sortBy='ASC'))
      for issue_update in result['issueUpdates']:
        yield Action(issue_update)
      page_token = result.get('nextPageToken')
      if not page_token:
        break

  @property
  def _verifier(self):
    """The issue verifier."""
    verifier = self._data['issueState'].get('verifier')
    if not verifier:
      return None
    return verifier['emailAddress']

  @_verifier.setter
  def _verifier(self, new_verifier):
    self._changed.add('_verifier')
    self._data['issueState']['verifier'] = _make_user(new_verifier)

  def _add_update_single(self,
                         update_body,
                         added,
                         removed,
                         field_name,
                         api_field_name,
                         modifier=None):
    """Prepares a single field update."""
    if field_name not in self._changed:
      return
    new_value = getattr(self, field_name)
    if new_value:
      if modifier:
        new_value = modifier(new_value)
      added.append(api_field_name)
      update_body['add'][api_field_name] = new_value
    else:
      removed.append(api_field_name)

  def _add_update_collection(self,
                             update_body,
                             added,
                             removed,
                             field_name,
                             api_field_name,
                             modifier=None):
    """Prepares a collection field update."""
    collection = getattr(self, field_name)
    collection_added = list(collection.added)
    if collection_added:
      added.append(api_field_name)
      if modifier:
        collection_added = modifier(collection_added)
      update_body['add'][api_field_name] = collection_added
    collection_removed = list(collection.removed)
    if collection_removed:
      removed.append(api_field_name)
      if modifier:
        collection_removed = modifier(collection_removed)
      update_body['remove'][api_field_name] = collection_removed

  def _update_issue(self, new_comment=None, notify=True):
    """Updates an existing issue."""
    update_body = {
        'add': {},
        'addMask': '',
        'remove': {},
        'removeMask': '',
    }
    if 'status' in self._changed and self.status == 'VERIFIED':
      # Always set verifier, as the caller is doing the verification.
      self._verifier = client.user()
      # VERIFIED also requires assignee to be set, so set it in case it's not
      # set.
      if not self.assignee:
        self.assignee = client.user()
    # Add updates.
    added = []
    removed = []
    self._add_update_single(update_body, added, removed, 'status', 'status')
    self._add_update_single(update_body, added, removed, 'assignee', 'assignee',
                            _make_user)
    self._add_update_single(update_body, added, removed, '_verifier',
                            'verifier', _make_user)
    self._add_update_single(update_body, added, removed, 'reporter', 'reporter',
                            _make_user)
    self._add_update_single(update_body, added, removed, 'title', 'title')
    self._add_update_collection(update_body, added, removed, 'ccs', 'ccs',
                                _make_users)
    self._add_update_collection(update_body, added, removed, '_collaborators',
                                'collaborators', _make_users)
    self._add_update_single(update_body, added, removed, '_access_limit',
                            'access_limit')
    update_body['addMask'] = ','.join(added)
    update_body['removeMask'] = ','.join(removed)
    if notify:
      update_body['significanceOverride'] = 'MAJOR'
    else:
      update_body['significanceOverride'] = 'SILENT'
    if new_comment:
      update_body['issueComment'] = {
          'comment': new_comment,
      }
    result = self._data
    if added or removed or new_comment:
      result = self.issue_tracker._execute(
          self.issue_tracker.client.issues().modify(
              issueId=str(self.id), body=update_body))
    # Special case: components.
    new_component = next(iter(self.components.added), None)
    if new_component:
      self.issue_tracker._execute(self.issue_tracker.client.issues().move(
          issueId=str(self.id),
          body={
              'componentId': int(new_component),
          },
      ))
    # Special case: hotlists.
    # TODO(ochang): Investigate batching.
    added_hotlists = self.labels.added
    removed_hotlists = self.labels.removed
    for hotlist in added_hotlists:
      self.issue_tracker._execute(
          self.issue_tracker.client.hotlists().createEntries(
              hotlistId=str(hotlist),
              body={'hotlistEntry': {
                  'issueId': str(self.id),
              }},
          ))
    for hotlist in removed_hotlists:
      self.issue_tracker._execute(self.issue_tracker.client.hotlists()
                                  .entries().delete(
                                      hotlistId=str(hotlist),
                                      issueId=str(self.id)))
    return result

  def _override_priority_and_type(self):
    """Determines whether if we should override the priority and type."""
    if '1680101' in self.labels:
      # Unreproducible hotlist.
      return False
    if '5075787' in self.labels:
      # Targets marked explicitly as non-security relevant.
      return False
    # 347144: Language Platforms>Software Analysis>SunDew>Target Generation -
    # FUDGE>Target Crashes
    # 1056691: Security>ISE>TPS>Autofuzz>ClusterFuzz>Unreproducible
    if self._components.get_single() in ('347144', '1056691'):
      return False
    if '//security/laser/sundew/targetgen' in self.title:
      # Noisy targets.
      return False
    return True

  def save(self, new_comment=None, notify=True):
    """Saves the issue."""
    if self._is_new:
      priority = _extract_label(self.labels, 'Pri-')
      issue_type = _extract_label(self.labels, 'Type-') or 'BUG'
      if not self._override_priority_and_type():
        # Reset to default.
        issue_type = 'BUG'
        priority = None
      self._data['issueState']['type'] = issue_type
      if priority:
        self._data['issueState']['priority'] = priority
      component_id = self._components.get_single()
      if component_id:
        self._data['issueState']['componentId'] = int(component_id)
      ccs = list(self._ccs)
      if ccs:
        self._data['issueState']['ccs'] = _make_users(ccs)
      collaborators = list(self._collaborators)
      if collaborators:
        self._data['issueState']['collaborators'] = _make_users(collaborators)
      access_limit = self._access_limit
      if access_limit:
        self._data['issueState']['access_limit'] = access_limit
      self._data['issueState']['hotlistIds'] = [
          int(label) for label in self.labels
      ]
      if self._body is not None:
        self._data['issueComment'] = {
            'comment': self._body,
        }
      result = self.issue_tracker._execute(
          self.issue_tracker.client.issues().create(
              body=self._data, templateOptions_applyTemplate=True))
      self._is_new = False
    else:
      result = self._update_issue(new_comment=new_comment, notify=notify)
    self._reset_tracking()
    self._data = result


class Action(issue_tracker.Action):
  """Issue tracker action."""

  # FieldUpdates give us the integer value for statuses, so we need to keep this
  # mapping.
  INT_TO_STATUS = {
      1: 'NEW',
      2: 'ASSIGNED',
      3: 'ACCEPTED',
      4: 'FIXED',
      5: 'VERIFIED',
      6: 'NOT_REPRODUCIBLE',
      7: 'INTENDED_BEHAVIOR',
      8: 'OBSOLETE',
      9: 'INFEASIBLE',
      10: 'DUPLICATE',
  }

  def __init__(self, data):
    self._data = data

  def _get_actual_value(self, value):
    """Gets the actual value of a field update google.protobuf.Any value."""
    if value is None:
      return None
    if 'emailAddress' in value:
      return value['emailAddress']
    if 'value' in value:
      return value['value']
    raise IssueTrackerError('Unknown value type: ' + value['type'])

  def _get_actual_values(self, values):
    """Gets the actual values of field update values."""
    if values is None:
      return None
    return [self._get_actual_value(value) for value in values]

  def _get_field_update(self, field_name):
    """Gets the FieldUpdate for a field name."""
    if 'fieldUpdates' not in self._data:
      return None
    return next(
        (update for update in self._data['fieldUpdates']
         if update['field'] == field_name),
        None,
    )

  def _get_field_update_single(self, field_name):
    """Gets a single field update."""
    update = self._get_field_update(field_name)
    if not update:
      return None, None
    single_value_update = update.get('singleValueUpdate')
    if not single_value_update:
      return None, None
    return (
        self._get_actual_value(single_value_update.get('oldValue')),
        self._get_actual_value(single_value_update.get('newValue')),
    )

  def _get_field_update_changes(self, field_name):
    """Gets a collection field update."""
    update = self._get_field_update(field_name)
    if not update:
      return None, None
    collection_update = update.get('collectionUpdate')
    if not collection_update:
      return None, None
    return (
        self._get_actual_values(collection_update.get('removedValues')),
        self._get_actual_values(collection_update.get('addedValues')),
    )

  @property
  def author(self):
    """The author of the action."""
    return self._data['author']['emailAddress']

  @property
  def comment(self):
    """Represents a comment."""
    if 'issueComment' not in self._data:
      return None
    return self._data['issueComment']['comment']

  @property
  def title(self):
    """The new issue title."""
    return self._get_field_update_single('title')[1]

  @property
  def status(self):
    """The new issue status."""
    return self.INT_TO_STATUS.get(self._get_field_update_single('status')[1])

  @property
  def assignee(self):
    """The new issue assignee."""
    assignee = self._get_field_update_single('assignee')[1]
    if not assignee:
      return None
    return assignee

  @property
  def ccs(self):
    """The issue CC change list."""
    removed, added = self._get_field_update_changes('ccs')
    change_list = issue_tracker.ChangeList()
    if added:
      change_list.added.extend(added)
    if removed:
      change_list.removed.extend(removed)
    return change_list

  @property
  def labels(self):
    """The issue labels change list."""
    # We need to use the snake_case version of the field here, as that's the
    # string value the backend actually uses.
    removed, added = self._get_field_update_changes('hotlist_ids')
    change_list = issue_tracker.ChangeList()
    if added:
      change_list.added.extend(added)
    if removed:
      change_list.removed.extend(removed)
    return change_list

  @property
  def components(self):
    """The issue component change list."""
    # We need to use the snake_case version of the field here, as that's the
    # string value the backend actually uses.
    old_value, new_value = self._get_field_update_single('component_id')
    change_list = issue_tracker.ChangeList()
    if new_value:
      change_list.added.append(new_value)
    if old_value:
      change_list.removed.append(old_value)
    return change_list


class IssueTracker(issue_tracker.IssueTracker):
  """Google issue tracker implementation."""

  def __init__(self, project, http_client, config):
    self._project = project
    self._client = http_client
    self._default_component_id = config['default_component_id']

  @property
  def client(self):
    """HTTP Client."""
    if self._client is None:
      self._client = client.build()
    return self._client

  def _execute(self, request):
    """Executes a request."""
    http = None
    for _ in range(2):
      try:
        return request.execute(num_retries=_NUM_RETRIES, http=http)
      except exceptions.RefreshError:
        # Rebuild client and retry request.
        http = client.build_http()
        self._client = client.build('issuetracker', http=http)
        return request.execute(num_retries=_NUM_RETRIES, http=http)
      except client.HttpError as e:
        if e.resp.status == 404:
          raise IssueTrackerNotFoundError(str(e))
        if e.resp.status == 403:
          raise IssueTrackerPermissionError(str(e))
        raise IssueTrackerError(str(e))

  @property
  def project(self):
    """Gets the project name of this issue tracker."""
    return self._project

  def new_issue(self):
    """Creates an unsaved new issue."""
    data = {
        'issueState': {
            'componentId': self._default_component_id,
            'ccs': [],
            'collaborators': [],
            'hotlistIds': [],
            'access_limit': {
                'access_level': IssueAccessLevel.LIMIT_NONE
            },
        }
    }
    return Issue(data, True, self)

  def get_issue(self, issue_id):
    """Gets the issue with the given ID."""
    try:
      issue = self._execute(self.client.issues().get(issueId=str(issue_id)))
      return Issue(issue, False, self)
    except IssueTrackerError as e:
      if isinstance(e, IssueTrackerNotFoundError):
        return None
      logs.log_error('Failed to retrieve issue.', issue_id=issue_id)
      return None

  def find_issues(self, keywords=None, only_open=None):
    """Finds issues."""
    page_token = None
    while True:
      issues = self._execute(self.client.issues().list(
          query=_get_query(keywords, only_open), pageToken=page_token))
      if "issues" not in issues:
        return
      for issue in issues['issues']:
        yield Issue(issue, False, self)
      page_token = issues.get('nextPageToken')
      if not page_token:
        break

  def find_issues_url(self, keywords=None, only_open=None):
    """Finds issues (web URL)."""
    return (_ISSUE_TRACKER_URL + '?' + urllib.parse.urlencode({
        'q': _get_query(keywords, only_open),
    }))

  def issue_url(self, issue_id):
    """Returns the issue URL with the given ID."""
    return _ISSUE_TRACKER_URL + '/' + str(issue_id)

  @property
  def label_type(self):
    """Label type."""
    return 'hotlist'

  def label_text(self, label):
    """Text for a label (with label type)."""
    return 'hotlistid:' + str(label)


def _make_user(email):
  """Makes a User."""
  return {
      'emailAddress': email,
  }


def _make_users(emails):
  """Makes Users."""
  return [_make_user(email) for email in emails]


def _parse_datetime(date_string):
  """Parses a datetime."""
  datetime_obj, _, microseconds_string = date_string.rstrip('Z').partition('.')
  datetime_obj = datetime.datetime.strptime(datetime_obj, '%Y-%m-%dT%H:%M:%S')
  if microseconds_string:
    microseconds = int(microseconds_string, 10)
    return datetime_obj + datetime.timedelta(microseconds=microseconds)
  return datetime_obj


def _get_query(keywords, only_open):
  """Gets a search query."""
  query = ' '.join('"{}"'.format(keyword) for keyword in keywords)
  if only_open:
    query += ' status:open'
  return query


def get(project, config, issue_tracker_client=None):
  """Gets an IssueTracker for the project."""
  return IssueTracker(project, issue_tracker_client, config)

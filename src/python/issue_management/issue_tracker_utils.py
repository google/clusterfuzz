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
"""Utilities for managing issue tracker instance."""

from datastore import data_types
from datastore import ndb_utils
from issue_management import monorail
from issue_management.monorail.issue_tracker_manager import IssueTrackerManager

ISSUE_TRACKER_MANAGERS = {}
ISSUE_TRACKER_URL = 'https://bugs.chromium.org/p/{project}/issues/detail?id='
ISSUE_TRACKER_SEARCH_URL = (
    'https://bugs.chromium.org/p/{project}/issues/list?can={can_id}&q={query}')


def _get_issue_tracker_project_name(testcase=None):
  """Return issue tracker project name given a testcase or default."""
  from datastore import data_handler
  job_type = testcase.job_type if testcase else None
  return data_handler.get_issue_tracker_name(job_type)


def clear_issue_tracker_managers():
  """Clear issue tracker manager instances."""
  global ISSUE_TRACKER_MANAGERS
  ISSUE_TRACKER_MANAGERS = {}


def get_issue_tracker(tracker_type, project_name=None, use_cache=False):
  """Get the issue tracker with the given type and name."""
  # TODO(ochang): Actually use `tracker_type`.
  assert tracker_type == 'monorail'
  if not project_name:
    from datastore import data_handler
    project_name = data_handler.get_issue_tracker_name()

  itm = _get_issue_tracker_manager_for_project(
      project_name, use_cache=use_cache)
  if itm is None:
    return None

  return monorail.IssueTracker(itm)


def get_issue_tracker_for_testcase(testcase, use_cache=False):
  """Get the issue tracker with the given type and name."""
  issue_tracker_project_name = _get_issue_tracker_project_name(testcase)
  if not issue_tracker_project_name:
    return None

  return get_issue_tracker(
      'monorail', issue_tracker_project_name, use_cache=use_cache)


# TODO(ochang): Move this to monorail/. See comment on
# get_issue_tracker_manager.
def _get_issue_tracker_manager_for_project(project_name, use_cache=False):
  """Return monorail issue tracker manager for the given project."""
  # If there is no issue tracker set, bail out.
  if not project_name or project_name == 'disabled':
    return None

  if use_cache and project_name in ISSUE_TRACKER_MANAGERS:
    return ISSUE_TRACKER_MANAGERS[project_name]

  issue_tracker_manager = IssueTrackerManager(project_name=project_name)
  ISSUE_TRACKER_MANAGERS[project_name] = issue_tracker_manager
  return issue_tracker_manager


# TODO(ochang): Replace all existing uses with get_issue_tracker_for_testcase,
# and move to monorail/.
def get_issue_tracker_manager(testcase=None, use_cache=False):
  """Return issue tracker instance for a testcase."""
  issue_tracker_project_name = _get_issue_tracker_project_name(testcase)
  return _get_issue_tracker_manager_for_project(
      issue_tracker_project_name, use_cache=use_cache)


def get_issue_url(testcase=None):
  """Return issue url for a testcase."""
  return ISSUE_TRACKER_URL.format(
      project=_get_issue_tracker_project_name(testcase))


def get_similar_issues_query(testcase):
  """Return the similar issues query."""
  crash_state_lines = testcase.crash_state.splitlines()
  search_text = ''
  if len(crash_state_lines) == 1:
    search_text = testcase.crash_state
  elif len(crash_state_lines) >= 2:
    search_text = '"%s" "%s"' % (crash_state_lines[0], crash_state_lines[1])

  if search_text:
    search_text = search_text.replace(':', ' ')
    search_text = search_text.replace('=', ' ')

  return search_text


def get_similar_issues_url(testcase, can):
  """Return the url for similar issues."""
  project = _get_issue_tracker_project_name(testcase)
  can_id = IssueTrackerManager.CAN_VALUE_TO_ID_MAP.get(can, '')
  query = get_similar_issues_query(testcase)
  url = ISSUE_TRACKER_SEARCH_URL.format(
      project=project, can_id=can_id, query=query)

  return url


# TODO(ochang): Make this more general.
def get_similar_issues(testcase,
                       can=IssueTrackerManager.CAN_ALL,
                       issue_tracker_manager=None):
  """Get issue objects that seem to be related to a particular test case."""
  if not issue_tracker_manager:
    issue_tracker_manager = get_issue_tracker_manager(testcase)

  # Get list of issues using the search query.
  search_text = get_similar_issues_query(testcase)
  issue_objects = issue_tracker_manager.get_issues(search_text, can=can)
  issue_ids = [issue.id for issue in issue_objects]

  # Add issues from similar testcases sharing the same group id.
  if testcase.group_id:
    group_query = data_types.Testcase.query(
        data_types.Testcase.group_id == testcase.group_id)
    similar_testcases = ndb_utils.get_all_from_query(group_query)
    for similar_testcase in similar_testcases:
      if not similar_testcase.bug_information:
        continue

      # Exclude issues already added above from search terms.
      issue_id = int(similar_testcase.bug_information)
      if issue_id in issue_ids:
        continue

      # Get issue object using ID.
      issue = issue_tracker_manager.get_issue(issue_id)
      if not issue:
        continue

      # If our search criteria allows open bugs only, then check issue and
      # testcase status so as to exclude closed ones.
      if (can == IssueTrackerManager.CAN_OPEN and
          (not issue.open or not testcase.open)):
        continue

      issue_objects.append(issue)
      issue_ids.append(issue_id)

  return issue_objects


def was_label_added(issue, label):
  """Check if a label was ever added to an issue."""
  for action in issue.actions:
    for added in action.labels.added:
      if label.lower() == added.lower():
        return True

  return False

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
"""Grouper for grouping similar looking testcases."""

import pickle
import os

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.issue_management import issue_tracker_utils
from clusterfuzz._internal.metrics import logs


FORWARDED_ATTRIBUTES = ('crash_state', 'crash_type', 'group_id',
                        'one_time_crasher_flag', 'project_name',
                        'security_flag', 'timestamp', 'job_type')

TEST_DELETED_TCS = set()
MAX_TCS_PICKLE = 100000


class TestcaseAttributes:
  """Testcase attributes used for grouping."""

  __slots__ = ('id', 'is_leader', 'issue_id', 'test_deleted') + FORWARDED_ATTRIBUTES

  def __init__(self, testcase_id):
    self.id = testcase_id
    self.is_leader = True
    self.issue_id = None


def noop(self):
  pass

def _has_testcase_with_same_params(testcase, testcase_map):
  """Return a bool whether there is another testcase with same params."""
  for other_testcase_id in testcase_map:
    # yapf: disable
    if (testcase.project_name ==
        testcase_map[other_testcase_id].project_name and
        testcase.crash_state ==
        testcase_map[other_testcase_id].crash_state and
        testcase.crash_type ==
        testcase_map[other_testcase_id].crash_type and
        testcase.security_flag ==
        testcase_map[other_testcase_id].security_flag and
        testcase.one_time_crasher_flag ==
        testcase_map[other_testcase_id].one_time_crasher_flag):
      return True
    # yapf: enable

  return False

def load_testcases():
  """Load and store testcases."""
  testcase_map = {}
  cached_issue_map = {}

  # No-op to update/delete functions
  data_types.Testcase.put = noop
  data_types.Testcase.key.delete = noop

  for testcase_id in data_handler.get_open_testcase_id_iterator():
    if MAX_TCS_PICKLE > 0 and len(testcase_map) >= MAX_TCS_PICKLE:
      break

    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      # Already deleted.
      continue

    # Remove duplicates early on to avoid large groups.
    if (not testcase.bug_information and not testcase.uploader_email and
        _has_testcase_with_same_params(testcase, testcase_map)):
      logs.info('Deleting duplicate testcase %d.' % testcase_id)
      TEST_DELETED_TCS.add(testcase_id)
      continue

    # Wait for minimization to finish as this might change crash params such
    # as type and may mark it as duplicate / closed.
    if not testcase.minimized_keys:
      continue

    # Store needed testcase attributes into |testcase_map|.
    testcase_map[testcase_id] = TestcaseAttributes(testcase_id)
    testcase_attributes = testcase_map[testcase_id]
    for attribute_name in FORWARDED_ATTRIBUTES:
      setattr(testcase_attributes, attribute_name,
              getattr(testcase, attribute_name))

    # Store original issue mappings in the testcase attributes.
    if testcase.bug_information:
      issue_id = int(testcase.bug_information)
      project_name = testcase.project_name

      if (project_name in cached_issue_map and
          issue_id in cached_issue_map[project_name]):
        testcase_attributes.issue_id = (
            cached_issue_map[project_name][issue_id])
      else:
        try:
          issue_tracker = issue_tracker_utils.get_issue_tracker_for_testcase(
              testcase)
          if issue_tracker:
            logs.info(
                f'Running grouping with issue tracker {issue_tracker.project}, '
                f' for testcase {testcase_id}')
        except ValueError:
          logs.error('Couldn\'t get issue tracker for issue.')
          del testcase_map[testcase_id]
          continue

        if not issue_tracker:
          logs.error('Unable to access issue tracker for issue %d.' % issue_id)
          testcase_attributes.issue_id = issue_id
          continue

        # Determine the original issue id traversing the list of duplicates.
        try:
          issue = issue_tracker.get_original_issue(issue_id)
          original_issue_id = int(issue.id)
        except:
          # If we are unable to access the issue, then we can't determine
          # the original issue id. Assume that it is the same as issue id.
          logs.error(
              'Unable to determine original issue for issue %d.' % issue_id)
          testcase_attributes.issue_id = issue_id
          continue

        if project_name not in cached_issue_map:
          cached_issue_map[project_name] = {}
        cached_issue_map[project_name][issue_id] = original_issue_id
        cached_issue_map[project_name][original_issue_id] = original_issue_id
        testcase_attributes.issue_id = original_issue_id

  # No longer needed. Free up some memory.
  cached_issue_map.clear()
  attr_filepath = os.path.join(os.getenv('PATH_TO_TCS', '.'), 'testcases_attributes.pkl')
  tcs_deleted_filepath = os.path.join(os.getenv('PATH_TO_TCS', '.'), 'testcases_deleted.pkl')
  with open(attr_filepath, 'wb') as f:
    pickle.dump(testcase_map, f)

  with open(tcs_deleted_filepath, 'wb') as f:
    pickle.dump(TEST_DELETED_TCS, f)

def main():
  logs.configure('run_bot')
  try:
    logs.info('Loading testcases.')
    load_testcases()
    logs.info(f'Loading done. Testcases saved at {os.getenv("PATH_TO_TCS", ".")}')
  except Exception as e:
    logs.error(f'Error occurred while loading test cases - {e}.')
    return False

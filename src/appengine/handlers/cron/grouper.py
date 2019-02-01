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

from base import errors
from crash_analysis.crash_comparer import CrashComparer
from datastore import data_handler
from datastore import data_types
from issue_management import issue_tracker_utils
from metrics import logs

import group_leader

FORWARDED_ATTRIBUTES = ('crash_state', 'crash_type', 'group_id',
                        'one_time_crasher_flag', 'project_name',
                        'security_flag', 'timestamp')

GROUP_MAX_TESTCASE_LIMIT = 100


class TestcaseAttributes(object):
  """Testcase attributes used for grouping."""

  __slots__ = ('is_leader', 'issue_id') + FORWARDED_ATTRIBUTES

  def __init__(self):
    self.is_leader = True
    self.issue_id = None


def combine_testcases_into_group(testcase_1, testcase_2, testcase_map):
  """Combine two testcases into a group."""
  logs.log(
      'Grouping testcase 1 '
      '(crash_type=%s, crash_state=%s, security_flag=%s, group=%s) '
      'and testcase 2 '
      '(crash_type=%s, crash_state=%s, security_flag=%s, group=%s).' %
      (testcase_1.crash_type, testcase_1.crash_state, testcase_1.security_flag,
       testcase_1.group_id, testcase_2.crash_type, testcase_2.crash_state,
       testcase_2.security_flag, testcase_2.group_id))

  # If none of the two testcases have a group id, just assign a new group id to
  # both.
  if not testcase_1.group_id and not testcase_2.group_id:
    new_group_id = get_new_group_id()
    testcase_1.group_id = new_group_id
    testcase_2.group_id = new_group_id
    return

  # If one of the testcase has a group id, then assign the other to reuse that
  # group id.
  if testcase_1.group_id and not testcase_2.group_id:
    testcase_2.group_id = testcase_1.group_id
    return
  if testcase_2.group_id and not testcase_1.group_id:
    testcase_1.group_id = testcase_2.group_id
    return

  # If both the testcase have their own groups, then just merge the two groups
  # together and reuse one of their group ids.
  group_id_to_reuse = testcase_1.group_id
  group_id_to_move = testcase_2.group_id
  for testcase in testcase_map.itervalues():
    if testcase.group_id == group_id_to_move:
      testcase.group_id = group_id_to_reuse


def get_new_group_id():
  """Get a new group id for testcase grouping."""
  new_group = data_types.TestcaseGroup()
  new_group.put()
  return new_group.key.id()


def group_testcases():
  """Group testcases based on rules like same bug numbers, similar crash
  states, etc."""
  testcase_map = {}
  cached_issue_map = {}

  for testcase_id in data_handler.get_open_testcase_id_iterator():
    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      # Already deleted.
      continue

    # Remove duplicates early on to avoid large groups.
    if (not testcase.bug_information and not testcase.uploader_email and
        has_testcase_with_same_params(testcase, testcase_map)):
      testcase.key.delete()
      continue

    # Store needed testcase attributes into |testcase_map|.
    testcase_map[testcase_id] = TestcaseAttributes()
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
        issue_tracker_manager = issue_tracker_utils.get_issue_tracker_manager(
            testcase=testcase, use_cache=True)
        if not issue_tracker_manager:
          continue

        # Determine the original issue id traversing the list of duplicates.
        try:
          issue = issue_tracker_manager.get_original_issue(issue_id)
          original_issue_id = issue.id
        except:
          # If we are unable to access the issue, then we can't determine
          # the original issue id. Assume that it is the same as issue id.
          logs.log_error(
              'Unable to determine original issue for %d.' % issue_id)
          original_issue_id = issue_id

        if project_name not in cached_issue_map:
          cached_issue_map[project_name] = {}
        cached_issue_map[project_name][issue_id] = original_issue_id
        cached_issue_map[project_name][original_issue_id] = original_issue_id
        testcase_attributes.issue_id = original_issue_id

  # No longer needed. Free up some memory.
  cached_issue_map.clear()

  group_testcases_with_similar_states(testcase_map)
  group_testcases_with_same_issues(testcase_map)
  group_leader.choose(testcase_map)

  # TODO(aarya): Replace with an optimized implementation using dirty flag.
  # Update the group mapping in testcase object.
  for testcase_id in data_handler.get_open_testcase_id_iterator():
    if testcase_id not in testcase_map:
      # A new testcase that was just created. Skip for now, will be grouped in
      # next iteration of group task.
      continue

    # If we are part of a group, then calculate the number of testcases in that
    # group and lowest issue id of issues associated with testcases in that
    # group.
    updated_group_id = testcase_map[testcase_id].group_id
    updated_is_leader = testcase_map[testcase_id].is_leader
    updated_group_id_count = 0
    updated_group_bug_information = 0
    if updated_group_id:
      for other_testcase in testcase_map.itervalues():
        if other_testcase.group_id != updated_group_id:
          continue
        updated_group_id_count += 1

        # Update group issue id to be lowest issue id in the entire group.
        if other_testcase.issue_id is None:
          continue
        if (not updated_group_bug_information or
            updated_group_bug_information > other_testcase.issue_id):
          updated_group_bug_information = other_testcase.issue_id

    # If this group id is used by only one testcase, then remove it.
    if updated_group_id_count == 1:
      data_handler.delete_group(updated_group_id, update_testcases=False)
      updated_group_id = 0
      updated_group_bug_information = 0
      updated_is_leader = True

    # If this group has more than the maximum allowed testcases, log an error
    # so that the sheriff can later debug what caused this. Usually, this is a
    # bug in grouping logic OR a ever changing crash signature (e.g. slightly
    # different crash types or crash states). We cannot bail out as otherwise,
    # we will not group the testcase leading to a spam of new filed bugs.
    if updated_group_id_count > GROUP_MAX_TESTCASE_LIMIT:
      logs.log_error(
          'Group %d exceeds maximum allowed testcases.' % updated_group_id)

    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      # Already deleted.
      continue

    is_changed = (
        (testcase.group_id != updated_group_id) or
        (testcase.group_bug_information != updated_group_bug_information) or
        (testcase.is_leader != updated_is_leader))

    if not is_changed:
      # If nothing is changed, no more work to do. It's faster this way.
      continue

    testcase.group_bug_information = updated_group_bug_information
    testcase.group_id = updated_group_id
    testcase.is_leader = updated_is_leader
    testcase.put()
    logs.log(
        'Updated testcase %d group to %d.' % (testcase_id, updated_group_id))


def group_testcases_with_same_issues(testcase_map):
  """Group testcases that are associated with same underlying issue."""
  for testcase_1_id, testcase_1 in testcase_map.iteritems():
    for testcase_2_id, testcase_2 in testcase_map.iteritems():
      # Rule: Don't group the same testcase and use different combinations for
      # comparisons.
      if testcase_1_id <= testcase_2_id:
        continue

      # Rule: If both testcase have the same group id, then no work to do.
      if testcase_1.group_id == testcase_2.group_id and testcase_1.group_id:
        continue

      # Rule: Check both testcase have an associated issue id.
      if testcase_1.issue_id is None or testcase_2.issue_id is None:
        continue

      # Rule: Check both testcase are under the same project.
      if testcase_1.project_name != testcase_2.project_name:
        continue

      # Rule: Group testcase with same underlying issue.
      if testcase_1.issue_id != testcase_2.issue_id:
        continue

      combine_testcases_into_group(testcase_1, testcase_2, testcase_map)


def group_testcases_with_similar_states(testcase_map):
  """Group testcases with similar looking crash states."""
  for testcase_1_id, testcase_1 in testcase_map.iteritems():
    for testcase_2_id, testcase_2 in testcase_map.iteritems():
      # Rule: Don't group the same testcase and use different combinations for
      # comparisons.
      if testcase_1_id <= testcase_2_id:
        continue

      # If both testcase have the same group id, then no work to do.
      if testcase_1.group_id == testcase_2.group_id and testcase_1.group_id:
        continue

      # Rule: Check both testcase are under the same project.
      if testcase_1.project_name != testcase_2.project_name:
        continue

      # Rule: Security bugs should never be grouped with functional bugs.
      if testcase_1.security_flag != testcase_2.security_flag:
        continue

      # Rule: Follow different comparison rules when crash types is one of the
      # ones that have unique crash state (custom ones specifically).
      if (testcase_1.crash_type in data_types.CRASH_TYPES_WITH_UNIQUE_STATE or
          testcase_2.crash_type in data_types.CRASH_TYPES_WITH_UNIQUE_STATE):

        # For grouping, make sure that both crash type and state match.
        if (testcase_1.crash_type != testcase_2.crash_type or
            testcase_1.crash_state != testcase_2.crash_state):
          continue

      else:
        # Rule: For functional bugs, compare for similar crash states.
        if not testcase_1.security_flag:
          crash_comparer = CrashComparer(testcase_1.crash_type,
                                         testcase_2.crash_type)
          if not crash_comparer.is_similar():
            continue

        # Rule: Check for crash state similarity.
        crash_comparer = CrashComparer(testcase_1.crash_state,
                                       testcase_2.crash_state)
        if not crash_comparer.is_similar():
          continue

      combine_testcases_into_group(testcase_1, testcase_2, testcase_map)


def has_testcase_with_same_params(testcase, testcase_map):
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

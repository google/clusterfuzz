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

import collections
import re

import six

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from libs.issue_management import issue_tracker_utils

from . import cleanup
from . import group_leader

FORWARDED_ATTRIBUTES = ('crash_state', 'crash_type', 'group_id',
                        'one_time_crasher_flag', 'project_name',
                        'security_flag', 'timestamp', 'job_type')

GROUP_MAX_TESTCASE_LIMIT = 25

VARIANT_CRASHES_IGNORE = re.compile(
    r'^(Out-of-memory|Timeout|Missing-library|Data race|GPU failure)')

VARIANT_STATES_IGNORE = re.compile(r'^NULL$')

VARIANT_THRESHOLD_PERCENTAGE = 0.2
VARIANT_MIN_THRESHOLD = 5
VARIANT_MAX_THRESHOLD = 10

TOP_CRASHES_LIMIT = 10


class TestcaseAttributes(object):
  """Testcase attributes used for grouping."""

  __slots__ = ('id', 'is_leader', 'issue_id') + FORWARDED_ATTRIBUTES

  def __init__(self, testcase_id):
    self.id = testcase_id
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
    new_group_id = _get_new_group_id()
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
  for testcase in six.itervalues(testcase_map):
    if testcase.group_id == group_id_to_move:
      testcase.group_id = group_id_to_reuse


def _get_new_group_id():
  """Get a new group id for testcase grouping."""
  new_group = data_types.TestcaseGroup()
  new_group.put()
  return new_group.key.id()


def is_same_variant(variant1, variant2):
  """Checks for the testcase variants equality."""
  return (variant1.crash_type == variant2.crash_type and
          variant1.crash_state == variant2.crash_state and
          variant1.security_flag == variant2.security_flag)


def matches_top_crash(testcase, top_crashes_by_project_and_platform):
  """Returns whether or not a testcase is a top crash."""
  if testcase.project_name not in top_crashes_by_project_and_platform:
    return False

  crashes_by_platform = top_crashes_by_project_and_platform[
      testcase.project_name]
  for crashes in crashes_by_platform.values():
    for crash in crashes:
      if (crash['crashState'] == testcase.crash_state and
          crash['crashType'] == testcase.crash_type and
          crash['isSecurity'] == testcase.security_flag):
        return True

  return False


def _group_testcases_based_on_variants(testcase_map):
  """Group testcases that are associated based on variant analysis."""
  # Skip this if the project is configured so (like Google3).
  enable = local_config.ProjectConfig().get('deduplication.variant', True)
  if not enable:
    return

  logs.log('Grouping based on variant analysis.')
  grouping_candidates = collections.defaultdict(list)
  project_num_testcases = collections.defaultdict(int)
  # Phase 1: collect all grouping candidates.
  for testcase_1_id, testcase_1 in testcase_map.items():
    # Count the number of testcases for each project.
    project_num_testcases[testcase_1.project_name] += 1

    for testcase_2_id, testcase_2 in testcase_map.items():
      # Rule: Don't group the same testcase and use different combinations for
      # comparisons.
      if testcase_1_id <= testcase_2_id:
        continue

      # Rule: If both testcase have the same group id, then no work to do.
      if testcase_1.group_id == testcase_2.group_id and testcase_1.group_id:
        continue

      # Rule: Check both testcase are under the same project.
      if testcase_1.project_name != testcase_2.project_name:
        continue

      # Rule: If both testcase have same job_type, then skip variant anlysis.
      if testcase_1.job_type == testcase_2.job_type:
        continue

      # Rule: Skip variant analysis if any testcase is timeout or OOM.
      if (VARIANT_CRASHES_IGNORE.match(testcase_1.crash_type) or
          VARIANT_CRASHES_IGNORE.match(testcase_2.crash_type)):
        continue

      # Rule: Skip variant analysis if any testcase states is NULL.
      if (VARIANT_STATES_IGNORE.match(testcase_1.crash_state) or
          VARIANT_STATES_IGNORE.match(testcase_2.crash_state)):
        continue

      # Rule: Skip variant analysis if any testcase is not reproducible.
      if testcase_1.one_time_crasher_flag or testcase_2.one_time_crasher_flag:
        continue

      # Rule: Group testcase with similar variants.
      # For each testcase2, get the related variant1 and check for equivalence.
      candidate_variant = data_handler.get_testcase_variant(
          testcase_1_id, testcase_2.job_type)

      if (not candidate_variant or
          not is_same_variant(candidate_variant, testcase_2)):
        continue

      current_project = testcase_1.project_name
      grouping_candidates[current_project].append((testcase_1_id,
                                                   testcase_2_id))

  # Top crashes are usually startup crashes, so don't group them.
  top_crashes_by_project_and_platform = (
      cleanup.get_top_crashes_for_all_projects_and_platforms(
          limit=TOP_CRASHES_LIMIT))

  # Phase 2: check for the anomalous candidates
  # i.e. candiates matched with many testcases.
  for project, candidate_list in grouping_candidates.items():
    project_ignore_testcases = set()
    # Count the number of times a testcase is matched for grouping.
    project_counter = collections.defaultdict(int)
    for candidate_tuple in candidate_list:
      for testcase_id in candidate_tuple:
        project_counter[testcase_id] += 1

    # Determine anomalous candidates.
    threshold = VARIANT_THRESHOLD_PERCENTAGE * project_num_testcases[project]
    threshold = min(threshold, VARIANT_MAX_THRESHOLD)
    threshold = max(threshold, VARIANT_MIN_THRESHOLD)
    # Check threshold to be above a minimum, to avoid unnecessary filtering.
    for testcase_id, count in project_counter.items():
      if count >= threshold:
        project_ignore_testcases.add(testcase_id)
    for (testcase_1_id, testcase_2_id) in candidate_list:
      if (testcase_1_id in project_ignore_testcases or
          testcase_2_id in project_ignore_testcases):
        logs.log('VARIANT ANALYSIS (Pruning): Anomalous match: (id1=%s, '
                 'matched_count1=%d) matched with (id2=%d, matched_count2=%d), '
                 'threshold=%.2f.' %
                 (testcase_1_id, project_counter[testcase_1_id], testcase_2_id,
                  project_counter[testcase_2_id], threshold))
        continue

      testcase_1 = testcase_map[testcase_1_id]
      testcase_2 = testcase_map[testcase_2_id]

      if (matches_top_crash(testcase_1, top_crashes_by_project_and_platform) or
          matches_top_crash(testcase_2, top_crashes_by_project_and_platform)):
        logs.log(f'VARIANT ANALYSIS: {testcase_1_id} or {testcase_2_id} '
                 'is a top crash, skipping.')
        continue

      logs.log(
          'VARIANT ANALYSIS: Grouping testcase 1 '
          '(id=%s, '
          'crash_type=%s, crash_state=%s, security_flag=%s, job=%s, group=%s) '
          'and testcase 2 (id=%s, '
          'crash_type=%s, crash_state=%s, security_flag=%s, job=%s, group=%s).'
          %
          (testcase_1.id, testcase_1.crash_type, testcase_1.crash_state,
           testcase_1.security_flag, testcase_1.job_type, testcase_1.group_id,
           testcase_2.id, testcase_2.crash_type, testcase_2.crash_state,
           testcase_2.security_flag, testcase_2.job_type, testcase_2.group_id))
      combine_testcases_into_group(testcase_1, testcase_2, testcase_map)


def _group_testcases_with_same_issues(testcase_map):
  """Group testcases that are associated with same underlying issue."""
  logs.log('Grouping based on same issues.')
  for testcase_1_id, testcase_1 in six.iteritems(testcase_map):
    for testcase_2_id, testcase_2 in six.iteritems(testcase_map):
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


def _group_testcases_with_similar_states(testcase_map):
  """Group testcases with similar looking crash states."""
  logs.log('Grouping based on similar states.')
  for testcase_1_id, testcase_1 in six.iteritems(testcase_map):
    for testcase_2_id, testcase_2 in six.iteritems(testcase_map):
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


def _shrink_large_groups_if_needed(testcase_map):
  """Shrinks groups that exceed a particular limit."""

  def _key_func(testcase):
    weight = 0
    if not testcase.one_time_crasher_flag:
      weight |= 2**1
    if testcase.issue_id:
      weight |= 2**2
    return weight

  group_id_with_testcases_map = {}
  for testcase in six.itervalues(testcase_map):
    if not testcase.group_id:
      continue

    if testcase.group_id not in group_id_with_testcases_map:
      group_id_with_testcases_map[testcase.group_id] = [testcase]
    else:
      group_id_with_testcases_map[testcase.group_id].append(testcase)

  for testcases_in_group in group_id_with_testcases_map.values():
    if len(testcases_in_group) <= GROUP_MAX_TESTCASE_LIMIT:
      continue

    testcases_in_group = sorted(testcases_in_group, key=_key_func)
    for testcase in testcases_in_group[:-GROUP_MAX_TESTCASE_LIMIT]:
      try:
        testcase_entity = data_handler.get_testcase_by_id(testcase.id)
      except errors.InvalidTestcaseError:
        # Already deleted.
        continue

      if testcase_entity.bug_information:
        continue

      logs.log_warn(('Deleting testcase {testcase_id} due to overflowing group '
                     '{group_id}.').format(
                         testcase_id=testcase.id, group_id=testcase.group_id))
      testcase_entity.key.delete()


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
        _has_testcase_with_same_params(testcase, testcase_map)):
      logs.log('Deleting duplicate testcase %d.' % testcase_id)
      testcase.key.delete()
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
        issue_tracker = issue_tracker_utils.get_issue_tracker_for_testcase(
            testcase)
        if not issue_tracker:
          logs.log_error(
              'Unable to access issue tracker for issue %d.' % issue_id)
          testcase_attributes.issue_id = issue_id
          continue

        # Determine the original issue id traversing the list of duplicates.
        try:
          issue = issue_tracker.get_original_issue(issue_id)
          original_issue_id = int(issue.id)
        except:
          # If we are unable to access the issue, then we can't determine
          # the original issue id. Assume that it is the same as issue id.
          logs.log_error(
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

  _group_testcases_with_similar_states(testcase_map)
  _group_testcases_with_same_issues(testcase_map)
  _group_testcases_based_on_variants(testcase_map)
  _shrink_large_groups_if_needed(testcase_map)
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
      for other_testcase in six.itervalues(testcase_map):
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

    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      # Already deleted.
      continue

    is_changed = (
        (testcase.group_id != updated_group_id) or
        (testcase.group_bug_information != updated_group_bug_information) or
        (testcase.is_leader != updated_is_leader))

    if not testcase.get_metadata('ran_grouper'):
      testcase.set_metadata('ran_grouper', True, update_testcase=not is_changed)

    if not is_changed:
      continue

    testcase.group_bug_information = updated_group_bug_information
    testcase.group_id = updated_group_id
    testcase.is_leader = updated_is_leader
    testcase.put()
    logs.log(
        'Updated testcase %d group to %d.' % (testcase_id, updated_group_id))

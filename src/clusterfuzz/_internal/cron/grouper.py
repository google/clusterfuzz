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

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.issue_management import issue_tracker_utils
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import monitoring_metrics

from . import cleanup
from . import group_leader

FORWARDED_ATTRIBUTES = ('crash_state', 'crash_type', 'group_id',
                        'one_time_crasher_flag', 'project_name',
                        'security_flag', 'timestamp', 'job_type', 'fuzzer_name')

VARIANT_CRASHES_IGNORE = re.compile(
    r'^(Out-of-memory|Timeout|Missing-library|Data race|GPU failure)')

VARIANT_STATES_IGNORE = re.compile(r'^NULL$')

VARIANT_THRESHOLD_PERCENTAGE = 0.2
VARIANT_MIN_THRESHOLD = 5
VARIANT_MAX_THRESHOLD = 10

TOP_CRASHES_LIMIT = 10

DELETE_TESTCASES_FROM_GROUPING = local_config.ProjectConfig().get(
    'deduplication.delete_testcases_from_grouping', True)
GROUP_MAX_TESTCASE_LIMIT = local_config.ProjectConfig().get(
    'deduplication.group_max_limit', 25)
CRASH_COMPARER_THRESHOLD = local_config.ProjectConfig().get(
    'deduplication.crash_comparer_threshold')
CRASH_COMPARER_SAME_FRAMES = local_config.ProjectConfig().get(
    'deduplication.crash_comparer_same_frames')


class TestcaseAttributes:
  """Testcase attributes used for grouping."""

  __slots__ = ('id', 'is_leader', 'issue_id') + FORWARDED_ATTRIBUTES

  def __init__(self, testcase_id):
    self.id = testcase_id
    self.is_leader = True
    self.issue_id = None

  def get_metadata(self, key=None, default=None):
    """Retrieve class attributes."""
    # This method is useful so that an object calling it gets a similar result
    # independently of its class being a Testcase or TestcaseAttributes.
    if not key:
      return {k: getattr(self, k) for k in self.__slots__ if hasattr(self, k)}
    return getattr(self, key, default)


def _emit_grouping_event(moved_testcase: int,
                         new_group_id: int,
                         prev_group_id: int,
                         similar_testcase: int | None,
                         reason: str,
                         group_merge: bool = False):
  """Helper for emitting a testcase grouping event."""
  # If this is due to a group merge, we have to use the grouping reason as the
  # reason for the merge itself.
  group_merge_reason = None
  if group_merge:
    group_merge_reason = reason
    reason = events.GroupingReason.GROUP_MERGE

  events.emit(
      events.TestcaseGroupingEvent(
          testcase_id=moved_testcase,
          group_id=new_group_id,
          previous_group_id=prev_group_id,
          similar_testcase_id=similar_testcase,
          grouping_reason=reason,
          group_merge_reason=group_merge_reason))


def combine_testcases_into_group(
    testcase_1: TestcaseAttributes, testcase_2: TestcaseAttributes,
    testcase_map: dict[int, TestcaseAttributes], reason: str) -> None:
  """Combine two testcases into a group."""
  logs.info(
      'Grouping testcase %s '
      '(crash_type=%s, crash_state=%s, security_flag=%s, group=%s) '
      'and testcase %s '
      '(crash_type=%s, crash_state=%s, security_flag=%s, group=%s). Reason: %s'
      % (testcase_1.id, testcase_1.crash_type, testcase_1.crash_state,
         testcase_1.security_flag, testcase_1.group_id, testcase_2.id,
         testcase_2.crash_type, testcase_2.crash_state,
         testcase_2.security_flag, testcase_2.group_id, reason))

  # If none of the two testcases have a group id, just assign a new group id to
  # both.
  if not testcase_1.group_id and not testcase_2.group_id:
    new_group_id = _get_new_group_id()
    testcase_1.group_id = new_group_id
    testcase_2.group_id = new_group_id
    # Both testcases are moved, so emit an event for each.
    _emit_grouping_event(testcase_1.id, new_group_id, 0, testcase_2.id, reason)
    _emit_grouping_event(testcase_2.id, new_group_id, 0, testcase_1.id, reason)
    return

  # If one of the testcase has a group id, then assign the other to reuse that
  # group id.
  if testcase_1.group_id and not testcase_2.group_id:
    testcase_2.group_id = testcase_1.group_id
    # Only emit event for moved testcase_2.
    _emit_grouping_event(testcase_2.id, testcase_1.group_id, 0, testcase_1.id,
                         reason)
    return

  if testcase_2.group_id and not testcase_1.group_id:
    testcase_1.group_id = testcase_2.group_id
    # Only emit event for moved testcase_1.
    _emit_grouping_event(testcase_1.id, testcase_2.group_id, 0, testcase_2.id,
                         reason)
    return

  # If both the testcase have their own groups, then just merge the two groups
  # together and reuse one of their group ids.
  group_id_to_reuse = testcase_1.group_id
  group_id_to_move = testcase_2.group_id
  # Emit event for testcase from group to be moved.
  _emit_grouping_event(testcase_2.id, testcase_1.group_id, testcase_2.group_id,
                       testcase_1.id, reason)

  moved_testcase_ids = []
  for testcase in testcase_map.values():
    if testcase.group_id == group_id_to_move:
      testcase.group_id = group_id_to_reuse
      moved_testcase_ids.append(str(testcase.id))
      if testcase.id != testcase_2.id:
        # Emit event for each testcase moved due to the group merge.
        _emit_grouping_event(
            testcase.id,
            group_id_to_reuse,
            group_id_to_move,
            testcase_2.id,
            reason,
            group_merge=True)

  logs.info(f'Merged group {group_id_to_move} into {group_id_to_reuse}: ' +
            'moved testcases: ' + ', '.join(moved_testcase_ids))


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


def _check_variant_grouping_candidate(testcase_1: TestcaseAttributes,
                                      testcase_2: TestcaseAttributes,
                                      grouping_candidates: dict[str, list]):
  """Check if a pair of testcases is a candidate for variant-based grouping.
  
  If the pair is a valid candidate for variant grouping, their IDs are appended
  as a tuple to the corresponding project in the `grouping_candidates` map.
  """
  testcase_1_id = testcase_1.id
  testcase_2_id = testcase_2.id

  # Rule: Don't group the same testcase and use different combinations for
  # comparisons.
  if testcase_1_id <= testcase_2_id:
    return

  # Rule: If both testcase have the same group id, then no work to do.
  if testcase_1.group_id == testcase_2.group_id and testcase_1.group_id:
    return

  # Rule: Check both testcase are under the same project.
  if testcase_1.project_name != testcase_2.project_name:
    return

  # Rule: If both testcase have same job_type, then skip variant anlysis.
  if testcase_1.job_type == testcase_2.job_type:
    return

  # Rule: Skip variant analysis if any testcase is timeout or OOM.
  if (VARIANT_CRASHES_IGNORE.match(testcase_1.crash_type) or
      VARIANT_CRASHES_IGNORE.match(testcase_2.crash_type)):
    return

  # Rule: Skip variant analysis if any testcase states is NULL.
  if (VARIANT_STATES_IGNORE.match(testcase_1.crash_state) or
      VARIANT_STATES_IGNORE.match(testcase_2.crash_state)):
    return

  # Rule: Skip variant analysis if any testcase is not reproducible.
  if testcase_1.one_time_crasher_flag or testcase_2.one_time_crasher_flag:
    return

  # Rule: Group testcase with similar variants.
  # For each testcase2, get the related variant1 and check for equivalence.
  candidate_variant = data_handler.get_testcase_variant(testcase_1_id,
                                                        testcase_2.job_type)

  if (not candidate_variant or
      not is_same_variant(candidate_variant, testcase_2)):
    return

  current_project = testcase_1.project_name
  grouping_candidates[current_project].append((testcase_1_id, testcase_2_id))


def _group_testcases_based_on_variants(testcase_map):
  """Group testcases that are associated based on variant analysis."""
  # Skip this if the project is configured so (like Google3).
  enable = local_config.ProjectConfig().get('deduplication.variant', True)
  if not enable:
    return

  logs.info('Grouping based on variant analysis.')
  grouping_candidates = collections.defaultdict(list)
  project_num_testcases = collections.defaultdict(int)
  # Phase 1: collect all grouping candidates.
  for testcase_1_id, testcase_1 in testcase_map.items():
    # Count the number of testcases for each project.
    project_num_testcases[testcase_1.project_name] += 1

    for testcase_2_id, testcase_2 in testcase_map.items():
      with logs.grouper_log_context(testcase_1, testcase_2):
        _check_variant_grouping_candidate(testcase_1, testcase_2,
                                          grouping_candidates)

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
      testcase_1 = testcase_map[testcase_1_id]
      testcase_2 = testcase_map[testcase_2_id]
      with logs.grouper_log_context(testcase_1, testcase_2):
        if (testcase_1_id in project_ignore_testcases or
            testcase_2_id in project_ignore_testcases):
          logs.info(
              'VARIANT ANALYSIS (Pruning): Anomalous match: (id1=%s, '
              'matched_count1=%d) matched with (id2=%d, matched_count2=%d), '
              'threshold=%.2f.' %
              (testcase_1_id, project_counter[testcase_1_id], testcase_2_id,
               project_counter[testcase_2_id], threshold))
          continue

        if (matches_top_crash(testcase_1,
                              top_crashes_by_project_and_platform) or
            matches_top_crash(testcase_2, top_crashes_by_project_and_platform)):
          logs.info(f'VARIANT ANALYSIS: {testcase_1_id} or {testcase_2_id} '
                    'is a top crash, skipping.')
          continue

        combine_testcases_into_group(testcase_1, testcase_2, testcase_map,
                                     events.GroupingReason.IDENTICAL_VARIANT)


def _group_testcases_with_same_issues(testcase_map):
  """Group testcases that are associated with same underlying issue."""
  logs.info('Grouping based on same issues.')
  for testcase_1_id, testcase_1 in testcase_map.items():
    for testcase_2_id, testcase_2 in testcase_map.items():
      with logs.grouper_log_context(testcase_1, testcase_2):
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

        combine_testcases_into_group(testcase_1, testcase_2, testcase_map,
                                     events.GroupingReason.SAME_ISSUE)


def _compare_testcases_crash_states(testcase_1, testcase_2) -> bool:
  """Apply crash comparison rules for a pair of testcases."""
  # Rule: Follow different comparison rules when crash types is one of the
  # ones that have unique crash state (custom ones specifically).
  if (testcase_1.crash_type in data_types.CRASH_TYPES_WITH_UNIQUE_STATE or
      testcase_2.crash_type in data_types.CRASH_TYPES_WITH_UNIQUE_STATE):

    # For grouping, make sure that both crash type and state match.
    if (testcase_1.crash_type != testcase_2.crash_type or
        testcase_1.crash_state != testcase_2.crash_state):
      return False

  else:
    # Rule: For functional bugs, compare for similar crash states.
    if not testcase_1.security_flag:
      crash_comparer = CrashComparer(
          testcase_1.crash_type, testcase_2.crash_type,
          CRASH_COMPARER_THRESHOLD, CRASH_COMPARER_SAME_FRAMES)
      if not crash_comparer.is_similar():
        return False

    # Rule: Check for crash state similarity.
    crash_comparer = CrashComparer(
        testcase_1.crash_state, testcase_2.crash_state,
        CRASH_COMPARER_THRESHOLD, CRASH_COMPARER_SAME_FRAMES)
    if not crash_comparer.is_similar():
      return False

  return True


def _group_testcases_with_similar_states(testcase_map):
  """Group testcases with similar looking crash states."""
  logs.info('Grouping based on similar states.')
  for testcase_1_id, testcase_1 in testcase_map.items():
    for testcase_2_id, testcase_2 in testcase_map.items():
      with logs.grouper_log_context(testcase_1, testcase_2):
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

        if not _compare_testcases_crash_states(testcase_1, testcase_2):
          continue

        combine_testcases_into_group(testcase_1, testcase_2, testcase_map,
                                     events.GroupingReason.SIMILAR_CRASH)


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


def _increment_group_overflow_metric(group_overflow, testcase):
  """Increments the counter for group overflow metric."""
  job = testcase.job_type
  fuzzer = testcase.fuzzer_name
  id_tuple = (job, fuzzer)
  if id_tuple not in group_overflow:
    group_overflow[id_tuple] = 0
  group_overflow[id_tuple] += 1


def _emit_group_overflow_metric(group_overflow):
  """Emits the testcase group overflow count metric."""
  for (job, fuzzer) in group_overflow:
    monitoring_metrics.TESTCASE_GROUP_OVERFLOW_COUNT.set(
        group_overflow[(job, fuzzer)], labels={
            'job': job,
            'fuzzer': fuzzer,
        })


def _shrink_large_groups_if_needed(testcase_map):
  """Shrinks groups that exceed a particular limit."""
  group_overflow = {}
  if isinstance(GROUP_MAX_TESTCASE_LIMIT, int):
    group_max_testcase_limit = int(GROUP_MAX_TESTCASE_LIMIT)
  else:
    logs.warning('Max group size is wrongly configured: '
                 f'{GROUP_MAX_TESTCASE_LIMIT}. Defaulting to 25.')
    group_max_testcase_limit = 25

  def _key_func(testcase):
    weight = 0
    if not testcase.one_time_crasher_flag:
      weight |= 2**1
    if testcase.issue_id:
      weight |= 2**2
    return weight

  group_id_with_testcases_map = {}
  for testcase in testcase_map.values():
    if not testcase.group_id:
      continue

    if testcase.group_id not in group_id_with_testcases_map:
      group_id_with_testcases_map[testcase.group_id] = [testcase]
    else:
      group_id_with_testcases_map[testcase.group_id].append(testcase)

  for testcases_in_group in group_id_with_testcases_map.values():
    group_size = len(testcases_in_group)
    monitoring_metrics.TESTCASE_GROUPS_SIZES.add(group_size)
    if group_size <= group_max_testcase_limit:
      continue

    testcases_in_group = sorted(testcases_in_group, key=_key_func)
    for testcase in testcases_in_group[:-group_max_testcase_limit]:
      try:
        testcase_entity = data_handler.get_testcase_by_id(testcase.id)
      except errors.InvalidTestcaseError:
        # Already deleted.
        continue

      with logs.testcase_log_context(testcase_entity,
                                     testcase_entity.get_fuzz_target()):
        if testcase_entity.bug_information:
          continue

        _increment_group_overflow_metric(group_overflow, testcase_entity)
        events.emit(
            events.TestcaseRejectionEvent(
                testcase=testcase_entity,
                rejection_reason=events.RejectionReason.GROUPER_OVERFLOW))
        if DELETE_TESTCASES_FROM_GROUPING:
          logs.warning(f'Deleting testcase {testcase.id} due to overflowing '
                       f'group {testcase.group_id}.')
          testcase_entity.key.delete()
        else:
          # Mark testcase as closed instead of deleting it to avoid data loss.
          logs.warning(f'Closing testcase {testcase.id} due to overflowing '
                       f'group {testcase.group_id}.')
          # TODO(vtcosta): Add logic to re-run progression for these testcases
          # when the group leader is closed. Delete them if they are also fixed.
          testcase_entity.fixed = 'NA'
          testcase_entity.open = False
          testcase_entity.put()

  _emit_group_overflow_metric(group_overflow)


def _get_testcase_attributes(testcase, testcase_map, cached_issue_map):
  """Retrieve testcase attributes for grouping and add it to the map."""
  testcase_id = testcase.key.id()
  # Remove duplicates early on to avoid large groups.
  if (not testcase.bug_information and not testcase.uploader_email and
      _has_testcase_with_same_params(testcase, testcase_map)):
    logs.info('Deleting duplicate testcase %d.' % testcase_id)
    events.emit(
        events.TestcaseRejectionEvent(
            testcase=testcase,
            rejection_reason=events.RejectionReason.GROUPER_DUPLICATE))
    testcase.key.delete()
    return

  # Wait for minimization to finish as this might change crash params such
  # as type and may mark it as duplicate / closed.
  if not testcase.minimized_keys:
    return

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
      testcase_attributes.issue_id = cached_issue_map[project_name][issue_id]
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
        return

      if not issue_tracker:
        logs.error('Unable to access issue tracker for issue %d.' % issue_id)
        testcase_attributes.issue_id = issue_id
        return

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
        return

      if project_name not in cached_issue_map:
        cached_issue_map[project_name] = {}
      cached_issue_map[project_name][issue_id] = original_issue_id
      cached_issue_map[project_name][original_issue_id] = original_issue_id
      testcase_attributes.issue_id = original_issue_id


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
    with logs.testcase_log_context(testcase, testcase.get_fuzz_target()):
      _get_testcase_attributes(testcase, testcase_map, cached_issue_map)

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
    testcase_attr = testcase_map[testcase_id]
    with logs.testcase_log_context(testcase_attr, None):
      # If we are part of a group, then calculate the number of testcases in
      # that group and lowest issue id of issues associated with testcases in
      # that group.
      updated_group_id = testcase_map[testcase_id].group_id
      updated_is_leader = testcase_map[testcase_id].is_leader
      updated_group_id_count = 0
      updated_group_bug_information = 0
      if updated_group_id:
        for other_testcase in testcase_map.values():
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
        logs.info(
            f'Deleted group {updated_group_id} used by only one testcase.')
        _emit_grouping_event(testcase_id, 0, updated_group_id, None,
                             events.GroupingReason.UNGROUPED)
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
        testcase.set_metadata(
            'ran_grouper', True, update_testcase=not is_changed)

      if not is_changed:
        continue

      testcase.group_bug_information = updated_group_bug_information
      testcase.group_id = updated_group_id
      testcase.is_leader = updated_is_leader
      testcase.put()
      logs.info(
          'Updated testcase %d group to %d.' % (testcase_id, updated_group_id))


@logs.cron_log_context()
def main():
  """Group testcases (this will be used to run grouper as a standalone cron in
  dev/staging environments)."""
  try:
    logs.info('Grouping testcases.')
    group_testcases()
    logs.info('Grouping done.')
  except:
    logs.error('Error occurred while grouping test cases.')
    return False

  return True

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
import random
import os
import pickle

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs

from . import cleanup
from . import group_leader
from load_groups import TestcaseAttributes

GROUP_MAX_TESTCASE_LIMIT = 25

VARIANT_CRASHES_IGNORE = re.compile(
    r'^(Out-of-memory|Timeout|Missing-library|Data race|GPU failure)')

VARIANT_STATES_IGNORE = re.compile(r'^NULL$')

VARIANT_THRESHOLD_PERCENTAGE = 0.2
VARIANT_MIN_THRESHOLD = 5
VARIANT_MAX_THRESHOLD = 10

TOP_CRASHES_LIMIT = 10
TEST_DELETED_TCS = set()

def noop(self):
  pass

class GroupAttributes:
  """Groups Attributes."""

  __slots__ = ('id', 'leader_id', 'group_issue_id', 'testcases')

  def __init__(self, group_id):
    self.id = group_id
    self.leader_id = None
    self.group_issue_id = None
    self.testcases = dict()

# def add_group_to_map(group_map: dict[int, GroupAttributes], group_id: int,
#                      tc1: int, tc2: int, reason: str) -> None:
#   if group_id not in group_map:
#     group_map[group_id] = GroupAttributes(group_id)
#   group_map[group_id].testcases.add(tc1)
#   group_map[group_id].testcases.add(tc2)
#   group_map[group_id].testcases_sims[f'{tc1}-{tc2}'] = reason 

def add_group_to_map(group_map: dict[int, GroupAttributes], group_id: int,
                     tc1: int, tc2: int, reason: str) -> None:
  if group_id not in group_map:
    group_map[group_id] = GroupAttributes(group_id)
  
  if tc1 not in group_map[group_id].testcases:
    group_map[group_id].testcases[tc1] = {}

  if tc2 not in group_map[group_id].testcases:
    group_map[group_id].testcases[tc2] = {}
  
  group_map[group_id].testcases[tc1][tc2] = reason 
  group_map[group_id].testcases[tc2][tc1] = reason

def remove_testcase_from_group(group_map: dict[int, GroupAttributes],
                               testcase: TestcaseAttributes) -> None:
  group_id = testcase.group_id
  tc_id = testcase.id
  if group_id not in group_map:
    return
  for similar_tc in group_map[group_id].testcases[tc_id].keys():
    del group_map[group_id].testcases[similar_tc][tc_id]
  del group_map[group_id].testcases[tc_id]

def combine_testcases_into_group(
    testcase_1: TestcaseAttributes, testcase_2: TestcaseAttributes,
    testcase_map: dict[int, TestcaseAttributes], reason: str, group_map: dict[int, GroupAttributes]) -> None:
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
    add_group_to_map(group_map, new_group_id, testcase_1.id, testcase_2.id, reason)
    return

  # If one of the testcase has a group id, then assign the other to reuse that
  # group id.
  if testcase_1.group_id and not testcase_2.group_id:
    testcase_2.group_id = testcase_1.group_id
    add_group_to_map(group_map, testcase_1.group_id, testcase_1.id, testcase_2.id, reason)
    return
  if testcase_2.group_id and not testcase_1.group_id:
    testcase_1.group_id = testcase_2.group_id
    add_group_to_map(group_map, testcase_2.group_id, testcase_1.id, testcase_2.id, reason)
    return

  # If both the testcase have their own groups, then just merge the two groups
  # together and reuse one of their group ids.
  group_id_to_reuse = testcase_1.group_id
  group_id_to_move = testcase_2.group_id
  moved_testcase_ids = []
  add_group_to_map(group_map, group_id_to_reuse, testcase_1.id, testcase_2.id, reason)
  for testcase in testcase_map.values():
    if testcase.group_id == group_id_to_move:
      testcase.group_id = group_id_to_reuse
      moved_testcase_ids.append(str(testcase.id))
      for tc_sim, r in group_map[group_id_to_move].testcases[testcase.id].items():
        add_group_to_map(group_map, group_id_to_reuse, testcase_1.id, tc_sim, r)
  del group_map[group_id_to_move]
  logs.info(f'Merged group {group_id_to_move} into {group_id_to_reuse}: ' +
            'moved testcases: ' + ', '.join(moved_testcase_ids))


def _get_new_group_id():
  """Get a new group id for testcase grouping."""
  return random.randint(0, 2**63-1)


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


def _group_testcases_based_on_variants(testcase_map, group_map):
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
      candidate_variant = data_handler.get_testcase_variant( # ---> ONLY QUERIES DB
          testcase_1_id, testcase_2.job_type)

      if (not candidate_variant or
          not is_same_variant(candidate_variant, testcase_2)):
        continue

      current_project = testcase_1.project_name
      grouping_candidates[current_project].append((testcase_1_id,
                                                   testcase_2_id))

  # Top crashes are usually startup crashes, so don't group them.
  top_crashes_by_project_and_platform = (
      cleanup.get_top_crashes_for_all_projects_and_platforms( # ---> ONLY QUERIES DB
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
        logs.info(
            'VARIANT ANALYSIS (Pruning): Anomalous match: (id1=%s, '
            'matched_count1=%d) matched with (id2=%d, matched_count2=%d), '
            'threshold=%.2f.' % (testcase_1_id, project_counter[testcase_1_id],
                                 testcase_2_id, project_counter[testcase_2_id],
                                 threshold))
        continue

      testcase_1 = testcase_map[testcase_1_id]
      testcase_2 = testcase_map[testcase_2_id]

      if (matches_top_crash(testcase_1, top_crashes_by_project_and_platform) or
          matches_top_crash(testcase_2, top_crashes_by_project_and_platform)):
        logs.info(f'VARIANT ANALYSIS: {testcase_1_id} or {testcase_2_id} '
                  'is a top crash, skipping.')
        continue

      combine_testcases_into_group(testcase_1, testcase_2, testcase_map,
                                   'identical variant', group_map)


def _group_testcases_with_same_issues(testcase_map, group_map):
  """Group testcases that are associated with same underlying issue."""
  logs.info('Grouping based on same issues.')
  for testcase_1_id, testcase_1 in testcase_map.items():
    for testcase_2_id, testcase_2 in testcase_map.items():
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
                                   'same issue', group_map)


def _group_testcases_with_similar_states(testcase_map, group_map):
  """Group testcases with similar looking crash states."""
  logs.info('Grouping based on similar states.')
  for testcase_1_id, testcase_1 in testcase_map.items():
    for testcase_2_id, testcase_2 in testcase_map.items():
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

      # # Rule: Check both testcases regressed to the same revision range
      # # considering the same job type.
      # if (testcase_1.regression != testcase_2.regression and
      #     testcase_1.job_type == testcase_2.job_type):
      #   continue

      # Rule: Follow different comparison rules when crash types is one of the
      # ones that have unique crash state (custom ones specifically).
      if (testcase_1.crash_type in data_types.CRASH_TYPES_WITH_UNIQUE_STATE or
          testcase_2.crash_type in data_types.CRASH_TYPES_WITH_UNIQUE_STATE):

        # For grouping, make sure that both crash type and state match.
        if (testcase_1.crash_type != testcase_2.crash_type or
            testcase_1.crash_state != testcase_2.crash_state):
          continue

      else:
        # Rule: For functional bugs, compare for similar crash types.
        if not testcase_1.security_flag:
          crash_comparer = CrashComparer(testcase_1.crash_type, # --> ONLY QUERIES DB
                                         testcase_2.crash_type)
          if not crash_comparer.is_similar():
            continue

        # Rule: Check for crash state similarity.
        crash_comparer = CrashComparer(testcase_1.crash_state, # --> ONLY QUERIES DB
                                       testcase_2.crash_state)
        if not crash_comparer.is_similar():
          continue

      combine_testcases_into_group(testcase_1, testcase_2, testcase_map,
                                   'similar crashes', group_map)

# TODO: Make this function also remove single groups
def _shrink_large_groups_if_needed(testcase_map, group_map):
  """Shrinks groups that exceed a particular limit."""

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
    if len(testcases_in_group) <= GROUP_MAX_TESTCASE_LIMIT:
      continue

    if len(testcases_in_group) == 1:
      del group_map[testcases_in_group[0].group_id]
      testcases_in_group[0].group_id = 0
      testcases_in_group[0].is_leader = True

    testcases_in_group = sorted(testcases_in_group, key=_key_func)
    for testcase in testcases_in_group[:-GROUP_MAX_TESTCASE_LIMIT]:
      if testcase.issue_id:
        continue

      logs.warning(('Deleting testcase {testcase_id} due to overflowing group '
                    '{group_id}.').format(
                        testcase_id=testcase.id, group_id=testcase.group_id))
      TEST_DELETED_TCS.add(testcase.id)
      del testcase_map[testcase.id]
      remove_testcase_from_group(group_map, testcase)

def get_loaded_testcases():
  attr_filepath = os.path.join(os.getenv('PATH_TO_TCS', '.'), 'testcases_attributes.pkl')
  tcs_deleted_filepath = os.path.join(os.getenv('PATH_TO_TCS', '.'), 'testcases_deleted.pkl')

  if os.path.exists(tcs_deleted_filepath):
    with open(tcs_deleted_filepath, 'rb') as f:
      TEST_DELETED_TCS.update(pickle.load(f))

  if not os.path.exists(attr_filepath):
    logs.error(f'Loaded Testcases map not found - {attr_filepath}')
    return None

  with open(attr_filepath, 'rb') as f:
    testcase_map = pickle.load(f)

  return testcase_map

def group_testcases():
  """Group testcases based on rules like same bug numbers, similar crash
  states, etc."""
  # No-op to update/delete functions
  data_types.Testcase.put = noop
  data_types.Testcase.key.delete = noop

  testcase_map = get_loaded_testcases()
  if testcase_map is None:
    return

  if os.getenv("JUST_TEST", False):
    print(f'Testcase map size - {len(testcase_map)}')
    print(f'Testcase keys - {testcase_map.keys()}')
    print(f'Class Type - {type(list(testcase_map.values())[0])}')
    print(f'Testcase Job Type - {list(testcase_map.values())[0].job_type}')
    return

  group_map = {}
  _group_testcases_with_similar_states(testcase_map, group_map)
  _group_testcases_with_same_issues(testcase_map, group_map)
  _group_testcases_based_on_variants(testcase_map, group_map)
  _shrink_large_groups_if_needed(testcase_map, group_map)
  group_leader.choose(testcase_map, group_map)

def main():
  logs.configure('run_bot')
  try:
    logs.info('Grouping testcases.')
    group_testcases()
    logs.info('Grouping done.')
  except:
    logs.error('Error occurred while grouping test cases.')
    return False

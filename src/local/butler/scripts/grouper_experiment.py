# Copyright 2025 Google LLC
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
"""Script to run the grouper locally and store the results.

This is intended to run local experiments with the grouper to analyze its
outcome without touching production. For this case, the grouper code was
edited to remove all delete/put operations for testcases/groups.

Some other changes: the testcases loading step was separated from the grouping
in order to locally store a snapshot of their attributes; a new data structure
to represent the groups was added, making it easier to inspect why testcases
were grouped; and some global variables were added to configure the experiment.
It is expected that this become stale if the grouper code is modified a lot.
"""

import argparse
import collections
import datetime
import os
import pickle
import random
import re
import uuid
import json
import networkx as nx
from dataclasses import asdict
from dataclasses import dataclass

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from clusterfuzz._internal.cron import cleanup
from clusterfuzz._internal.cron import group_leader
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.issue_management import issue_tracker_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

FORWARDED_ATTRIBUTES = ('crash_state', 'crash_type', 'group_id',
                        'one_time_crasher_flag', 'project_name',
                        'security_flag', 'timestamp', 'job_type', 'regression',
                        'crash_revision', 'overridden_fuzzer_name')

GROUP_MAX_TESTCASE_LIMIT = 25

VARIANT_CRASHES_IGNORE = re.compile(
    r'^(Out-of-memory|Timeout|Missing-library|Data race|GPU failure)')

VARIANT_STATES_IGNORE = re.compile(r'^NULL$')

VARIANT_THRESHOLD_PERCENTAGE = 0.2
VARIANT_MIN_THRESHOLD = 5
VARIANT_MAX_THRESHOLD = 10

TOP_CRASHES_LIMIT = 10

# Folder/file names.
TESTCASES_DIR_PREFIX = 'testcases_snapshot'
TESTCASES_ATTR_FILE = 'testcases_attributes'
TESTCASES_DUP_DELETED_FILE = 'testcases_duplicated'

REVISION_RANGE_FIX = False


def noop(self, *args, **kwargs):  #pylint: disable=unused-argument
  pass


class TestcaseAttributes:
  """Testcase attributes used for grouping."""

  __slots__ = ('id', 'is_leader', 'issue_id') + FORWARDED_ATTRIBUTES

  def __init__(self, testcase_id: int):
    self.id = testcase_id
    self.is_leader = True
    self.issue_id = None


class GroupAttributes:
  """Groups Attributes."""

  __slots__ = ('id', 'leader_id', 'group_issue_id', 'testcases')

  def __init__(self, group_id: int):
    self.id = group_id
    self.leader_id = None
    self.group_issue_id = None
    self.testcases = nx.Graph()

  def __len__(self):
    return self.testcases.number_of_nodes()

  def add_connection(self, tc1: int, tc2: int, reason: str) -> None:
    self.testcases.add_edge(tc1, tc2, reason=reason)

  def remove_testcase(self, tc: int) -> None:
    self.testcases.remove_node(tc)

  def merge_group(self, group: nx.Graph):
    self.testcases = nx.compose(self.testcases, group)


def add_testcases_to_group_map(group_map: dict[int, GroupAttributes],
                               group_id: int, tc1: int, tc2: int,
                               reason: str) -> None:
  """Add a new testcase grouping to an existing/new group in the map."""
  if group_id not in group_map:
    group_map[group_id] = GroupAttributes(group_id)
  group_map[group_id].add_connection(tc1, tc2, reason)


def remove_testcase_from_group(group_map: dict[int, GroupAttributes],
                               testcase: TestcaseAttributes) -> None:
  """Remove a testcase from its group in the map."""
  group_id = testcase.group_id
  tc_id = testcase.id
  if group_id not in group_map:
    return
  group_map[group_id].remove_testcase(tc_id)


def merge_testcases_groups(group_map: dict[int, GroupAttributes],
                           group_to_move: int, group_to_reuse: int):
  """Merge group_to_move into group_to_reuse."""
  group_map[group_to_reuse].merge_group(group_map[group_to_move].testcases)


def combine_testcases_into_group(
    testcase_1: TestcaseAttributes, testcase_2: TestcaseAttributes,
    testcase_map: dict[int, TestcaseAttributes], reason: str,
    group_map: dict[int, GroupAttributes]) -> None:
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
    add_testcases_to_group_map(group_map, new_group_id, testcase_1.id,
                               testcase_2.id, reason)
    return

  # If one of the testcase has a group id, then assign the other to reuse that
  # group id.
  if testcase_1.group_id and not testcase_2.group_id:
    testcase_2.group_id = testcase_1.group_id
    add_testcases_to_group_map(group_map, testcase_1.group_id, testcase_1.id,
                               testcase_2.id, reason)
    return
  if testcase_2.group_id and not testcase_1.group_id:
    testcase_1.group_id = testcase_2.group_id
    add_testcases_to_group_map(group_map, testcase_2.group_id, testcase_1.id,
                               testcase_2.id, reason)
    return

  # If both the testcase have their own groups, then just merge the two groups
  # together and reuse one of their group ids.
  group_id_to_reuse = testcase_1.group_id
  group_id_to_move = testcase_2.group_id
  testcase_2.group_id = group_id_to_reuse
  add_testcases_to_group_map(group_map, group_id_to_reuse, testcase_1.id,
                             testcase_2.id, reason)
  merge_testcases_groups(group_map, group_id_to_move, group_id_to_reuse)

  moved_testcase_ids = []
  for testcase in testcase_map.values():
    if testcase.group_id == group_id_to_move:
      testcase.group_id = group_id_to_reuse
      moved_testcase_ids.append(str(testcase.id))
  if group_id_to_reuse != group_id_to_move:
    del group_map[group_id_to_move]
    logs.info(f'Deleted group: {group_id_to_move}')

  logs.info(f'Merged group {group_id_to_move} into {group_id_to_reuse}: ' +
            'moved testcases: ' + ', '.join(moved_testcase_ids))


def _get_new_group_id():
  """Get a new group id for testcase grouping."""
  return random.randint(1, 2**63 - 1)


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
      candidate_variant = data_handler.get_testcase_variant(
          testcase_1_id, testcase_2.job_type)

      if (not candidate_variant or
          not is_same_variant(candidate_variant, testcase_2)):
        continue

      current_project = testcase_1.project_name
      grouping_candidates[current_project].append((testcase_1_id,
                                                   testcase_2_id))

  # DISABLE IT FOR THE GROUPER EXPERIMENTS AS IT TRIES TO ACCESS BIG QUERY.
  # Top crashes are usually startup crashes, so don't group them.
  # top_crashes_by_project_and_platform = None
  # top_crashes_by_project_and_platform = (
  #     cleanup.get_top_crashes_for_all_projects_and_platforms(
  #         limit=TOP_CRASHES_LIMIT))

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

      # DISABLE IT FOR THE GROUPER EXPERIMENTS AS IT TRIES TO ACCESS BIG QUERY.
      # if (matches_top_crash(testcase_1, top_crashes_by_project_and_platform) or
      #     matches_top_crash(testcase_2, top_crashes_by_project_and_platform)):
      #   logs.info(f'VARIANT ANALYSIS: {testcase_1_id} or {testcase_2_id} '
      #             'is a top crash, skipping.')
      #   continue

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


def _group_testcases_with_similar_states(testcase_map, group_map,
                                         tcs_revision_range):
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
          crash_comparer = CrashComparer(testcase_1.crash_type,
                                         testcase_2.crash_type,
                                         experiment_config.crash_comparer_threshold,
                                         experiment_config.same_frame_threshold)
          if not crash_comparer.is_similar():
            continue

        # Rule: Check for crash state similarity.
        crash_comparer = CrashComparer(testcase_1.crash_state,
                                       testcase_2.crash_state,
                                       experiment_config.crash_comparer_threshold,
                                       experiment_config.same_frame_threshold)
        if not crash_comparer.is_similar():
          continue

      # Rule: Check both testcases regressed to the same revision range
      # considering the same job type.
      # TODO(vtcosta): Add a check for the same fuzz target if needed.
      # TODO(vtcosta): Add check for valid regressed revision range.
      if REVISION_RANGE_FIX:
        if (testcase_1.regression != testcase_2.regression and
            testcase_1.job_type == testcase_2.job_type):
          tcs_revision_range.add((testcase_1_id, testcase_2_id))
          continue

      combine_testcases_into_group(testcase_1, testcase_2, testcase_map,
                                   'similar crashes', group_map)


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


def _shrink_large_groups_if_needed(testcase_map, group_map, tcs_deleted):
  """Shrinks groups that exceed a particular limit."""

  def _key_func(testcase):
    weight = 0
    if not testcase.one_time_crasher_flag:
      weight |= 2**1
    if testcase.issue_id:
      weight |= 2**2
    return weight

  group_max_size = experiment_config.group_max_size
  group_id_with_testcases_map = {}
  for testcase in testcase_map.values():
    if not testcase.group_id:
      continue

    if testcase.group_id not in group_id_with_testcases_map:
      group_id_with_testcases_map[testcase.group_id] = [testcase]
    else:
      group_id_with_testcases_map[testcase.group_id].append(testcase)

  for testcases_in_group in group_id_with_testcases_map.values():
    if len(testcases_in_group) <= group_max_size:
      continue

    testcases_in_group = sorted(testcases_in_group, key=_key_func)
    for testcase in testcases_in_group[:-group_max_size]:
      if testcase.issue_id:
        continue

      logs.warning(('Deleting testcase {testcase_id} due to overflowing group '
                    '{group_id}.').format(
                        testcase_id=testcase.id, group_id=testcase.group_id))
      tcs_deleted.add(testcase.id)
      remove_testcase_from_group(group_map, testcase)
      del testcase_map[testcase.id]


def sample_testcases(testcase_map, sample_size=100):
  """Retrieve a random sample from testcases attributes."""
  chosen_tcs = random.sample(list(testcase_map.keys()), sample_size)
  sample_testcase_map = {tc_id: testcase_map[tc_id] for tc_id in chosen_tcs}
  return sample_testcase_map


def get_loaded_testcases(local_dir: str):
  """Get local stored testcases attributes and list of deleted dup testcases."""
  # get latest testcases snapshot.
  latest_date = None
  testcases_snapshot = None
  for snapshot_dir in os.listdir(local_dir):
    if not snapshot_dir.startswith(TESTCASES_DIR_PREFIX):
      continue
    date_str = snapshot_dir.removeprefix(f'{TESTCASES_DIR_PREFIX}_')
    date_file = datetime.datetime.strptime(date_str, '%d_%m_%Y')
    if latest_date is None or date_file > latest_date:
      latest_date = date_file
      testcases_snapshot = snapshot_dir
  if not testcases_snapshot:
    return None, None, None
  print(f'Retrieving testcases from {testcases_snapshot}')

  attr_filepath = os.path.join(local_dir, testcases_snapshot,
                               f'{TESTCASES_ATTR_FILE}.pkl')
  tcs_duplicated_filepath = os.path.join(local_dir, testcases_snapshot,
                                         f'{TESTCASES_DUP_DELETED_FILE}.pkl')
  testcases_duplicated = set()
  testcase_map = None

  if os.path.exists(tcs_duplicated_filepath):
    with open(tcs_duplicated_filepath, 'rb') as f:
      testcases_duplicated = pickle.load(f)

  if os.path.exists(attr_filepath):
    with open(attr_filepath, 'rb') as f:
      testcase_map = pickle.load(f)

  return testcases_snapshot, testcase_map, testcases_duplicated


def _get_group_testcases(group_id):
  """Returns the testcases from a group id."""
  keys = ndb_utils.get_all_from_query(
      data_types.Testcase.query(data_types.Testcase.group_id == group_id),
      keys_only=True)
  for key in keys:
    yield key.id()


def load_testcases(local_dir: str):
  """Load and store testcases attributes used for grouping."""
  testcase_map = {}
  cached_issue_map = {}
  testcases_duplicated = set()

  if experiment_config.only_group_id:
    group_id = experiment_config.only_group_id
    logs.info(f'Using only testcases from original group id: {group_id}')
    testcase_it = _get_group_testcases(group_id)
  else:
    logs.info(f'Using all open testcases.')
    testcase_it = data_handler.get_open_testcase_id_iterator()

  for testcase_id in testcase_it:
    if (experiment_config.max_tcs_to_pickle > 0
        and len(testcase_map) == experiment_config.max_tcs_to_pickle):
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
      testcases_duplicated.add(testcase_id)
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

      if not experiment_config.use_issue_tracker:
        testcase_attributes.issue_id = issue_id
        continue

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

  print(f'Loaded {len(testcase_map)} unique testcases and '
        f'{len(testcases_duplicated)} were duplicated.')
  # Store Testcases attributes locally.
  now = datetime.datetime.strftime(datetime.datetime.now(), '%d_%m_%Y')
  testcases_dir = os.path.join(local_dir, f'{TESTCASES_DIR_PREFIX}_{now}')
  print(f'Storing testcases data at: {testcases_dir}')
  if not os.path.exists(testcases_dir):
    os.mkdir(testcases_dir)

  with open(os.path.join(testcases_dir, f'{TESTCASES_ATTR_FILE}.pkl'), 'wb') as f:
    pickle.dump(testcase_map, f)

  with open(os.path.join(testcases_dir, f'{TESTCASES_DUP_DELETED_FILE}.pkl'), 'wb') as f:
    pickle.dump(testcases_duplicated, f)

  with open(os.path.join(testcases_dir, 'config.txt'), 'w') as f:
    exp_cfg = json.dumps(asdict(experiment_config), indent=2)
    f.write(exp_cfg)
    f.write('\n')


def group_testcases(local_dir: str):
  """Group testcases based on rules like same bug numbers, similar crash
  states, etc."""

  testcases_snapshot, testcase_map, _ = get_loaded_testcases(local_dir)
  if testcases_snapshot is None or testcase_map is None:
    logs.error('Missing loaded testcases attributes.')
    return

  group_map = {}
  tcs_revision_range = set()
  tcs_deleted = set()

  if experiment_config.sample_to_group > 0:
    testcase_map = sample_testcases(
        testcase_map, sample_size=experiment_config.sample_to_group)

  if experiment_config.reset_groups or experiment_config.reset_issues:
    for testcase in testcase_map.values():
      testcase.group_id = 0 if experiment_config.reset_groups else testcase.group_id
      testcase.bug_information = '' if experiment_config.reset_issues else testcase.bug_information

  else:
    # Currently, there isn't an easy way to get which/why TCs were grouped. So,
    # if groups are not reset, we only create them and add the TCs without
    # connections, which results in the group graph not being fully connected.
    for testcase in testcase_map.values():
      group_id = testcase.group_id
      if not group_id:
        continue
      if group_id not in group_map:
        group_map[group_id] = GroupAttributes(group_id)
      group_map[group_id].add_testcase(testcase.id)

  _group_testcases_with_similar_states(testcase_map, group_map,
                                       tcs_revision_range)
  _group_testcases_with_same_issues(testcase_map, group_map)
  if experiment_config.use_variant:
    _group_testcases_based_on_variants(testcase_map, group_map)
  _shrink_large_groups_if_needed(testcase_map, group_map, tcs_deleted)
  group_leader.choose(testcase_map, group_map)

  for gid, group in group_map.items():
    # If this group id is used by only one testcase, then remove it.
    if len(group) == 1:
      testcase_id = list(group.testcases.nodes)[0]
      testcase_map[testcase_id].group_id = 0
      testcase_map[testcase_id].is_leader = True
      del group[gid]
      continue
    # Update group issue id to be lowest issue id in the entire group.
    group_bug_information = 0
    for tc_id in group.testcases.nodes:
      issue_id = testcase_map[tc_id].issue_id
      if issue_id is None:
        continue
      if not group_bug_information or group_bug_information > issue_id:
        group_bug_information = issue_id
    group.group_issue_id = group_bug_information

  # Add a map for querying {testcase id -> group id} to avoid overwriting the
  # testcase_map.
  tc_to_group_map = {}
  for tc_id, tc_attr in testcase_map.items():
    tc_to_group_map[tc_id] = tc_attr.group_id

  snapshot_date = testcases_snapshot.removeprefix(f'{TESTCASES_DIR_PREFIX}_')
  experiment_id = str(uuid.uuid4())[:8]
  experiment_name = experiment_config.experiment_name or 'common'
  grouper_foldername = f'experiment_snapshot-{snapshot_date}_{experiment_name}_{experiment_id}'
  print(f'Saving grouping experiment info at: "{grouper_foldername}"')

  grouper_dir = os.path.join(local_dir, grouper_foldername)
  if not os.path.exists(grouper_dir):
    os.mkdir(grouper_dir)

  group_map_filepath = os.path.join(grouper_dir, 'groups_map.pkl')
  with open(group_map_filepath, 'wb') as f:
    pickle.dump(group_map, f)

  tcs_deleted_filepath = os.path.join(grouper_dir,
                                      'testcases_deleted_grouping.pkl')
  with open(tcs_deleted_filepath, 'wb') as f:
    pickle.dump(tcs_deleted, f)

  tc_to_group_filepath = os.path.join(grouper_dir, 'testcase_to_group_map.pkl')
  with open(tc_to_group_filepath, 'wb') as f:
    pickle.dump(tc_to_group_map, f)

  if REVISION_RANGE_FIX:
    revision_range_filepath = os.path.join(grouper_dir,
                                           'testcases_revision_range.pkl')
    with open(revision_range_filepath, 'wb') as f:
      pickle.dump(tcs_revision_range, f)


def _parse_grouper_args(args):
  """Parse grouper arguments."""
  parser = argparse.ArgumentParser(description='Grouper experiment.')
  parser.add_argument('--step', nargs='*', default=['load', 'group'], choices=['load', 'group'])
  parser.add_argument('--exp_name', type=str, default=None)
  parser.add_argument('--use_group', type=int, default=0)
  parser.add_argument('--max_tcs', type=int, default=-1)
  parser.add_argument('--sample_to_group', type=int, default=-1)
  parser.add_argument('--reset_groups', action='store_true')
  parser.add_argument('--reset_issues', action='store_true')
  parser.add_argument('--use_variant', action='store_true')
  parser.add_argument('--group_max', type=int, default=25)
  parser.add_argument('--crash_threshold', type=float, default=0.8)
  parser.add_argument('--same_frames', type=int, default=2)
  parser.add_argument('--use_issue_tracker', action='store_true')

  args = ['--'+arg for arg in args]
  return parser.parse_args(args)

@dataclass
class ExperimentConfig():
  step: list[str]
  experiment_name: str
  only_group_id: int
  max_tcs_to_pickle: int
  sample_to_group: int
  reset_groups: bool
  reset_issues: bool
  use_variant: bool
  group_max_size: int
  crash_comparer_threshold: float
  same_frame_threshold: int
  config_dir: str
  use_issue_tracker: bool


def set_experiment_config(parsed_args, config_dir):
  """Set config."""
  experiment_config = ExperimentConfig(
      step=parsed_args.step,
      experiment_name=parsed_args.exp_name,
      only_group_id= parsed_args.use_group,
      max_tcs_to_pickle=parsed_args.max_tcs,
      sample_to_group=parsed_args.sample_to_group,
      reset_groups=parsed_args.reset_groups,
      reset_issues=parsed_args.reset_issues,
      use_variant=parsed_args.use_variant,
      group_max_size=parsed_args.group_max,
      crash_comparer_threshold=parsed_args.crash_threshold,
      same_frame_threshold=parsed_args.same_frames,
      use_issue_tracker=parsed_args.use_issue_tracker,
      config_dir=config_dir)
  return experiment_config


def execute(args):
  """Load testcases and/or run grouper locally."""
  parsed_args = _parse_grouper_args(args.script_args)

  global experiment_config
  experiment_config = set_experiment_config(parsed_args, args.config_dir)
  print()
  print(f'#### Experiment Config #####')
  print(json.dumps(asdict(experiment_config), indent=2))
  print(f'############################\n')

  # Since this is intended to run locally, force log to console.
  environment.set_bot_environment()
  os.environ['LOG_TO_CONSOLE'] = 'True'
  os.environ['LOG_TO_GCP'] = ''
  os.environ['LOCAL_DEVELOPMENT'] = 'True'
  logs.configure('run_bot')

  # No-op to update/delete functions - just for safety
  data_types.Testcase.put = noop
  data_types.Testcase.key.delete = noop

  local_dir = os.path.join(os.getenv('PATH_TO_LOCAL_DATA', '.'))
  print(
      f'Storing data at: {local_dir} - Set $PATH_TO_LOCAL_DATA to change dir.')
  if not os.path.exists(local_dir):
    os.mkdir(local_dir)

  if 'load' in experiment_config.step:
    try:
      logs.info('Loading testcases attributes.')
      load_testcases(local_dir)
      logs.info(f'Loading done.')
    except Exception as e:
      logs.error(f'Error occurred while loading test cases - {e}.')
      return

  if 'group' in experiment_config.step:
    try:
      logs.info('Grouping testcases.')
      group_testcases(local_dir)
      logs.info('Grouping done.')
    except Exception as e:
      logs.error(f'Error occurred while grouping test cases - {e}.')
      return

# How to run:
# DEBUG_TASK=True LOG_TO_CONSOLE=True LOG_TO_GCP=""
# PATH_TO_LOCAL_DATA="/usr/local/google/home/vtcosta/Data/grouper_experiment"
# python butler.py run grouper_experiment --script_args step=group exp_name=test
# use_variant crash_threshold=0.9
# --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
#
# SA (for issue tracker): cluster-fuzz@appspot.gserviceaccount.com

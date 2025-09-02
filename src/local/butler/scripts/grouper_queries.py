import collections
import os
import pickle
import random
import re

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
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer


def groups_fixed_states():
  import squarify
  import networkx as nx
  from matplotlib_venn import venn3, venn2
  from matplotlib_venn.layout.venn3 import DefaultLayoutAlgorithm
  import matplotlib.pyplot as plt

  local_dir = os.getenv('PATH_TO_LOCAL_DATA', '.')
  storage_dir = os.path.join(local_dir, 'groups_with_diff_fixed_states') 
  if not os.path.exists(storage_dir):
    os.mkdir(storage_dir)

  # Check the amount of testcases fixed/NA/not fixed in groups
  groups_with_fixed_testcases = set()  
  fixed_file = os.path.join(storage_dir, 'groups_with_fixed.pkl')
  groups_with_na_testcases = set()
  na_file = os.path.join(storage_dir, 'groups_with_na.pkl')
  groups_with_not_fixed_testcases = set()
  not_fixed_file = os.path.join(storage_dir, 'groups_with_not_fixed.pkl')

  groups_fixed_revision_range = collections.defaultdict(list)
  groups_fixed_range_file = os.path.join(storage_dir, 'groups_fixed_range.pkl')

  if not os.path.exists(fixed_file):
    grouped_testcases = data_types.Testcase.query(data_types.Testcase.group_id != 0)
    count = 0
    for testcase in grouped_testcases:
      if not testcase.fixed:
        groups_with_not_fixed_testcases.add(testcase.group_id)
      elif testcase.fixed == 'NA':
        groups_with_na_testcases.add(testcase.group_id)
      else:
        groups_with_fixed_testcases.add(testcase.group_id)
        groups_fixed_revision_range[testcase.group_id].append(testcase.fixed)
      count += 1
      if count % 100 == 0:
        print(f'{count} testcases analyzed.')

    with open(fixed_file, 'wb') as f:
      pickle.dump(groups_with_fixed_testcases, f)

    with open(na_file, 'wb') as f:
      pickle.dump(groups_with_na_testcases, f)

    with open(not_fixed_file, 'wb') as f:
      pickle.dump(groups_with_not_fixed_testcases, f)

    with open(groups_fixed_range_file, 'wb') as f:
      pickle.dump(groups_fixed_revision_range, f)

    return

  else:
    print(f'Loading from existing files.')
    with open(fixed_file, 'rb') as f:
      groups_with_fixed_testcases = pickle.load(f)

    with open(na_file, 'rb') as f:
      groups_with_na_testcases = pickle.load(f)

    with open(not_fixed_file, 'rb') as f:
      groups_with_not_fixed_testcases = pickle.load(f)

    with open(groups_fixed_range_file, 'rb') as f:
      groups_fixed_revision_range = pickle.load(f)


  venn2((groups_with_not_fixed_testcases.difference(groups_with_na_testcases), groups_with_fixed_testcases.difference(groups_with_na_testcases)), ('Not fixed', 'Fixed'), layout_algorithm=DefaultLayoutAlgorithm(fixed_subset_sizes=(1,1,1,1,1,1,1)))
  plt.savefig('groups_fixed_venn_2.png')
  plt.clf()
  venn3((groups_with_not_fixed_testcases, groups_with_na_testcases, groups_with_fixed_testcases), ('Not fixed', 'NA', 'Fixed'), layout_algorithm=DefaultLayoutAlgorithm(fixed_subset_sizes=(1,1,1,1,1,1,1)))
  plt.savefig('groups_fixed_venn_3.png')
  plt.clf()

  num_of_groups = len(groups_with_fixed_testcases.union(groups_with_na_testcases).union(groups_with_not_fixed_testcases))
  print(f'# Total groups: {num_of_groups}')

  only_fixed = groups_with_fixed_testcases.difference(groups_with_na_testcases).difference(groups_with_not_fixed_testcases)
  only_na = groups_with_na_testcases.difference(groups_with_fixed_testcases).difference(groups_with_not_fixed_testcases)
  only_not_fixed = groups_with_not_fixed_testcases.difference(groups_with_fixed_testcases).difference(groups_with_na_testcases)
  print(f'# Groups with only fixed: {len(only_fixed)}')
  print(f'# Groups with only NA: {len(only_na)}')
  print(f'# Groups with only not fixed: {len(only_not_fixed)}')


  # fixed_and_not_fixed = groups_with_fixed_testcases.intersection(groups_with_not_fixed_testcases)
  # fixed_and_na = groups_with_fixed_testcases.intersection(groups_with_na_testcases)
  # not_fixed_and_na = groups_with_not_fixed_testcases.intersection(groups_with_na_testcases)
  # print(f'# Groups with fixed and not fixed: {len(fixed_and_not_fixed)}')
  # print(f'# Groups with fixed and NA: {len(fixed_and_na)}')
  # print(f'# Groups with not fixed and NA: {len(not_fixed_and_na)}')


  print(f'-'*30)
  not_fixed_and_fixed = groups_with_not_fixed_testcases.intersection(groups_with_fixed_testcases).difference(groups_with_na_testcases)
  not_fixed_and_na = groups_with_not_fixed_testcases.intersection(groups_with_na_testcases).difference(groups_with_fixed_testcases)
  not_fixed_and_na_and_fixed = groups_with_not_fixed_testcases.intersection(groups_with_na_testcases).intersection(groups_with_fixed_testcases)


  print(f'# From {len(groups_with_not_fixed_testcases)} groups with at least one open testcase, '
        f'{len(only_not_fixed)} have only open testcases, {len(not_fixed_and_fixed)} have only open and fixed testcases, '
        f'{len(not_fixed_and_na)} have open and NA testcases, {len(not_fixed_and_na_and_fixed)} have open, fixed and NA testcases.')

  sizes = [len(only_not_fixed), len(not_fixed_and_fixed), len(not_fixed_and_na), len(not_fixed_and_na_and_fixed)]
  labels = ['Only Open', 'Open and fixed', 'Open and NA', 'Open, fixed and NA']
  labels = [f'{l}\n{s}' for l, s in zip(labels, sizes)]
  squarify.plot(sizes=sizes, label=labels, alpha=0.8)
  plt.savefig('groups_treemap.png')
  plt.clf()

  # print(list(groups_fixed_revision_range.items())[0])
  revisions_per_group = []
  count_1 = 0
  count_n = 0
  for group_id, group_revs in groups_fixed_revision_range.items():
    # Look only for groups with fixed testcases.
    if group_id not in only_fixed:
      continue
    # Remove groups with only 1 testcase.
    if len(group_revs) <= 1:
      continue

    group_unique_revs = set(group_revs)
    # Remove groups with fixed rev 'Yes' (custom builds).
    if 'Yes' in group_unique_revs:
      continue

    if len(group_unique_revs) == 1:
      # if count_1 % 500:
      #   print(group_id)
      count_1 += 1
    else:
      count_n += 1

    revisions_per_group.append(len(group_unique_revs))

  print(f'# Groups with all fixed in same revision: {count_1} (of {count_n + count_1})')
  plt.figure(figsize=(12, 8))
  plt.hist(revisions_per_group, bins=50)
  plt.xlabel('Distinct fixed revision ranges.')
  plt.ylabel('Count')
  plt.title('Distribution of the number of distinct fixed revisions in closed groups.')
  plt.tight_layout()
  plt.savefig('revision_range_dist.png')


def get_largest_groups():
  group_sizes = collections.Counter()
  ungrouped = 0
  for testcase_id in data_handler.get_open_testcase_id_iterator():
    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except:
      continue
    if testcase.group_id == 0:
      ungrouped += 1
    else:
      group_sizes[testcase.group_id] += 1

  print(f'\nTop 15 larger groups: {group_sizes.most_common(15)}')
  print(f'\n # Ungrouped testcases: {ungrouped}')

def execute(args):
  """Load testcases and/or run grouper locally."""
  # groups_fixed_states()
  get_largest_groups()

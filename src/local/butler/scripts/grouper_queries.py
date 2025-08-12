import collections
import os
import pickle
import random
import re
import networkx as nx
# from matplotlib_venn import venn3, venn2
# # from matplotlib_venn.layout.venn2 import DefaultLayoutAlgorithm
# from matplotlib_venn.layout.venn3 import DefaultLayoutAlgorithm
import matplotlib.pyplot as plt

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

  groups_fixed_revision_range = collections.defaultdict(set)
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
        groups_fixed_revision_range[testcase.group_id].add(testcase.fixed)
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


  # venn2((groups_with_not_fixed_testcases.difference(groups_with_na_testcases), groups_with_fixed_testcases.difference(groups_with_na_testcases)), ('Not fixed', 'Fixed'), layout_algorithm=DefaultLayoutAlgorithm(fixed_subset_sizes=(1,1,1,1,1,1,1)))
  # plt.savefig('groups_fixed_venn_2.png')

  # venn3((groups_with_not_fixed_testcases, groups_with_na_testcases, groups_with_fixed_testcases), ('Not fixed', 'NA', 'Fixed'), layout_algorithm=DefaultLayoutAlgorithm(fixed_subset_sizes=(1,1,1,1,1,1,1)))
  # plt.savefig('groups_fixed_venn_3.png')

  num_of_groups = len(groups_with_fixed_testcases.union(groups_with_na_testcases).union(groups_with_not_fixed_testcases))
  print(f'# Total groups: {num_of_groups}')

  only_fixed = groups_with_fixed_testcases.difference(groups_with_na_testcases).difference(groups_with_not_fixed_testcases)
  only_na = groups_with_na_testcases.difference(groups_with_fixed_testcases).difference(groups_with_not_fixed_testcases)
  only_not_fixed = groups_with_not_fixed_testcases.difference(groups_with_fixed_testcases).difference(groups_with_na_testcases)
  print(f'# Groups with only fixed: {len(only_fixed)}')
  print(f'# Groups with only NA: {len(only_na)}')
  print(f'# Groups with only not fixed: {len(only_not_fixed)}')


  fixed_and_not_fixed = groups_with_fixed_testcases.intersection(groups_with_not_fixed_testcases)
  fixed_and_na = groups_with_fixed_testcases.intersection(groups_with_na_testcases)
  not_fixed_and_na = groups_with_not_fixed_testcases.intersection(groups_with_na_testcases)
  print(f'# Groups with fixed and not fixed: {len(fixed_and_not_fixed)}')
  print(f'# Groups with fixed and NA: {len(fixed_and_na)}')
  print(f'# Groups with not fixed and NA: {len(not_fixed_and_na)}')


def execute(args):
  """Load testcases and/or run grouper locally."""
  groups_fixed_states()

### ADD ANALYSIS FOR FIXED IN THE SAME FIXED REVISION RANGE
### ADD analysis for the top jobs causing issues
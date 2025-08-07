import collections
import os
import pickle
import random
import re
import networkx as nx

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


def execute(args):
  """Load testcases and/or run grouper locally."""

  local_dir = os.getenv('PATH_TO_LOCAL_DATA', '.')
  storage_dir = os.path.join(local_dir, 'groups_with_diff_fixed_states') 
  if not os.path.exists(storage_dir):
    os.mkdir(storage_dir)

  # Check the amount of testcases fixed/NA/not fixed in groups
  groups_with_fixed_testcases = set()
  groups_with_na_testcases = set()
  groups_with_not_fixed_testcases = set()
  grouped_testcases = data_types.Testcase.query(data_types.Testcase.group_id != 0)
  count = 0
  for testcase in grouped_testcases:
    if not testcase.fixed:
      groups_with_not_fixed_testcases.add(testcase.group_id)
    elif testcase.fixed == 'NA':
      groups_with_na_testcases.add(testcase.group_id)
    else:
      groups_with_fixed_testcases.add(testcase.group_id)
    count += 1
    if count % 100 == 0:
      print(f'{count} testcases analyzed.')

  with open(os.path.join(storage_dir, 'groups_with_fixed.pkl'), 'wb') as f:
    pickle.dump(groups_with_fixed_testcases, f)

  with open(os.path.join(storage_dir, 'groups_with_na.pkl'), 'wb') as f:
    pickle.dump(groups_with_na_testcases, f)

  with open(os.path.join(storage_dir, 'groups_with_not_fixed.pkl'), 'wb') as f:
    pickle.dump(groups_with_not_fixed_testcases, f)


  only_fixed = groups_with_fixed_testcases.difference(groups_with_na_testcases).difference(groups_with_not_fixed_testcases)
  only_na = groups_with_na_testcases.difference(groups_with_fixed_testcases).difference(groups_with_not_fixed_testcases)
  only_not_fixed = groups_with_not_fixed_testcases.difference(groups_with_fixed_testcases).difference(groups_with_na_testcases)
  print(f'# Groups with only fixed: {only_fixed}')
  print(f'# Groups with only NA: {only_na}')
  print(f'# Groups with only not fixed: {only_not_fixed}')


  fixed_and_not_fixed = groups_with_fixed_testcases.intersection(groups_with_not_fixed_testcases)
  fixed_and_na = groups_with_fixed_testcases.intersection(groups_with_na_testcases)
  not_fixed_and_na = groups_with_not_fixed_testcases.intersection(groups_with_na_testcases)
  print(f'# Groups with fixed and not fixed: {fixed_and_not_fixed}')
  print(f'# Groups with fixed and NA: {fixed_and_na}')
  print(f'# Groups with not fixed and NA: {not_fixed_and_na}')

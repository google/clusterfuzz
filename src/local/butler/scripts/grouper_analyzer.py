import collections
import os
import pickle
import random
import re
import networkx as nx
import statistics

from .grouper_experiment import GROUPS_MAP_FILE
from .grouper_experiment import TESTCASES_DELETED_GROUP_FILE
from .grouper_experiment import TESTCASES_TO_GROUP_FILE
from .grouper_experiment import get_loaded_testcases

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


# GROUPER_DIR = '/usr/local/google/home/vtcosta/Data/grouper/'

# def get_grouper_data(local_dir='.', grouper_foldername='groups'):
#   tcs_map_fp = os.path.join(local_dir, 'testcases_attributes.pkl')
#   with open(tcs_map_fp, 'rb') as f:
#     tcs_map = pickle.load(f)

#   tcs_dup_fp = os.path.join(local_dir, 'testcases_duplicated.pkl')
#   with open(tcs_dup_fp, 'rb') as f:
#     tcs_dup = pickle.load(f)

#   gps_map_fp = os.path.join(local_dir, grouper_foldername, 'group_map.pkl')
#   with open(gps_map_fp, 'rb') as f:
#     gps_map = pickle.load(f)

#   tcs_del_grp_fp = os.path.join(local_dir, grouper_foldername, 'testcases_deleted_grouping.pkl')
#   with open(tcs_del_grp_fp, 'rb') as f:
#     tcs_del_grps = pickle.load(f)

#   tcs_to_grp_map_fp = os.path.join(local_dir, grouper_foldername, 'testcase_to_group_map.pkl')
#   with open(tcs_to_grp_map_fp, 'rb') as f:
#     tcs_to_grp_map = pickle.load(f)

#   return tcs_map, tcs_dup, gps_map, tcs_del_grps, tcs_to_grp_map

# def get_group_size_stats(group_map):
#   sizes = []
#   for group in group_map.values():
#     sizes.append(len(group.testcases))

#   mean = round(statistics.mean(sizes), 2)
#   median = round(statistics.median(sizes), 2)
#   quantiles = [round(q, 2) for q in statistics.quantiles(sizes, n=10)]

#   stats_str = f'Mean: {mean}, Median: {median}, Quantiles (10): {quantiles}'
#   return stats_str


# def execute_legacy(args):
#   """Legacy: Analyze result from grouper."""

#   local_dir = os.path.join(os.getenv('PATH_TO_LOCAL_DATA', GROUPER_DIR), 'grouper_data')
#   print(
#       f'Loading data from: {local_dir} - Set $PATH_TO_LOCAL_DATA to change dir.')

#   # Since this is intended to run locally, force log to console.
#   environment.set_bot_environment()
#   os.environ['LOG_TO_CONSOLE'] = 'True'
#   os.environ['LOCAL_DEVELOPMENT'] = 'True'
#   os.environ['LOG_TO_GCP'] = ''
#   logs.configure('run_bot')

#   tcs_map, tcs_dup, gps_map, tcs_del_grps, tcs_to_grp_map = get_grouper_data(local_dir, 'groups_variant')
#   print(f'\n\n## Analysis results:\n')
#   print(f'### Total TCs analyzed: {len(tcs_map)}.')
#   print()
#   print(f'### Duplicated TCs deleted: {len(tcs_dup)}.')
#   print()
#   print(f'### Groups: {len(gps_map)}.')
#   print()
#   print(f'### Groups sizes stats: {get_group_size_stats(gps_map)}')
#   print()
#   print(f'### TCs deleted due to group overflow: {len(tcs_del_grps)}.')
#   print()

#   grouped = 0
#   ungrouped = 0
#   for grp_id in tcs_to_grp_map.values():
#     if grp_id == 0:
#       ungrouped += 1
#     else:
#       grouped += 1

#   print(f'### Potential bugs filed, i.e., ungrouped ({ungrouped}) + groups ({len(gps_map)}): {len(gps_map) + ungrouped}')



def get_testcase_data(local_dir: str, snapshot='latest'):
  return get_loaded_testcases(local_dir)


def get_groups_experiments_data(local_dir: str, snapshot_date: str | None = None):
  group_experiments = {}
  files_to_read = [GROUPS_MAP_FILE, TESTCASES_DELETED_GROUP_FILE, TESTCASES_TO_GROUP_FILE]
  pattern = re.compile(r'^experiment_snapshot-(\d{2}_\d{2}_\d{4})_(.+?)_([0-9a-f]{8})$')
  for group_dir in os.listdir(local_dir):
    match_dir = pattern.match(group_dir)
    if not match_dir:
      print(f'Not matched: {group_dir}')
      continue

    if snapshot_date and snapshot_date != match_dir.group(1):
      continue
    print()
    print(f'Found: {match_dir.group(0)}')
    print(f'Snapshot date: {match_dir.group(1)}')
    print(f'Experiment name: {match_dir.group(2)}')
    print(f'Experiment hash: {match_dir.group(3)}')
    print()
    group_experiments[group_dir] = {}
    for file in files_to_read:
      filepath = os.path.join(local_dir, group_dir, file + '.pkl')
      if not os.path.exists(filepath):
        print(f'File not found : {filepath}')
        continue

      with open(filepath, 'rb') as f:
        group_experiments[group_dir][file] = pickle.load(f)

  return group_experiments


def execute(args):
  """Analyze results from grouper experiments."""

  # Since this is intended to run locally, force log to console.
  environment.set_bot_environment()
  os.environ['LOG_TO_CONSOLE'] = 'True'
  os.environ['LOG_TO_GCP'] = ''
  os.environ['LOCAL_DEVELOPMENT'] = 'True'
  logs.configure('run_bot')

  local_dir = os.path.join(os.getenv('PATH_TO_LOCAL_DATA', '.'))
  print(
      f'Loading data from: {local_dir} - Set $PATH_TO_LOCAL_DATA to change dir.')
  if not os.path.exists(local_dir):
    print(f'Local dir not found.')
    return
  
  group_experiments = get_groups_experiments_data(local_dir)
  return

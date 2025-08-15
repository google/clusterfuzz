import collections
import os
import pickle
import random
import re
import networkx as nx
import statistics
import matplotlib.pyplot as plt

from .grouper_experiment import GROUPS_MAP_FILE
from .grouper_experiment import TESTCASES_DELETED_GROUP_FILE
from .grouper_experiment import TESTCASES_TO_GROUP_FILE
from .grouper_experiment import TESTCASES_DIR_PREFIX
from .grouper_experiment import TESTCASES_ATTR_FILE
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

potential_deleted_tcs = {}
potential_bugs_filed = {}


def get_group_size_stats(group_map):
  if len(group_map) == 1:
    group = list(group_map.values())[0]
    group_size = group if isinstance(group, int) else len(group.testcases)
    return f'One group of size {group_size}'

  sizes = []
  for group in group_map.values():
    if isinstance(group, int):
      sizes.append(group)
    else:
      sizes.append(len(group.testcases))

  mean = round(statistics.mean(sizes), 2)
  median = round(statistics.median(sizes), 2)
  quants = [round(q, 2) for q in statistics.quantiles(sizes, n=100)]
  percentiles = [quants[10], quants[25], quants[75], quants[90]]
  max_size = max(sizes)

  stats_str = f'Mean: {mean}, Median: {median}, Percentiles (10%, 25%, 75%, 90%): {percentiles}, Max: {max_size}'
  return stats_str


def get_groups_experiments_data(local_dir: str, snapshot_date: str | None = None):
  group_experiments = {}
  files_to_read = [GROUPS_MAP_FILE, TESTCASES_DELETED_GROUP_FILE, TESTCASES_TO_GROUP_FILE]
  pattern = re.compile(r'^experiment_snapshot-(\d{2}_\d{2}_\d{4})_(.+?)_([0-9a-f]{8})$')
  for group_dir in os.listdir(local_dir):
    match_dir = pattern.match(group_dir)
    if not match_dir:
      print(f'\nNot matched: {group_dir}')
      continue

    if snapshot_date and snapshot_date != match_dir.group(1):
      continue
    # print()
    # print(f'Found: {match_dir.group(0)}')
    # print(f'Snapshot date: {match_dir.group(1)}')
    # print(f'Experiment name: {match_dir.group(2)}')
    # print(f'Experiment hash: {match_dir.group(3)}')
    # print()
    group_experiments[group_dir] = {}
    for file in files_to_read:
      filepath = os.path.join(local_dir, group_dir, file + '.pkl')
      if not os.path.exists(filepath):
        print(f'File not found : {filepath}')
        continue

      with open(filepath, 'rb') as f:
        group_experiments[group_dir][file] = pickle.load(f)

  return group_experiments

def get_default_stats(local_dir: str, snapshot_date: str | None = None):
  testcases_snapshot, testcase_map, _ = get_loaded_testcases(local_dir)
  if testcase_map is None:
    print('Failed getting testcases map.')
    return
  print(f'\nGetting default grouper stats from: {testcases_snapshot}')
  groups_map = {}
  ungrouped = 0
  max_group = 0
  max_size = 0
  for testcase_attr in testcase_map.values():
    group_id = testcase_attr.group_id
    if not group_id:
      ungrouped += 1
      continue
    if group_id not in groups_map:
      groups_map[group_id] = 0
    groups_map[group_id] += 1
    if groups_map[group_id] >= max_size:
      max_group = group_id
      max_size = groups_map[group_id]

  bugs_filed = len(groups_map) + ungrouped
  print(f'\n* Current state:\n')
  print(f'  * Total TCs: {len(testcase_map)}')
  print(f'  * Groups: {len(groups_map)}')
  print(f'  * Groups sizes stats: {get_group_size_stats(groups_map)}')
  print(f'  * Max group {max_group}: Size={max_size}')
  print(f'  * Potential bugs filed, i.e., ungrouped ({ungrouped}) + groups ({len(groups_map)}): {bugs_filed}')
  potential_deleted_tcs[testcases_snapshot] = 0
  potential_bugs_filed[testcases_snapshot] = bugs_filed
  return testcases_snapshot


def get_experiment_stats(exp_name: str, group_exp: dict):
  groups_map = group_exp[GROUPS_MAP_FILE]
  testcases_overflow = group_exp[TESTCASES_DELETED_GROUP_FILE]
  testscases_to_group_map = group_exp[TESTCASES_TO_GROUP_FILE]

  grouped = 0
  ungrouped = 0
  for grp_id in testscases_to_group_map.values():
    if grp_id == 0:
      ungrouped += 1
    else:
      grouped += 1

  total_tcs_analyzed = ungrouped + grouped + len(testcases_overflow)
  bugs_filed = len(groups_map) + ungrouped
  print(f'\n\n* Analysis results - {exp_name}:\n')
  print(f'  * Total TCs analyzed: {total_tcs_analyzed}.')
  print(f'  * Groups: {len(groups_map)}.')
  print(f'  * Groups sizes stats: {get_group_size_stats(groups_map)}')
  print(f'  * TCs deleted due to group overflow: {len(testcases_overflow)}.')
  print(f'  * Potential bugs filed, i.e., ungrouped ({ungrouped}) + groups ({len(groups_map)}): {bugs_filed}')

  potential_deleted_tcs[exp_name] = len(testcases_overflow)
  potential_bugs_filed[exp_name] = bugs_filed


def gen_ordered_bar_plot(data, map_exp_name, descending, filename, title='Title', xlabel='Items', ylabel='Values'):
  pattern = re.compile(r'^experiment_snapshot-(\d{2}_\d{2}_\d{4})_(.+?)_([0-9a-f]{8})$')
  sorted_items = sorted(data.items(), key=lambda item: item[1], reverse=descending)
  prev_labels, values = zip(*sorted_items)
  labels = []
  for lb in prev_labels:
    match_name = pattern.match(lb)
    if match_name:
      labels.append(map_exp_name[match_name.group(2)])
    elif 'testcases_snapshot' in lb:
      labels.append('before_grouping')
    else:
      labels.append(lb)

  # plt.style.use('seaborn-v0_8-whitegrid')
  _, ax = plt.subplots(figsize=(10, 6))
  ax.grid(True)

  # Create bars
  bars = ax.bar(labels, values)#, color='skyblue')
  if min(values) >= 1000:
    ax.set_ylim(bottom=1000)

  for bar in bars:
      yval = bar.get_height()
      ax.text(bar.get_x() + bar.get_width() / 2.0, yval, f'{int(yval)}', va='bottom', ha='center')

  # Add titles and labels
  ax.set_title(title, fontsize=10, fontweight='bold')
  ax.set_xlabel(xlabel, fontsize=10)
  ax.set_ylabel(ylabel, fontsize=10)

  # Rotate x-axis labels for better readability if they are long
  plt.xticks(rotation=45, ha='right')

  # Ensure everything fits without overlapping
  plt.tight_layout()
  plt.savefig(f'{filename}.png')

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

  snapshot_name = get_default_stats(local_dir)
  snapshot_date = snapshot_name.removeprefix('testcases_snapshot_')
  group_experiments = get_groups_experiments_data(local_dir)
  for exp_name, group_exp in group_experiments.items():
    get_experiment_stats(exp_name, group_exp)


  # map_exp_name = {
  #     'default' : 'default (with variant)',
  #     'disable_variant' : 'default disable variant',
  #     'disable_variant_and_same_frames_3' : 'same_frames_LCS=3',
  #     'disable_variant_and_crash_thr_85' : 'crash_thr=0.85',
  #     'disable_variant_and_crash_thr_90' : 'crash_thr=0.90',
  #     'disable_variant_and_group_size_40' : 'group_size_lim=40',
  #     'disable_variant_and_group_size_35' : 'group_size_lim=35',
  #     'disable_variant_and_crash_thr_85_and_same_frames_3' : 'crash_thr=0.85 and same_frames_LCS=3',
  #     'disable_variant_and_crash_thr_90_and_same_frames_3' : 'crash_thr=0.90 and same_frames_LCS=3',
  #     'enable_variant_and_crash_thr_90_and_same_frames_3' : 'crash_thr=0.90 and same_frames_LCS=3 and enable variant',
  #     'disable_variant_and_increase_thrs_and_group_size_35' : 'crash_thr=0.90 and same_frames_LCS=3 and group_size_lim=35',
  #     'disable_variant_and_increase_thrs_and_group_size_40' : 'crash_thr=0.90 and same_frames_LCS=3 and group_size_lim=40',
  # }
  # gen_ordered_bar_plot(data=potential_bugs_filed,
  #                      map_exp_name=map_exp_name,
  #                      descending=False,
  #                      filename=f'potential_bugs_{snapshot_date}',
  #                      title=f'Potential bugs filed (ungrouped + grouped) - {snapshot_date}',
  #                      xlabel='Experiments',
  #                      ylabel='Bugs')

  # gen_ordered_bar_plot(data=potential_deleted_tcs,
  #                      map_exp_name=map_exp_name,
  #                      descending=True,
  #                      filename=f'potential_deleted_{snapshot_date}',
  #                      title=f'Testcases deleted due to overflow - {snapshot_date}',
  #                      xlabel='Experiments',
  #                      ylabel='Testcases')


# DEBUG_TASK=TRUE PATH_TO_LOCAL_DATA=/usr/local/google/home/vtcosta/Data/grouper_data_latest python butler.py run grouper_analyzer --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
# DEBUG_TASK=TRUE PATH_TO_LOCAL_DATA=/usr/local/google/home/vtcosta/Data/grouper_specific_4885551400288256 python butler.py run grouper_analyzer --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
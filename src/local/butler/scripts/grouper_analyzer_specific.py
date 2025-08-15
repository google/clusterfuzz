import collections
import os
import pickle
import random
import re
import itertools
import networkx as nx
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


def execute(args):
  """Load testcases and/or run grouper locally."""

  local_dir = '/usr/local/google/home/vtcosta/Data/grouper_specific_4885551400288256'
  # Since this is intended to run locally, force log to console.
  environment.set_bot_environment()
  os.environ['LOG_TO_CONSOLE'] = 'True'
  os.environ['LOCAL_DEVELOPMENT'] = 'True'
  os.environ['LOG_TO_GCP'] = ''
  logs.configure('run_bot')

  # GROUP ANALYSIS
  # LEGACY
  # tcs_map, tcs_dup, gps_map, tcs_del_grps, tcs_to_grp_map = get_grouper_data(local_dir, 'groups_variant')
  # print(f'# TCs: {len(tcs_map)}. Example:')
  # tc_id = random.choice(list(tcs_map.keys()))
  # print(f'\tID:{tcs_map[tc_id].id}, Crash Type: {tcs_map[tc_id].crash_type}')
  # print()
  # print(f'Duplicated TCs ({len(tcs_dup)}): {tcs_dup}')
  # print()
  # print(f'# Groups: {len(gps_map)}.')
  # if len(gps_map) <= 5:
  #   for gp_id in gps_map:
  #     print()
  #     print(f'\tID: {gps_map[gp_id].id}, Leader: {gps_map[gp_id].leader_id}, Isse: {gps_map[gp_id].group_issue_id}, Graph: {gps_map[gp_id].testcases}')
  #     for line in nx.generate_edgelist(gps_map[gp_id].testcases, data=True):
  #       print(line)
  # else:
  #   gp_id = random.choice(list(gps_map.keys()))
  #   print(f'\tID: {gps_map[gp_id].id}, Leader: {gps_map[gp_id].leader_id}, Isse: {gps_map[gp_id].group_issue_id}, Graph: {gps_map[gp_id].testcases}')
  #   for line in nx.generate_edgelist(gps_map[gp_id].testcases, data=True):
  #     print(line)

  # GROUP ANALYSIS
  # GRAPH
  pattern = re.compile(r'^experiment_snapshot-(\d{2}_\d{2}_\d{4})_(.+?)_([0-9a-f]{8})$')
  # Iterate over experiments
  for group_dir in os.listdir(local_dir):
    match_dir = pattern.match(group_dir)
    if not match_dir:
      print(f'\nNot matched: {group_dir}\n')
      continue

    exp_name = match_dir.group(2) + '_' + match_dir.group(3)
    exp_title = ''
    if 'default' in exp_name:
      exp_title = 'Default grouping'

    if 'thr_80' in exp_name:
      exp_title += 'crash similarity threshold = 0.8, '

    elif 'thr_90' in exp_name:
      exp_title += 'crash similarity threshold = 0.9, '

    if 'same_frames_2' in exp_name:
      exp_title += 'same frames LCS = 2'

    elif 'same_frames_3' in exp_name:
      exp_title += 'same frames LCS = 3'

    experiment_data = os.path.join(local_dir, match_dir.group(0))
    print(exp_name)
    print(experiment_data)
    print()

    with open(os.path.join(experiment_data, 'groups_map.pkl'), 'rb') as f:
      group_map = pickle.load(f)
    with open(os.path.join(experiment_data, 'testcase_to_group_map.pkl'), 'rb') as f:
      testcase_to_group_maps = pickle.load(f)

    ungrouped_testcases = []
    for testcase in testcase_to_group_maps:
      if testcase_to_group_maps[testcase] == 0:
        ungrouped_testcases.append(testcase)

    
    group_graph = None
    for group in group_map:
      if group_graph is None:
        group_graph = group_map[group].testcases
      else:
        group_graph = nx.compose(group_graph, group_map[group].testcases)

    if group_graph is None:
      return

    for tc in ungrouped_testcases:
      group_graph.add_node(tc)

    # Abbr nodes
    node_mapping = {node: str(node)[-5:] for node in group_graph.nodes()}
    nx.relabel_nodes(group_graph, node_mapping, copy=False)

    # Abbr edges - with sim threshold
    abbr_reason = {}
    for u, v, label in group_graph.edges(data=True):
      if 'crashes' in label['reason']:
        new_label = f'crash:{round(label["similarity"], 2)}'
      elif 'variant' in label['reason']:
        new_label = 'variant'
      elif 'issue' in label['reason']:
        new_label = 'issue'
      else:
        new_label = label
      abbr_reason[(u, v)] = new_label

    # components = list(nx.connected_components(group_graph))
    # all_pos = {}
    # x_offset = 0
    # y_offset = 0
    # for _, nodes in enumerate(components):
    #   subgraph = group_graph.subgraph(nodes)
    #   pos_subgraph = nx.planar_layout(subgraph)
    #   # if len(nodes) > 5:
    #   #   pos_subgraph = nx.spring_layout(subgraph, k=5)
    #   # else:
    #   #   pos_subgraph = nx.spring_layout(subgraph, k=0.1)
    #   for node, (x, y) in pos_subgraph.items():
    #     all_pos[node] = (x + x_offset, y + y_offset)
    #   x_offset += 1
    #   y_offset += 1

    # plt.figure(figsize=(12, 12))
    # plt.title(exp_title)
    # nx.draw_networkx(group_graph, all_pos, with_labels=True, node_color='skyblue', font_size=8, node_size=100)
    # nx.draw_networkx_edge_labels(group_graph, all_pos, edge_labels=abbr_reason, font_size=8)
    # # plt.savefig(f'group_{group}.png')
    # plt.savefig(f'group_all_{exp_name}.png')


    # pos = nx.spring_layout(group_graph, k=1, iterations=100)
    # pos = nx.kamada_kawai_layout(group_graph)
    pos = nx.planar_layout(group_graph)
    plt.figure(figsize=(12, 12))
    plt.title(exp_title)
    nx.draw_networkx(group_graph, pos, with_labels=True, node_color='skyblue', font_size=8, node_size=100)
    nx.draw_networkx_edge_labels(group_graph, pos, edge_labels=abbr_reason, font_size=8)
    # plt.savefig(f'group_{group}.png')
    plt.savefig(f'group_all_{exp_name}.png')


  # PRINT TESTCASES STACK IN GROUP
  # testcases_dir = os.path.join(local_dir, 'testcases_snapshot_11_08_2025')
  # with open(os.path.join(testcases_dir, 'testcases_attributes.pkl'), 'rb') as f:
  #   testcases_map = pickle.load(f)
  # for group in group_map:
  #   print('#' * 10, f' Group {group} ', '#'*10, '\n')
  #   for testcase in group_map[group].testcases.nodes():
  #     testcase_attr = testcases_map[testcase]
  #     print(f'TC {testcase}:')
  #     print(f'\t{testcase_attr.crash_type}')
  #     print(f'\t{testcase_attr.crash_state}')
  #     print()
  #   print('#' * 50)
  #   print()

  # SPECIFIC TESTCASE ANALYSIS

  # testcase_1 = data_handler.get_testcase_by_id(6124507764817920)
  # testcase_2 = data_handler.get_testcase_by_id(5675506816974848)
  # crash_comparer_type = CrashComparer(testcase_1.crash_type, testcase_2.crash_type)
  # crash_comparer_state = CrashComparer(testcase_1.crash_state, testcase_2.crash_state)
  # print(f'Type: {crash_comparer_type.is_similar()}')
  # print()
  # print(f'State: {crash_comparer_state.is_similar()}')


  # testcase_1 = data_handler.get_testcase_by_id(5779519583485952)
  # testcase_2 = data_handler.get_testcase_by_id(4816292301176832)
  # testcase_3 = data_types.Testcase()
  # testcase_3.crash_type = 'Unknown'
  # testcase_3.crash_state = '0 == imm.memory->index in liftoff-compiler.cc\nv8::internal::wasm::LiftoffCompiler::AtomicStoreMem\nv8::internal::wasm::WasmFullDecoder<v8::internal::wasm::Decoder::NoValidationTag'

  # for t1, t2 in itertools.combinations([testcase_1, testcase_2, testcase_3], 2):
  #   print(f'###########################################')
  #   print(f'T1:\n{t1.crash_state}\nT2:\n{t2.crash_state}')
  #   crash_comparer_state = CrashComparer(t1.crash_state, t2.crash_state)
  #   print(f'State: {crash_comparer_state.is_similar()}')
  #   print()
  # crash_comparer_type = CrashComparer(testcase_2.crash_type, testcase_3.crash_type)
  # crash_comparer_state = CrashComparer(testcase_2.crash_state, testcase_3.crash_state)
  # print(f'Type: {crash_comparer_type.is_similar()}')
  # print()
  # print(f'State: {crash_comparer_state.is_similar()}')

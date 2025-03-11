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
"""Query datastore to find testcases within the same group."""
import datetime
import pickle
from collections import defaultdict

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import data_handler

# class GroupAttrs:
#   def __init__(self):
#     self.size = 0
#     self.revisions = set()
#     self.issues = set()

def execute(args):
  ## Check data from a single testcase
  # testcase = data_handler.get_testcase_by_id("6244230598950912")
  # print(f'Regression: {testcase.regression}')
  # print(f'State: {testcase.crash_state}')
  # print(f'Group ID: {testcase.group_id}')
  # print(f'Group Bug Info: {testcase.group_bug_information}')
  # print(f'Bug info: {testcase.bug_information}')
  # create_time = testcase.get_created_time()
  # print(type(create_time))
  # print(create_time)

  # data_handler.get_testcase_ids_in_group

  ## Count TCs from all Groups
  # query = data_types.Testcase.query(*query_args)
  # groups = Counter()
  # for testcase in query:
  #   groups[int(testcase.group_id)] += 1
  #   if groups.total() % 500 == 0:+
  #     print(len(groups))
  # print(f'#Groups: {len(groups)}')
  # print(f'Top 10 groups: {groups.most_common(10)}')

  start_year = 2023
  date = datetime.datetime.strptime(f"01/01/{start_year}", "%d/%m/%Y")
  query_args = [
    data_types.Testcase.project_name.IN(['chromium', 'chromium-testing']),
    data_types.Testcase.timestamp > date,
  ]  
  groups = dict()
  query = data_types.Testcase.query(*query_args)
  for testcase in query:
    gp_id = int(testcase.group_id)
    if gp_id not in groups:
      groups[gp_id] = [0, set(), set()]

    groups[gp_id][0] += 1
    if gp_id != 0:
      groups[gp_id][1].add(str(testcase.regression))
      groups[gp_id][2].add(str(testcase.bug_information))
      groups[gp_id][3].add(str(testcase.job_type))


    if len(groups) % 100 == 0:
      print(len(groups))

  print(f'#Groups: {len(groups)}')

  temp_file = f'../Misc/grouper/group_attrs_{start_year}.pkl'
  with open(temp_file, 'wb+') as f:
    pickle.dump(groups, f)
  print(f'Groups saved in {temp_file}.')

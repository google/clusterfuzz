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
"""Build attributes of every testcase."""

import datetime
import sys

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.cron import manage_vms
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.fuzzing import fuzzer_selection
from clusterfuzz._internal.cron import batch_fuzzer_jobs
from clusterfuzz._internal.cron import project_setup
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import ndb_utils
# from local.butler.run_bot

def execute(args):
  """Build keywords."""
  three_days_ago = datetime.datetime.now() - datetime.timedelta(days=3)
  query = ndb_utils.get_all_from_query(
      data_types.Testcase.query(
          data_types.Testcase.timestamp >= three_days_ago))
  testcases = []
  for t in query:
    if t.archive_state != 1:
      print('unarchived', t.archive_state)
      continue
    if not t.fuzzed_keys:
      print('not fuzzed')
      continue
    t.archive_state = 0
    testcases.append(t)
    # break
  print(testcases)
  print(len(testcases))
  # ndb_utils.put_multi(testcases)

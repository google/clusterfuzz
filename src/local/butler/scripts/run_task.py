# Copyright 2024 Google LLC
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
"""Run a task locally."""

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def execute(args):
  """Build keywords."""
  del args
  environment.set_bot_environment()
  logs.configure('run_bot')

  high_end_topic = 'high-end-jobs-linux'
  high_end_testcases = []

  # This query is the same used to schedule progression tasks.
  for status in ['Processed', 'Duplicate']:
    for testcase in data_types.Testcase.query(
        ndb_utils.is_true(data_types.Testcase.open),
        ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag),
        data_types.Testcase.status == status):
      testcase_id = testcase.key.id()
      queue = tasks.queue_for_testcase(testcase)
      if str(queue) == high_end_topic:
        high_end_testcases.append(testcase_id)
        testcase.queue = None
        new_queue = tasks.queue_for_testcase(testcase)
        # testcase.put()
        logs.info(f'Updated Testcase {testcase_id} queue. From: {queue} -> To: {new_queue}')

  logs.info(f'Moved {len(high_end_testcases)} Testcases from topic {high_end_topic}: {high_end_testcases}')
  print('Finished!')

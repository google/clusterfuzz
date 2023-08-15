# Copyright 2023 Google LLC
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
"""Task scheduler used to recreate recurring tasks."""

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs


def schedule(task):
  """Creates tasks for open reproducible testcases."""

  for status in ['Processed', 'Duplicate']:
    testcases = data_types.Testcase.query(
        ndb_utils.is_true(data_types.Testcase.open),
        ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag),
        data_types.Testcase.status == status)

    for testcase in testcases:
      try:
        tasks.add_task(
            task,
            testcase.key.id(),
            testcase.job_type,
            queue=tasks.queue_for_testcase(testcase))
      except Exception:
        logs.log_error('Failed to add task.')
        continue
  logs.log(f'Task {task} added successfully')

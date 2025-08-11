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

import datetime

from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs

_LOGGING_BATCH_SIZE = 50


def execute(args):
  """Schedules minimize task for open testcases after outage in OSS-Fuzz
  schedule main."""
  del args
  processed_count = 0
  id_batch = []

  dt_format = '%Y/%m/%d %H:%M:%S'
  # Dates between the bad deploy and the revert:
  time_lower = datetime.datetime.strptime('2025/07/08 18:00:00', dt_format)
  time_upper = datetime.datetime.strptime('2025/07/09 19:00:00', dt_format)
  for testcase in data_types.Testcase.query(
      ndb_utils.is_true(data_types.Testcase.open),
      data_types.Testcase.timestamp >= time_lower,
      data_types.Testcase.timestamp <= time_upper):

    if data_handler.critical_tasks_completed(testcase):
      continue

    testcase_id = testcase.key.id()
    task_creation.create_minimize_task_if_needed(testcase)

    processed_count += 1
    id_batch.append(testcase_id)

    if processed_count % _LOGGING_BATCH_SIZE == 0:
      logs.info(f'Scheduled minimize tasks for {processed_count} testcases. '
                f'Last batch included IDs: {id_batch}.')
      id_batch = []

  if id_batch:
    logs.info(f'Finished. Total testcases processed: {processed_count}. '
              f'Final batch of IDs: {id_batch}.')
  else:
    logs.info(f'Finished. Total testcases processed: {processed_count}.')

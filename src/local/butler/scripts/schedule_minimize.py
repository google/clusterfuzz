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
"""Schedule minimize task for all open testcases."""

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.metrics import logs

_LOGGING_BATCH_SIZE = 500


def schedule_minimize_tasks_for_open_testcases(_):
  """Schedules minimize tasks for all open testcases."""
  processed_count = 0
  id_batch = []

  for testcase_id in enumerate(data_handler.get_open_testcase_id_iterator(), 1):
    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      continue

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
"""Schedule minimize task for all open testcases."""

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.metrics import logs

_LOGGING_BATCH_SIZE = 500


def schedule_minimize_tasks_for_open_testcases(_):
  """Schedules minimize tasks for all open testcases."""
  processed_count = 0
  id_batch = []

  for testcase_id in enumerate(data_handler.get_open_testcase_id_iterator(), 1):
    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      continue

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

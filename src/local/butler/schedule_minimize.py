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

from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.datastore import data_handler


def execute(_):
  """Schedule minimize task for each open testcase."""
  count = 0
  for testcase_id in data_handler.get_open_testcase_id_iterator():
    testcase = data_handler.get_testcase_by_id(testcase_id)
    task_creation.create_minimize_task_if_needed(testcase)
    count += 1

  print(f'Scheduled minimize task for {count} testcases.')

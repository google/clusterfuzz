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
"""Add tasks to a queue."""
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.datastore import data_handler

_TASK_NAMES = [
    'minimize',
    'analyze',
    'regression',
    'progression',
]


def execute(args):
  """Adds tasks to queue."""
  if args.script_args is None or len(args.script_args) < 2:
    print('Usage: add_tasks --script_args TASK_NAME TESTCASE_IDS...')
    return

  task_name = args.script_args[0]
  if task_name not in _TASK_NAMES:
    print(f'Unknown task name {task_name}. Valid options: ' +
          ','.join(_TASK_NAMES))
    return

  testcase_ids = args.script_args[1:]

  queue = tasks.default_queue()

  for testcase_id in testcase_ids:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    print(f'Adding task: {task_name} {testcase_id} {testcase.job_type}')
    if not args.non_dry_run:
      print('  Skipping for dry-run mode.')
      continue

    tasks.add_task(task_name, testcase_id, testcase.job_type, queue)

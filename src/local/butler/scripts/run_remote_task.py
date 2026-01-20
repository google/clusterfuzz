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
"""Script for running remote tasks on Google Cloud Batch."""

import contextlib

from clusterfuzz._internal import remote_task
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.system import environment


@contextlib.contextmanager
def lease_all_tasks(task_list):
  """Creates a context manager that leases every task in tasks_list."""
  with contextlib.ExitStack() as exit_stack:
    for task in task_list:
      monitoring_metrics.TASK_COUNT.increment({
          'task': task.command or '',
          'job': task.job or '',
      })
      exit_stack.enter_context(task.lease())
    yield


def schedule_utask_mains():
  """Schedules utask_mains from preprocessed utasks on Google Cloud Batch."""

  print('Attempting to combine batch tasks.')
  utask_mains = tasks.get_utask_mains()
  if not utask_mains:
    print('No utask mains.')
    return []

  print(f'Combining {len(utask_mains)} batch tasks.')
  results = []
  with lease_all_tasks(utask_mains):
    batch_tasks = [
        remote_task_types.RemoteTask(task.command, task.job, task.argument)
        for task in utask_mains
    ]

    results = remote_task.RemoteTaskGate().create_utask_main_jobs(batch_tasks)
  print('Created jobs:', results)
  return results


def execute(*args, **kwargs):  # pylint: disable=unused-argument
  """Executes the remote task script."""
  environment.set_bot_environment()
  return schedule_utask_mains()

# Copyright 2026 Google LLC
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
"""Swarming service."""

from clusterfuzz._internal import swarming
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import remote_task_types


class SwarmingService(remote_task_types.RemoteTaskInterface):
  """Remote task service implementation for Swarming."""

  def create_utask_main_job(self, module: str, job_type: str,
                            input_download_url: str):
    """Creates a single swarming task for a uworker main task."""
    command = task_utils.get_command_from_module(module)
    swarming_task = remote_task_types.RemoteTask(command, job_type,
                                                 input_download_url)
    result = self.create_utask_main_jobs([swarming_task])

    if not result:
      return None

    return result[0]

  def create_utask_main_jobs(self,
                             remote_tasks: list[remote_task_types.RemoteTask]
                            ) -> list[remote_task_types.RemoteTask]:
    """Creates many remote tasks for uworker main tasks.
       Returns the tasks that couldn't be created.
    """
    unscheduled_tasks = []
    for task in remote_tasks:
      try:
        if not swarming.is_swarming_task(task.command, task.job_type):
          unscheduled_tasks.append(task)
          continue

        swarming.push_swarming_task(task.command, task.input_download_url,
                                    task.job_type)
      except Exception:  # pylint: disable=broad-except
        logs.error(
            f'Failed to push task to Swarming: {task.command}, {task.job_type}.'
        )
        unscheduled_tasks.append(task)
    return unscheduled_tasks

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

from clusterfuzz._internal.remote_task import remote_task_types
import clusterfuzz._internal.swarming as swarming
from clusterfuzz._internal.base.tasks import task_utils

class RemoteTaskSwarmingService(remote_task_types.RemoteTaskInterface):
  def create_utask_main_job(self, module: str, job_type: str,
                            input_download_url: str):
    """Creates a single swarming task for a uworker main task."""
    command = task_utils.get_command_from_module(module)
    if not swarming.is_swarming_task(command, job_type):
      return
    
    swarming.push_swarming_task(command, input_download_url, job_type)
  
  def create_utask_main_jobs(
      self, remote_tasks: list[remote_task_types.RemoteTask]) -> list[remote_task_types.RemoteTask]:
    """Creates many remote tasks for uworker main tasks.
       Returns the tasks that couldn't be created.
    """
    unscheduled_tasks = []
    for task in remote_tasks:
      try:
        self.create_utask_main_job(task.command, task.job_type, task.input_download_url)
      except Exception:  # pylint: disable=broad-except
        unscheduled_tasks.append(task)
    return unscheduled_tasks
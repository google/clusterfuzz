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
from clusterfuzz._internal.remote_task import remote_task_types

class SwarmingService(remote_task_types.RemoteTaskInterface):
  """A remote task execution client for Swarming."""

  def create_utask_main_job(self, module, job_type, input_download_url):
    """Creates a single Swarming job for a uworker main task."""
    command = task_utils.get_command_from_module(module)
    try:
      swarming.push_swarming_task(command, input_download_url, job_type)
      return None
    except Exception:  # pylint: disable=broad-except
      return remote_task_types.RemoteTask(command, job_type, input_download_url)

  def create_utask_main_jobs(self, remote_tasks: list[remote_task_types.RemoteTask]):
    """Creates Swarming jobs for a list of uworker main tasks."""
    uncreated_tasks = []
    for task in remote_tasks:
      try:
        swarming.push_swarming_task(task.command, task.input_download_url,
                                    task.job_type)
      except Exception:  # pylint: disable=broad-except
        uncreated_tasks.append(task)
    return uncreated_tasks

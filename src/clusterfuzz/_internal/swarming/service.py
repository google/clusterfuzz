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

import json

from clusterfuzz._internal import swarming
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.swarming.api import SwarmingAPI


class SwarmingService(remote_task_types.RemoteTaskInterface):
  """Remote task service implementation for Swarming."""

  _api: SwarmingAPI = None
  MAX_PENDING_TASKS = 50

  def _get_api(self) -> SwarmingAPI:
    """Returns the Swarming API instance."""
    if not self._api:
      self._api = SwarmingAPI()
    return self._api

  def _get_os_dimension(self,
                        request: swarming_pb2.NewTaskRequest) -> str | None:  # pylint: disable=no-member
    """Extracts the OS dimension from the task request."""
    for dimension in request.task_slices[0].properties.dimensions:
      if dimension.key == 'os':
        return dimension.value
    return None

  def _is_backpressure_applied(
      self, count_request: swarming_pb2.TasksCountRequest) -> bool:  # pylint: disable=no-member
    """Checks if backpressure should be applied based on pending tasks count.
    
    Returns True if backpressure is applied or if the check fails (Fail Closed).
    """
    try:
      response_str = self._get_api().count_tasks(count_request)
      if not response_str:
        raise RuntimeError("Empty response from CountTasks")

      response_json = json.loads(response_str)
      count = int(response_json.get('count', 0))

      if count >= self.MAX_PENDING_TASKS:
        logs.info(f'[Swarming] Backpressure applied. Queue size: {count}. '
                  'Stopping scheduling.')
        return True
      return False
    except Exception as e:
      logs.error(f'[Swarming] Failed to check backpressure (Fail Closed): {e}')
      return True  # Fail closed, always fails if swarming request fails

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

  @logs.task_stage_context(logs.Stage.SCHEDULER)
  def create_utask_main_jobs(self,
                             remote_tasks: list[remote_task_types.RemoteTask]
                            ) -> list[remote_task_types.RemoteTask]:
    """Creates many remote tasks for uworker main tasks.
       Returns the tasks that couldn't be created.
    """
    unscheduled_tasks = []
    logs.info(f'[Swarming] Pushing {len(remote_tasks)} tasks trough service.')
    for i, task in enumerate(remote_tasks):
      try:
        if not swarming.is_swarming_task(task.job_type):
          unscheduled_tasks.append(task)
          continue

        request = swarming.create_new_task_request(task.command, task.job_type,
                                                   task.argument)
        if not request:
          unscheduled_tasks.append(task)
          continue

        os_val = self._get_os_dimension(request)
        if not os_val:
          logs.error(
              f'[Swarming] Failed to find OS dimension for job {task.job_type}.'
          )
          unscheduled_tasks.append(task)
          continue

        # Check backpressure
        count_request = swarming_pb2.TasksCountRequest(  # pylint: disable=no-member
            tags=['pool:chrome-sec-clusterfuzz', f'os:{os_val}'],
            state=swarming_pb2.QUERY_PENDING)  # pylint: disable=no-member

        if self._is_backpressure_applied(count_request):
          unscheduled_tasks.extend(remote_tasks[i:])
          break

        self._get_api().push_task(request)
      except Exception:  # pylint: disable=broad-except
        logs.error(
            f'Failed to push task to Swarming: {task.command}, {task.job_type}.'
        )
        unscheduled_tasks.append(task)
    return unscheduled_tasks

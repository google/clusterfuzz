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

from requests.exceptions import HTTPError

from clusterfuzz._internal import swarming
from clusterfuzz._internal.base.feature_flags import FeatureFlags
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.base.tasks.pub_sub_task_queue import \
    get_max_size_for_queue
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.swarming.api import SwarmingApi
from clusterfuzz._internal.swarming.api import SwarmingApiError

SWARMING_MAIN_QUEUE_LIMIT_DEFAULT = 25


class SwarmingService(remote_task_types.RemoteTaskInterface):
  """Remote task service implementation for Swarming."""

  _api: SwarmingApi | None = None

  def __init__(self):
    self._api = SwarmingApi.create()

  # pylint: disable=no-member
  def _get_dimension(self, request: swarming_pb2.NewTaskRequest,
                     key: str) -> str:
    """Extracts a dimension value from the task request.

    Returns:
      The dimension value if found, or an empty string otherwise.
    """
    for dimension in request.task_slices[0].properties.dimensions:
      if dimension.key == key:
        return dimension.value
    return ""

  def _is_queue_full(self,
                     count_request: swarming_pb2.TasksCountRequest) -> bool:  # pylint: disable=no-member
    """Checks if the queue is full based on pending tasks count.

    Returns True if the queue is full or if the check fails (Fail Closed).
    """
    # TODO(b/517517107): Improve backpressure calculation to account for
    # differently-sized bot groups in swarming.
    try:
      response = self._api.count_tasks(count_request)
    except SwarmingApiError as e:
      logs.error('[Swarming] Failed to check backpressure (Fail Closed): '
                 f'{e}')
      return True

    count = response.count if response.count else 0
    max_pending_tasks = get_max_size_for_queue(
        SWARMING_MAIN_QUEUE_LIMIT_DEFAULT,
        FeatureFlags.SWARMING_MAX_PENDING_TASKS)
    if count >= max_pending_tasks:
      logs.info(f'[Swarming] Backpressure applied. Queue size: {count}. '
                'Stopping scheduling.')
      return True

    return False

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

        task_req = swarming.create_new_task_request(task.command, task.job_type,
                                                    task.argument)
        if not task_req:
          unscheduled_tasks.append(task)
          continue

        os_val = self._get_dimension(task_req, 'os')
        pool_val = self._get_dimension(task_req, 'pool')
        if not os_val or not pool_val:
          logs.error(f'[Swarming] Failed to find required dimension for job '
                     f'{task.job_type}.')
          unscheduled_tasks.append(task)
          continue

        # Since there are multiple concurrent scheduling sessions/bots, it is
        # important to always check the queue size with Swarming to account for
        # the possibility that the queue was empty in the first iteration but
        # filled up on subsequent iterations due to other schedulers.
        count_request = swarming_pb2.TasksCountRequest(  # pylint: disable=no-member
            tags=[f'pool:{pool_val}', f'os:{os_val}'],
            state=swarming_pb2.QUERY_PENDING)  # pylint: disable=no-member

        # If the queue is full, there is no sense in continuing to schedule
        # tasks in this session, so we return the remaining tasks as
        # unscheduled.
        if self._is_queue_full(count_request):
          unscheduled_tasks.extend(remote_tasks[i:])
          break

        self._api.push_task(task_req)
      except HTTPError as api_failure:
        logs.warning(
            f'''Failed to push task to Swarming: {task.command}, {task.job_type}
            . Reason: {api_failure}.
            ''')
        unscheduled_tasks.append(task)
    return unscheduled_tasks

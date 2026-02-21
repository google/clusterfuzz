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
"""Remote task interface.

This module defines the interface for a remote task execution client. This
abstraction allows ClusterFuzz to support multiple remote execution
environments, such as GCP Batch and Kubernetes, without tightly coupling
the task creation logic to a specific implementation.
"""

import collections
import random

from google.cloud import ndb

from clusterfuzz._internal.base import feature_flags
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import remote_task_adapters
from clusterfuzz._internal.remote_task import remote_task_types


class RemoteTaskGate(remote_task_types.RemoteTaskInterface):
  """A generic dispatcher for remote task execution.

  This class acts as a high-level manager that abstracts away the specific
  details of the underlying remote execution backends. It uses the frequencies
  defined in this module to dynamically choose a backend for each task,
  allowing for flexible distribution and A/B testing.
  """

  def __init__(self):
    # Instantiate and cache the service clients for each defined adapter.
    self._service_map = {
        adapter.id: adapter.service()
        for adapter in remote_task_adapters.RemoteTaskAdapters
    }
    self._adapters = remote_task_adapters.RemoteTaskAdapters

  def _get_adapter(self, job_type: str = None) -> str:
    """Performs a weighted random choice to select a remote backend.

    This method is used when creating a single task, ensuring that the
    distribution of tasks over time aligns with the configured frequencies.
    """
    if feature_flags.FeatureFlags.JOB_RUNTIME_ROUTING.enabled and job_type:
      job_runtime = ndb.Key(data_types.JobRuntime, job_type).get()
      if job_runtime:
        if job_runtime.runtime == 'batch':
          return 'gcp_batch'
        if job_runtime.runtime == 'kata':
          return 'kubernetes'

    frequencies = self.get_job_frequency()
    population = list(frequencies.keys())
    weights = list(frequencies.values())
    return random.choices(population, weights)[0]

  def get_job_frequency(self):
    """Returns the frequency distribution for all remote task adapters.

    This function calculates the proportion of tasks that should be sent to each
    remote backend defined in the `RemoteTaskAdapters` enum. The calculation
    is based on feature flags, default weights, and ensures the total
    distribution sums to 1.0.

    The order of adapters in the enum matters, as this function processes them
    sequentially, and any remaining weight to sum to 1.0 is assigned to the
    last adapter.

    Returns:
      A dictionary mapping each adapter's ID (e.g., 'gcp_batch') to its
      calculated frequency (a float between 0.0 and 1.0).
    """
    frequencies = {adapter.id: 0.0 for adapter in self._adapters}
    total_weight = 0.0

    for adapter in self._adapters:
      default_weight = adapter.default_weight
      feature_flag = adapter.feature_flag
      weight = default_weight

      # A feature flag can override the default weight for an adapter, allowing
      # for dynamic adjustments to task distribution.
      if (feature_flag and feature_flag.enabled and
          isinstance(feature_flag.content, float)):
        feature_flag_weight = feature_flag.content
        if 0 <= feature_flag_weight <= 1:
          weight = feature_flag_weight

      if total_weight >= 1.0 and weight > 0.0:
        logs.warning(
            'Total weight for jobs frequency bigger than 1.0. Adapter starving',
            adapter=adapter.id)
        break

      # Ensure the cumulative weight does not exceed 1.0. If adding the
      # current weight would push the total over, we cap it.
      if weight + total_weight > 1.0:
        weight = 1.0 - total_weight

      total_weight += weight
      frequencies[adapter.id] = weight if weight >= 0 else 0.0

    logs.info('Job frequencies', frequencies=frequencies)
    return frequencies

  def create_utask_main_job(self, module, job_type, input_download_url):
    """Creates a single remote task, selecting a backend dynamically."""
    adapter_id = self._get_adapter(job_type)
    service = self._service_map[adapter_id]
    return service.create_utask_main_job(module, job_type, input_download_url)

  def create_utask_main_jobs(self,
                             remote_tasks: list[remote_task_types.RemoteTask]):
    """Creates a batch of remote tasks, distributing them across backends.

    This method distributes tasks based on both configured frequencies and
    JobRuntime preferences. It ensures that the total number of tasks sent to
    each runtime does not exceed its frequency-based allocation, while
    prioritizing JobRuntime preferences when possible.
    """
    if not remote_tasks:
      return []

    tasks_by_adapter = collections.defaultdict(list)

    if len(remote_tasks) == 1:
      # For a single task, use the specific adapter selection logic which
      # respects JobRuntime preferences if enabled.
      adapter_id = self._get_adapter(remote_tasks[0].job_type)
      tasks_by_adapter[adapter_id].extend(remote_tasks)
      unscheduled_tasks = []
    else:
      frequencies = self.get_job_frequency()
      total_count = len(remote_tasks)

      # Calculate target counts for each adapter based on frequencies.
      target_counts = {
          adapter_id: int(total_count * freq)
          for adapter_id, freq in frequencies.items()
      }

      # Group tasks by their preferred adapter.
      preferred_tasks = collections.defaultdict(list)
      if feature_flags.FeatureFlags.JOB_RUNTIME_ROUTING.enabled:
        # Fetch all JobRuntime entities in a single multi-get to optimize
        # performance.
        unique_job_types = list({task.job_type for task in remote_tasks})
        keys = [
            ndb.Key(data_types.JobRuntime, job_type)
            for job_type in unique_job_types
        ]
        job_runtimes = ndb.get_multi(keys)
        runtime_map = {
            jr.job_name: jr.runtime for jr in job_runtimes if jr is not None
        }

        for task in remote_tasks:
          runtime = runtime_map.get(task.job_type)
          if runtime == 'batch':
            preferred_tasks['gcp_batch'].append(task)
          elif runtime == 'kata':
            preferred_tasks['kubernetes'].append(task)
          else:
            preferred_tasks[None].append(task)
      else:
        preferred_tasks[None] = list(remote_tasks)

      # 1. Assign preferred tasks up to target count (respecting the "min"
      # rule).
      # The number of tasks for each runtime is min(preferred, target_count).
      remaining_tasks = []
      for adapter_id, target in target_counts.items():
        assigned = preferred_tasks[adapter_id][:target]
        tasks_by_adapter[adapter_id].extend(assigned)
        # Overflow preferred tasks are pooled for later distribution.
        remaining_tasks.extend(preferred_tasks[adapter_id][target:])

      # Add tasks with no preference to the pool.
      remaining_tasks.extend(preferred_tasks[None])

      # 2. Fill remaining room in target counts using tasks from the pool.
      for adapter_id, target in target_counts.items():
        room = target - len(tasks_by_adapter[adapter_id])
        if room > 0:
          tasks_by_adapter[adapter_id].extend(remaining_tasks[:room])
          remaining_tasks = remaining_tasks[room:]

      # 3. Handle remainders due to rounding or sum(frequencies) < 1.0.
      unscheduled_tasks = []
      if sum(frequencies.values()) >= 0.999:
        for i, task in enumerate(remaining_tasks):
          adapter_id = list(frequencies.keys())[i % len(frequencies)]
          tasks_by_adapter[adapter_id].append(task)
      else:
        unscheduled_tasks = list(remaining_tasks)

    for adapter_id, tasks in tasks_by_adapter.items():
      if tasks:
        try:
          logs.info(f'Sending {len(tasks)} tasks to {adapter_id}.')
          service = self._service_map[adapter_id]
          unscheduled_tasks.extend(service.create_utask_main_jobs(tasks))
        except Exception:  # pylint: disable=broad-except
          logs.error(f'Failed to send {len(tasks)} tasks to {adapter_id}.')
          unscheduled_tasks.extend(tasks)

    return unscheduled_tasks

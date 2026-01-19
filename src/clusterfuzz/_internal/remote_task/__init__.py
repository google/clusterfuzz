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
import abc
import collections
from enum import Enum
import random
from typing import List

from clusterfuzz._internal.datastore import feature_flags
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import types


class RemoteTaskGate(types.RemoteTaskInterface):
  """A generic dispatcher for remote task execution.

  This class acts as a high-level manager that abstracts away the specific
  details of the underlying remote execution backends. It uses the frequencies
  defined in this module to dynamically choose a backend for each task,
  allowing for flexible distribution and A/B testing.
  """

  def __init__(self):
    # Avoiding circular import
    from clusterfuzz._internal.remote_task import remote_task_adapters

    # Instantiate and cache the service clients for each defined adapter.
    self._service_map = {
        adapter.id: adapter.service()
        for adapter in remote_task_adapters.RemoteTaskAdapters
    }
    self._adapters = remote_task_adapters.RemoteTaskAdapters

  def _get_adapter(self) -> str:
    """Performs a weighted random choice to select a remote backend.

    This method is used when creating a single task, ensuring that the
    distribution of tasks over time aligns with the configured frequencies.
    """
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

  def create_utask_main_job(self, module: str, job_type: str,
                            input_download_url: str):
    """Creates a single remote task on a dynamically chosen backend."""
    adapter_id = self._get_adapter()
    service = self._service_map[adapter_id]
    return service.create_utask_main_job(module, job_type, input_download_url)

  def create_utask_main_jobs(self, remote_tasks: List[types.RemoteTask]):
    """Creates a batch of remote tasks, distributing them across backends.

    This method handles two cases:
    1. If there is only one task, it uses a weighted random choice to select
       a backend, similar to `create_utask_main_job`.
    2. If there are multiple tasks, it distributes them deterministically
       across the available backends based on their configured frequencies.
       This ensures that a batch of 100 tasks with a 70/30 split sends
       exactly 70 tasks to one backend and 30 to the other.
    """
    tasks_by_adapter = collections.defaultdict(list)

    if len(remote_tasks) == 1:
      # For a single task, use a random distribution.
      adapter_id = self._get_adapter()
      tasks_by_adapter[adapter_id].extend(remote_tasks)
    else:
      # For multiple tasks, use deterministic slicing to ensure the
      # distribution precisely matches the frequency configuration.
      frequencies = self.get_job_frequency()
      start_index = 0
      for adapter_id, frequency in frequencies.items():
        count = int(len(remote_tasks) * frequency)
        tasks_by_adapter[adapter_id].extend(
            remote_tasks[start_index:start_index + count])
        start_index += count

      # Distribute any remainder tasks (due to rounding) one by one. This
      # ensures that all tasks are assigned to a backend.
      remaining_tasks = remote_tasks[start_index:]
      for i, task in enumerate(remaining_tasks):
        adapter_id = list(frequencies.keys())[i % len(frequencies)]
        tasks_by_adapter[adapter_id].append(task)

    results = []
    for adapter_id, tasks in tasks_by_adapter.items():
      if tasks:
        logs.info(f'Sending {len(tasks)} tasks to {adapter_id}.')
        service = self._service_map[adapter_id]
        results.extend(service.create_utask_main_jobs(tasks))
    return results

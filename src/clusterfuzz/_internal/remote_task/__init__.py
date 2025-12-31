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
import random
from typing import List

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import job_frequency


class RemoteTask:
  """Represents a single ClusterFuzz task to be executed on a remote worker.
  
  This class holds the necessary information to execute a ClusterFuzz command,
  such as 'fuzz' or 'progression', in a remote environment like GCP Batch. It
  is used to enqueue tasks and track their state.
  """

  def __init__(self, command, job_type, input_download_url, pubsub_task=None):
    self.command = command
    self.job_type = job_type
    self.input_download_url = input_download_url
    self.pubsub_task = pubsub_task


class RemoteTaskInterface(abc.ABC):
  """Interface for a remote task execution client.
  
  This interface defines the contract for a client that can create and manage
  remote jobs. Each client is responsible for translating a ClusterFuzz task
  specification into a job that can be executed in its target environment.
  """

  @abc.abstractmethod
  def create_uworker_main_batch_job(self, module: str, job_type: str,
                                    input_download_url: str):
    """Creates a single remote task for a uworker main task."""
    raise NotImplementedError

  @abc.abstractmethod
  def create_uworker_main_batch_jobs(self, remote_tasks: List[RemoteTask]):
    """Creates a many remote tasks for uworker main tasks."""
    raise NotImplementedError


class RemoteTaskGate(RemoteTaskInterface):
  """A gatekeeper for remote task execution.
  
  This class is responsible for choosing the remote execution backend (GCP Batch
  or Kubernetes) for a given task, based on the configured frequencies in the
  `job_frequency` module.
  """

  def __init__(self):
    from clusterfuzz._internal.batch.service import GcpBatchService
    from clusterfuzz._internal.k8s.service import KubernetesService
    self._gcp_batch_service = GcpBatchService()
    self._kubernetes_service = KubernetesService()

  def _should_use_kubernetes(self, job_type: str) -> bool:
    """Determines whether to use the Kubernetes backend for a given job.
    
    The decision is made based on a random roll and the configured frequency
    for the given job type.
    """
    frequencies = job_frequency.get_job_frequency(job_type)
    return random.random() < frequencies['kubernetes']

  def create_uworker_main_batch_job(self, module: str, job_type: str,
                                    input_download_url: str):
    """Creates a batch job on either GCP Batch or Kubernetes.
    
    The choice of backend is determined by the `_should_use_kubernetes` method.
    """
    if self._should_use_kubernetes(job_type):
      return self._kubernetes_service.create_uworker_main_batch_job(
          module, job_type, input_download_url)
    return self._gcp_batch_service.create_uworker_main_batch_job(
        module, job_type, input_download_url)

  def create_uworker_main_batch_jobs(self, remote_tasks: List[RemoteTask]):
    """Creates batch jobs on either GCP Batch or Kubernetes.
    
    The tasks are grouped by their target backend (GCP Batch or Kubernetes) and
    then created in separate batches.
    """
    gcp_batch_tasks = []
    kubernetes_tasks = []

    # Group tasks by job_type to respect per-job frequencies
    tasks_by_job = collections.defaultdict(list)
    for task in remote_tasks:
      tasks_by_job[task.job_type].append(task)

    for job_type, tasks in tasks_by_job.items():
      # Use random distribution if there is only one task
      if len(tasks) == 1:
        if self._should_use_kubernetes(job_type):
          kubernetes_tasks.extend(tasks)
        else:
          gcp_batch_tasks.extend(tasks)
        continue

      # Use deterministic slicing for multiple tasks
      frequencies = job_frequency.get_job_frequency(job_type)
      k8s_ratio = frequencies['kubernetes']
      k8s_count = int(len(tasks) * k8s_ratio)

      # We take the first chunk for Kubernetes
      kubernetes_tasks.extend(tasks[:k8s_count])
      gcp_batch_tasks.extend(tasks[k8s_count:])

    logs.info(f'Sending {len(gcp_batch_tasks)} tasks to GCP Batch.')
    logs.info(f'Sending {len(kubernetes_tasks)} tasks to Kubernetes.')

    results = []
    if kubernetes_tasks:
      from clusterfuzz._internal.k8s.service import JobLimitReachedError
      try:
        results.extend(
            self._kubernetes_service.create_uworker_main_batch_jobs(
                kubernetes_tasks))
      except JobLimitReachedError:
        logs.warning('Kubernetes job limit reached. Not acking tasks.')
        for task in kubernetes_tasks:
          if task.pubsub_task:
            task.pubsub_task.do_not_ack = True

    if gcp_batch_tasks:
      results.extend(
          self._gcp_batch_service.create_uworker_main_batch_jobs(
              gcp_batch_tasks))
    return results

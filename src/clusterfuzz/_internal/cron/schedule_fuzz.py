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
"""Cron job to schedule fuzz tasks that run on batch."""

import collections
import random
import sys
import time
from typing import Dict

from googleapiclient import discovery

from clusterfuzz._internal.base import concurrency
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs


def _get_quotas(project, region):
  gcp_credentials = credentials.get_default()[0]
  compute = discovery.build('compute', 'v1', credentials=gcp_credentials)
  return compute.regions().get(  # pylint: disable=no-member
      region=region, project=project).execute()['quotas']


def get_available_cpus(project: str, region: str) -> int:
  """Gets the number of available CPUs in the current GCE region."""
  quotas = _get_quotas(project, region)

  # If preemptible quota is not defined, we need to use CPU quota instead.
  cpu_quota = None
  preemptible_quota = None

  # Get preemptible_quota and cpu_quota from the list of quotas.
  for quota in quotas:
    if preemptible_quota and cpu_quota:
      break
    if quota['metric'] == 'CPUS':
      cpu_quota = quota
      continue
    if quota['metric'] == 'PREEMPTIBLE_CPUS':
      preemptible_quota = quota
      continue
  assert preemptible_quota or cpu_quota

  if not preemptible_quota['limit']:
    quota = cpu_quota
  else:
    quota = preemptible_quota
  assert quota['limit'], quota

  return quota['limit'] - quota['usage']


class BaseFuzzTaskScheduler:
  """Base fuzz task scheduler for any deployment of ClusterFuzz."""

  def __init__(self, num_cpus):
    self.num_cpus = num_cpus

  def get_fuzz_tasks(self):
    raise NotImplementedError('Child class must implement.')

  def _get_cpus_per_fuzz_job(self, job_name):
    del job_name
    # TODO(metzman): Actually implement this.
    return 2


class FuzzerJob:
  """Data class that holds more info about FuzzerJobs than the ndb.Models do.
  Something like this would probably not be needed if we were using SQL and
  could use joins."""

  def __init__(self, job, project, queue, fuzzer=None, weight=None):
    self.job = job
    self.project = project
    self.queue = queue
    self.fuzzer = fuzzer
    self.weight = weight

  def copy(self):
    return FuzzerJob(
        job=self.job,
        project=self.project,
        queue=self.queue,
        fuzzer=self.fuzzer,
        weight=self.weight)


class OssfuzzFuzzTaskScheduler(BaseFuzzTaskScheduler):
  """Fuzz task scheduler for OSS-Fuzz."""

  def get_fuzz_tasks(self) -> Dict[str, tasks.Task]:
    # TODO(metzman): Handle high end.
    # A job's weight is determined by its own weight and the weight of the
    # project is a part of. First get project weights.
    logs.info('Getting projects.')
    projects = list(
        ndb_utils.get_all_from_query(data_types.OssFuzzProject.query()))

    total_cpu_weight = sum(project.cpu_weight for project in projects)
    project_weights = {}
    for project in projects:
      project_weight = project.cpu_weight / total_cpu_weight
      project_weights[project.name] = project_weight

    # Then get FuzzerJob weights.
    logs.info('Getting jobs.')
    jobs = {}
    for job in ndb_utils.get_all_from_query(data_types.Job.query()):
      jobs[job.name] = FuzzerJob(
          job=job.name,
          project=job.project,
          queue=tasks.queue_for_platform(job.platform))

    fuzzer_job_weight_by_project = collections.defaultdict(int)
    fuzzer_jobs = {}
    fuzzer_job_query = ndb_utils.get_all_from_query(
        data_types.FuzzerJob.query())

    def get_fuzzer_job_key(fuzzer, job):
      return f'{job},{fuzzer}'

    for fuzzer_job_db in fuzzer_job_query:
      fuzzer_job = jobs[fuzzer_job_db.job].copy()
      fuzzer_job.fuzzer = fuzzer_job_db.fuzzer
      project_weight = project_weights.get(fuzzer_job.project, None)
      if project_weight is None:
        logs.info(f'No project weight for {fuzzer_job.project}')
        continue

      fuzzer_job.weight = fuzzer_job_db.actual_weight * project_weight
      key = get_fuzzer_job_key(fuzzer_job_db.fuzzer, fuzzer_job_db.job)
      fuzzer_jobs[key] = fuzzer_job

      fuzzer_job_weight_by_project[fuzzer_job.project] += (
          fuzzer_job_db.actual_weight)

    for key, fuzzer_job in list(fuzzer_jobs.items()):
      total_project_weight = fuzzer_job_weight_by_project[fuzzer_job.project]
      fuzzer_job.weight /= total_project_weight

    # Prepare lists for random.choice
    fuzzer_job_list = []
    weights = []
    for fuzzer_job in fuzzer_jobs.values():
      weights.append(fuzzer_job.weight)
      fuzzer_job_list.append(fuzzer_job)

    # TODO(metzman): Handle high-end jobs correctly.
    num_instances = int(self.num_cpus / self._get_cpus_per_fuzz_job(None))
    logs.info(f'Scheduling {num_instances} fuzz tasks.')

    choices = random.choices(fuzzer_job_list, weights=weights, k=num_instances)
    queues_to_tasks = collections.defaultdict(list)
    for fuzzer_job in choices:
      queue_tasks = queues_to_tasks[fuzzer_job.queue]

      queue_tasks.append(tasks.Task('fuzz', fuzzer_job.fuzzer, fuzzer_job.job))
    return queues_to_tasks


def get_fuzz_tasks(available_cpus: int) -> [tasks.Task]:
  assert utils.is_oss_fuzz()
  scheduler = OssfuzzFuzzTaskScheduler(available_cpus)
  fuzz_tasks = scheduler.get_fuzz_tasks()
  return fuzz_tasks


def get_batch_regions(batch_config):
  mapping = batch_config.get('mapping')
  return list(set(config['gce_region'] for config in mapping.values()))


def schedule_fuzz_tasks() -> bool:
  """Schedules fuzz tasks."""
  # TODO(metzman): Remove this when we are ready to run on Chrome.
  start = time.time()

  batch_config = local_config.BatchConfig()
  regions = get_batch_regions(batch_config)
  # TODO(metzman): Make it possible to use multiple regions.
  assert len(regions) == 1
  project = batch_config.get('project')
  available_cpus = get_available_cpus(project, regions[0])
  # TODO(metzman): Remove this as we move from experimental code to production.
  available_cpus = min(available_cpus, 40)
  fuzz_tasks = get_fuzz_tasks(available_cpus)
  if not fuzz_tasks:
    logs.error('No fuzz tasks found to schedule.')
    return False

  # TODO(b/378684001): Change this to using one queue when oss-fuzz's untrusted
  # worker model is deleted.
  with concurrency.make_pool() as pool:
    list(pool.map(bulk_add, fuzz_tasks.items()))
  logs.info(f'Scheduled {len(fuzz_tasks)} fuzz tasks.')

  end = time.time()
  total = end - start
  logs.info(f'Task scheduling took {total} seconds.')
  return True


def bulk_add(queue_and_tasks):
  queue, task_list = queue_and_tasks
  logs.info(f'Adding {task_list} to {queue}.')
  tasks.bulk_add_tasks(task_list, queue=queue, eta_now=True)


def main():
  return schedule_fuzz_tasks()

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
import time
from typing import Dict

from googleapiclient import discovery

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
  """Returns the number of available CPUs in the current GCE region."""
  quotas = _get_quotas(project, region)

  # Sometimes, the preemptible quota is 0, which means the number of preemptible
  # CPUs is actually limited by the CPU quota.
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
    # Preemptible quota is not set. Obey the CPU quota since that limitss us.
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


class FuzzTaskCandidate:
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
    return FuzzTaskCandidate(
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
    projects = list(
        ndb_utils.get_all_from_query(data_types.OssFuzzProject.query()))

    logs.info(f'Got {len(projects)} projects.')
    total_cpu_weight = sum(project.cpu_weight for project in projects)
    project_weights = {}
    for project in projects:
      project_weight = project.cpu_weight / total_cpu_weight
      project_weights[project.name] = project_weight

    # Then get FuzzTaskCandidate weights.
    logs.info('Getting jobs.')
    # TODO(metzman): Handle cases where jobs are fuzzed by multiple fuzzers.
    candidates_by_job = {}
    for job in ndb_utils.get_all_from_query(data_types.Job.query()):
      candidates_by_job[job.name] = FuzzTaskCandidate(
          job=job.name,
          project=job.project,
          queue=tasks.queue_for_platform(job.platform))

    fuzzer_job_weight_by_project = collections.defaultdict(int)
    fuzz_task_candidates = []
    fuzzer_job_query = ndb_utils.get_all_from_query(
        data_types.FuzzerJob.query())

    for fuzzer_job in fuzzer_job_query:
      fuzz_task_candidate = candidates_by_job[fuzzer_job.job].copy()
      fuzz_task_candidate.fuzzer = fuzzer_job.fuzzer
      project_weight = project_weights.get(fuzz_task_candidate.project, None)
      if project_weight is None:
        logs.info(f'No project weight for {fuzz_task_candidate.project}')
        continue

      fuzz_task_candidate.weight = fuzzer_job.actual_weight * project_weight
      fuzz_task_candidates.append(fuzz_task_candidate)

      fuzzer_job_weight_by_project[fuzz_task_candidate.project] += (
          fuzzer_job.actual_weight)

    for fuzz_task_candidate in fuzz_task_candidates:
      total_project_weight = fuzzer_job_weight_by_project[
          fuzz_task_candidate.project]
      fuzz_task_candidate.weight /= total_project_weight

    # Prepare lists for random.choice
    weights = []
    for fuzz_task_candidate in fuzz_task_candidates:
      weights.append(fuzz_task_candidate.weight)

    # TODO(metzman): Handle high-end jobs correctly.
    num_instances = int(self.num_cpus / self._get_cpus_per_fuzz_job(None))
    logs.info(f'Scheduling {num_instances} fuzz tasks.')

    choices = random.choices(
        fuzz_task_candidates, weights=weights, k=num_instances)
    fuzz_tasks = [
        tasks.Task('fuzz', fuzz_task_candidate.fuzzer, fuzz_task_candidate.job)
        for fuzz_task_candidate in choices
    ]
    # TODO(metzman): Remove the queue stuff if it's uneeded for Chrome.
    return fuzz_tasks


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
  if len(regions) > 1:
    region = 'us-central1'
  else:
    region = regions[0]
  project = batch_config.get('project')
  available_cpus = get_available_cpus(project, region)
  # TODO(metzman): Remove this as we move from experimental code to production.
  available_cpus = min(available_cpus, 4000)
  fuzz_tasks = get_fuzz_tasks(available_cpus)
  if not fuzz_tasks:
    logs.error('No fuzz tasks found to schedule.')
    return False

  logs.info(f'Adding {fuzz_tasks} to preprocess queue.')
  tasks.bulk_add_tasks(fuzz_tasks, queue=tasks.PREPROCESS_QUEUE, eta_now=True)
  logs.info(f'Scheduled {len(fuzz_tasks)} fuzz tasks.')

  end = time.time()
  total = end - start
  logs.info(f'Task scheduling took {total} seconds.')
  return True


def main():
  return schedule_fuzz_tasks()

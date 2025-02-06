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
import multiprocessing
import random
import time
from typing import Dict
from typing import List

from google.cloud import monitoring_v3
from googleapiclient import discovery

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import batch
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs

# TODO(metzman): Actually implement this.
CPUS_PER_FUZZ_JOB = 2


def _get_quotas(creds, project, region):
  compute = discovery.build('compute', 'v1', credentials=creds)
  return compute.regions().get(  # pylint: disable=no-member
      region=region, project=project).execute()['quotas']


def count_unacked(creds, project_id, subscription_id):
  """Counts the unacked messages in |subscription_id|."""
  # TODO(metzman): Not all of these are fuzz_tasks. Deal with that.
  metric = 'pubsub.googleapis.com/subscription/num_undelivered_messages'
  query_filter = (f'metric.type="{metric}" AND '
                  f'resource.labels.subscription_id="{subscription_id}"')
  time_now = time.time()
  # Get the last 5 minutes.
  time_interval = monitoring_v3.TimeInterval(
      end_time={'seconds': int(time_now)},
      start_time={'seconds': int(time_now - 5 * 60)},
  )
  client = monitoring_v3.MetricServiceClient(credentials=creds)
  results = client.list_time_series(
      request={
          'filter': query_filter,
          'interval': time_interval,
          'name': f'projects/{project_id}',
          'view': monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
      })
  # Get the latest point.
  for result in results:
    if len(result.points) == 0:
      continue
    size = int(result.points[0].value.int64_value)
    logs.info(f'Unacked in {subscription_id}: {result}')
    return size
  return 0


def get_available_cpus_for_region(creds, project: str, region: str) -> int:
  """Returns the number of available CPUs in the current GCE region."""

  quotas = _get_quotas(creds, project, region)

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
    # Preemptible quota is not set. Obey the CPU quota since that limits us.
    quota = cpu_quota
  else:
    quota = preemptible_quota
  assert quota['limit'], quota

  # TODO(metzman): Do this in a more configurable way.
  # We need this because us-central1 and us-east4 have different numbers of
  # cores alloted to us in their quota. Treat them the same to simplify things.
  limit = quota['limit']
  limit -= quota['usage']
  return min(limit, 50_000)


class BaseFuzzTaskScheduler:
  """Base fuzz task scheduler for any deployment of ClusterFuzz."""

  def __init__(self, num_cpus):
    self.num_cpus = num_cpus

  def get_fuzz_tasks(self):
    raise NotImplementedError('Child class must implement.')

  def _get_cpus_per_fuzz_job(self, job_name):
    del job_name
    return CPUS_PER_FUZZ_JOB


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
  fuzz_subconf_names = {
      subconf['name'] for subconf in batch_config.get(
          'mapping.LINUX-PREEMPTIBLE-UNPRIVILEGED.subconfigs')
  }

  subconfs = batch_config.get('subconfigs')
  return list(
      set(subconfs[subconf]['region']
          for subconf in subconfs
          if subconf in fuzz_subconf_names))


def get_available_cpus(project: str, regions: List[str]) -> int:
  """Returns the available CPUs for fuzz tasks."""
  # TODO(metzman): This doesn't distinguish between fuzz and non-fuzz
  # tasks (nor preemptible and non-preemptible CPUs). Fix this.
  # Get total scheduled and queued.
  creds = credentials.get_default()[0]
  count_args = ((project, region) for region in regions)
  with multiprocessing.Pool(2) as pool:
    # These calls are extremely slow (about 1 minute total).
    result = pool.starmap_async(  # pylint: disable=no-member
        batch.count_queued_or_scheduled_tasks, count_args)
    waiting_tasks = count_unacked(creds, project, 'preprocess')
    waiting_tasks += count_unacked(creds, project, 'utask_main')
    region_counts = zip(*result.get())  #  Group all queued and all scheduled.

  # Add up all queued and scheduled.
  region_counts = [sum(tup) for tup in region_counts]
  logs.info(f'Region counts: {region_counts}')
  if region_counts[0] > 10000:
    # Check queued tasks.
    logs.info('Too many jobs queued, not scheduling more fuzzing.')
    return 0
  waiting_tasks += sum(region_counts)  # Add up queued and scheduled.
  soon_occupied_cpus = waiting_tasks * CPUS_PER_FUZZ_JOB
  logs.info(f'Soon occupied CPUs: {soon_occupied_cpus}')
  available_cpus = sum(
      get_available_cpus_for_region(creds, project, region)
      for region in regions)
  logs.info('Actually free CPUs (before subtracting soon '
            f'occupied): {available_cpus}')
  available_cpus = max(available_cpus - soon_occupied_cpus, 0)

  # Don't schedule more than 10K tasks at once. So we don't overload batch.
  print('len_regions', len(regions))
  # This number is arbitrary, but we aren't at full capacity at lower numbers.
  available_cpus = min(available_cpus, 27_500 * len(regions))
  return available_cpus


def schedule_fuzz_tasks() -> bool:
  """Schedules fuzz tasks."""
  multiprocessing.set_start_method('spawn')
  batch_config = local_config.BatchConfig()
  project = batch_config.get('project')
  regions = get_batch_regions(batch_config)
  start = time.time()
  available_cpus = get_available_cpus(project, regions)
  logs.error(f'{available_cpus} available CPUs.')
  if not available_cpus:
    # Not clear if this should be False or True.
    # TODO(metzman): Revisit this.
    return False

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

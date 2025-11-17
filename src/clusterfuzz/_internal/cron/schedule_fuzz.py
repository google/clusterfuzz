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

from google.cloud import ndb
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

# Pretend like our CPU limit is 3% higher than it actually is so that we use the
# full CPU capacity even when scheduling is slow.
CPU_BUFFER_MULTIPLIER = 1.03


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


def get_cpu_usage(creds, project: str, region: str) -> int:
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
  limit = min(quota['limit'], 100_000)
  project_config = local_config.ProjectConfig()
  # On OSS-Fuzz there is a limit to the number of CPUs we can use.
  limit = min(limit, project_config.get('schedule_fuzz.cpu_limit', limit))
  return limit, quota['usage']


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

  def __init__(self,
               job,
               project,
               fuzzer=None,
               weight=None,
               base_os_version=None):
    self.job = job
    self.project = project
    self.fuzzer = fuzzer
    self.weight = weight
    self.base_os_version = base_os_version

  def copy(self):
    return FuzzTaskCandidate(
        job=self.job,
        project=self.project,
        fuzzer=self.fuzzer,
        weight=self.weight,
        base_os_version=self.base_os_version)


class OssfuzzFuzzTaskScheduler(BaseFuzzTaskScheduler):
  """Fuzz task scheduler for OSS-Fuzz."""

  def get_fuzz_tasks(self) -> Dict[str, tasks.Task]:
    # TODO(metzman): Handle high end.
    # A job's weight is determined by its own weight and the weight of the
    # project is a part of. First get project weights.
    projects = list(
        ndb_utils.get_all_from_query(data_types.OssFuzzProject.query()))

    print(f'Got {len(projects)} projects.')
    total_cpu_weight = sum(project.cpu_weight for project in projects)
    project_weights = {}
    for project in projects:
      project_weight = project.cpu_weight / total_cpu_weight
      project_weights[project.name] = project_weight

    projects_by_name = {project.name: project for project in projects}

    # Then get FuzzTaskCandidate weights.
    print('Getting jobs.')
    # TODO(metzman): Handle cases where jobs are fuzzed by multiple fuzzers.
    candidates_by_job = {}
    for job in ndb_utils.get_all_from_query(data_types.Job.query()):
      project = projects_by_name.get(job.project)
      base_os_version = None
      if project and project.base_os_version:
        base_os_version = project.base_os_version
      elif job.base_os_version:
        base_os_version = job.base_os_version

      candidates_by_job[job.name] = FuzzTaskCandidate(
          job=job.name, project=job.project, base_os_version=base_os_version)

    fuzzer_job_weight_by_project = collections.defaultdict(int)
    fuzz_task_candidates = []
    fuzzer_job_query = ndb_utils.get_all_from_query(
        data_types.FuzzerJob.query())

    # TODO(metzman): Refactor this to use richer types and less primitives.
    for fuzzer_job in fuzzer_job_query:
      fuzz_task_candidate = candidates_by_job[fuzzer_job.job].copy()
      fuzz_task_candidate.fuzzer = fuzzer_job.fuzzer
      fuzz_task_candidate.weight = fuzzer_job.actual_weight
      fuzz_task_candidates.append(fuzz_task_candidate)

      fuzzer_job_weight_by_project[fuzz_task_candidate.project] += (
          fuzzer_job.actual_weight)

    print(f'Generated {len(fuzz_task_candidates)} fuzz task candidates.')

    for fuzz_task_candidate in fuzz_task_candidates:
      project_weight = project_weights.get(fuzz_task_candidate.project, None)
      if project_weight is None:
        logs.info(f'No project weight for {fuzz_task_candidate.project}.'
                  'Not scheduling.')
        fuzz_task_candidate.weight = 0
        continue
      total_project_weight = fuzzer_job_weight_by_project[
          fuzz_task_candidate.project]
      fuzz_task_candidate.weight = (
          fuzz_task_candidate.weight / total_project_weight) * project_weight

    # Prepare lists for random.choice
    weights = []
    for fuzz_task_candidate in fuzz_task_candidates:
      weights.append(fuzz_task_candidate.weight)
    print(f'Calculated weights: {weights}')

    # TODO(metzman): Handle high-end jobs correctly.
    num_instances = int(self.num_cpus / self._get_cpus_per_fuzz_job(None))
    print(f'Scheduling {num_instances} fuzz tasks for OSS-Fuzz.')

    choices = random.choices(
        fuzz_task_candidates, weights=weights, k=num_instances)
    fuzz_tasks = [
        tasks.Task(
            'fuzz',
            fuzz_task_candidate.fuzzer,
            fuzz_task_candidate.job,
            extra_info={'base_os_version': fuzz_task_candidate.base_os_version})
        for fuzz_task_candidate in choices
    ]
    # TODO(metzman): Use number of targets even though weight
    # implicitly includes this often.
    # TODO(metzman): Remove the queue stuff if it's uneeded for Chrome.
    return fuzz_tasks


class ChromeFuzzTaskScheduler(BaseFuzzTaskScheduler):
  """Fuzz task scheduler for Chrome."""

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.num_cpus = respect_project_max_cpus(self.num_cpus)

  def get_fuzz_tasks(self) -> List[tasks.Task]:
    """Returns fuzz tasks for chrome, weighted by job weight."""
    logs.info('Getting jobs for Chrome.')
    candidates_by_job = {}
    # Only consider linux jobs for chrome fuzzing.
    job_query = data_types.Job.query(data_types.Job.platform == 'LINUX')
    for job in ndb_utils.get_all_from_query(job_query):
      base_os_version = None
      if job.base_os_version:
        base_os_version = job.base_os_version

      candidates_by_job[job.name] = FuzzTaskCandidate(
          job=job.name, project=job.project, base_os_version=base_os_version)

    fuzz_task_candidates = []
    fuzzer_job_query = ndb_utils.get_all_from_query(
        data_types.FuzzerJob.query())

    for fuzzer_job in fuzzer_job_query:
      if fuzzer_job.job not in candidates_by_job:
        continue
      fuzz_task_candidate = candidates_by_job[fuzzer_job.job].copy()
      fuzz_task_candidate.fuzzer = fuzzer_job.fuzzer
      fuzz_task_candidate.weight = fuzzer_job.actual_weight
      fuzz_task_candidates.append(fuzz_task_candidate)

    weights = [candidate.weight for candidate in fuzz_task_candidates]
    num_instances = int(self.num_cpus / self._get_cpus_per_fuzz_job(None))
    logs.info(f'Scheduling {num_instances} fuzz tasks for Chrome.')

    if not fuzz_task_candidates:
      return []

    choices = random.choices(
        fuzz_task_candidates, weights=weights, k=num_instances)
    fuzz_tasks = [
        tasks.Task(
            'fuzz',
            candidate.fuzzer,
            candidate.job,
            extra_info={'base_os_version': candidate.base_os_version})
        for candidate in choices
    ]
    return fuzz_tasks


def get_fuzz_tasks(available_cpus: int) -> [tasks.Task]:
  print(f'utils.is_oss_fuzz() returned: {utils.is_oss_fuzz()}')
  if utils.is_oss_fuzz():
    print('Using OssfuzzFuzzTaskScheduler.')
    scheduler = OssfuzzFuzzTaskScheduler(available_cpus)
  else:
    print('Using ChromeFuzzTaskScheduler.')
    scheduler = ChromeFuzzTaskScheduler(available_cpus)
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
  # NOTE: This is a temporary modification for a high-load test.
  # This will be reverted.
  return 6


def respect_project_max_cpus(num_cpus):
  conf = local_config.ProjectConfig()
  max_cpus_per_schedule = conf.get('max_cpus_per_schedule')
  if max_cpus_per_schedule is None:
    return num_cpus
  return min(max_cpus_per_schedule, num_cpus)


def schedule_fuzz_tasks() -> bool:
  """Schedules fuzz tasks."""
  multiprocessing.set_start_method('spawn')
  batch_config = local_config.BatchConfig()
  project = batch_config.get('project')
  regions = get_batch_regions(batch_config)
  start = time.time()
  available_cpus = get_available_cpus(project, regions)
  print(f'{available_cpus} available CPUs.')
  if not available_cpus:
    return False

  fuzz_tasks = get_fuzz_tasks(available_cpus)
  print(f'Publishing {len(fuzz_tasks)} tasks.')
  if not fuzz_tasks:
    print('No fuzz tasks found to schedule.')
    return False

  print(f'Adding {fuzz_tasks} to preprocess queue.')
  print(f'Calling tasks.bulk_add_tasks with {len(fuzz_tasks)} tasks.')
  tasks.bulk_add_tasks(fuzz_tasks, queue=tasks.PREPROCESS_QUEUE, eta_now=True)
  print(f'Finished tasks.bulk_add_tasks. Scheduled {len(fuzz_tasks)} fuzz tasks.')

  end = time.time()
  total = end - start
  logs.info(f'Task scheduling took {total} seconds.')
  return True


import os
import json
from google.oauth2 import credentials as oauth_credentials

def main():
  print('Main function in schedule_fuzz.py is being executed.')
  # Force load credentials from the local ADC file.
  # This is a temporary change for testing and will be reverted.
  adc_path = os.path.expanduser('~/.config/gcloud/application_default_credentials.json')
  with open(adc_path, 'r') as f:
    creds_info = json.load(f)
  
  creds = oauth_credentials.Credentials.from_authorized_user_info(creds_info)
  
  client = ndb.Client(project='clusterfuzz-external', credentials=creds)
  with client.context():
    return schedule_fuzz_tasks()

if __name__ == '__main__':
  main()

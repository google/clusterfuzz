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

import random
import sys
import time

from googleapiclient import discovery

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment



def _get_quotas():
  compute.regions().get(  # pylint: disable=no-member
      region=region,
      project=utils.get_application_id()).execute().quotas


def get_available_cpus(region: str) -> int:
  """Gets the number of available CPUs in the current GCE region."""
  gcp_credentials = credentials.get_default()
  compute = discovery.build('compute', 'v1', credentials=gcp_credentials)
  quotas = _get_quotas()

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
    assert preemptible_quota and cpu_quota

  if not preemptible_quota['limit']:
    quota = cpu_quota
  else:
    quota = preemptible_quota
  assert quota['limit'], quota

  return quota['limit'] - quota['usage']


def _get_job_to_oss_fuzz_project_mapping():
  """Returns a mapping of jobs to OSS-Fuzz project."""
  mapping = {}
  for job in ndb_utils.get_all_from_query(data_types.Job.query()):
    project_name = job.get_environment().get('PROJECT_NAME')
    assert project_name
    mapping[job.name] = project_name
  return mapping


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


class OssfuzzFuzzTaskScheduler(BaseFuzzTaskScheduler):
  """Fuzz task scheduler for OSS-Fuzz."""

  def get_fuzz_tasks(self) -> [tasks.Task]:
    # TODO(metzman): Handle high end.
    projects = list(
        ndb_utils.get_all_from_query(data_types.OssFuzzProject.query()))

    total_cpu_weight = sum(project.cpu_weight for project in projects)
    project_weights = {}
    for project in projects:
      # Don't accidentally save this.
      project_weight = project.cpu_weight / total_cpu_weight
      project_weights[project.name] = project_weight

    platform = environment.platform()
    fuzzer_job_query = ndb_utils.get_all_from_query(
        data_types.FuzzerJobs.query(data_types.FuzzerJobs.platform == platform))
    fuzzer_jobs = {job.name: job for job in fuzzer_job_query}

    job_to_project = _get_job_to_oss_fuzz_project_mapping()
    fuzzer_job_weights = {}
    for fuzzer_job in fuzzer_jobs.values():
      project_name = job_to_project[fuzzer_job.name]
      fuzzer_job_weight = (
          fuzzer_job.actual_weight * project_weights[project_name])
      fuzzer_job_weights[fuzzer_job.name] = fuzzer_job_weight

    # TODO(metzman): Handle different number of CPUs correctly.
    fuzzer_job_names = list(fuzzer_job_weights.keys())
    fuzzer_job_weights = [fuzzer_job_weight[name] for name in fuzzer_job_names]
    num_instances = self.num_cpus

    choices = random.choices(
        fuzzer_job_names, weights=fuzzer_job_weights, k=num_instances)
    fuzz_tasks = [
        tasks.Task('fuzz', fuzzer_jobs[fuzzer_job_name].fuzzer,
                   fuzzer_jobs[fuzzer_job_name].job)
        for fuzzer_job_name in choices
    ]
    return fuzz_tasks


def get_fuzz_tasks(available_cpus: int) -> [tasks.Task]:
  assert utils.is_oss_fuzz()
  scheduler = OssfuzzFuzzTaskScheduler(available_cpus)
  fuzz_tasks = scheduler.get_fuzz_tasks()
  return fuzz_tasks


def schedule_fuzz_tasks() -> bool:
  """Schedules fuzz tasks."""
  # TODO(metzman): Remove this when we are ready to run on Chrome.
  start = time.time()

  # TODO(metzman): Make this configurable.
  available_cpus = get_available_cpus('us-east4')
  # TODO(metzman): Remove this as we move from experimental code to production.
  available_cpus = max(available_cpus, 50)
  fuzz_tasks = get_fuzz_tasks(available_cpus)
  if not fuzz_tasks:
    logs.error('No fuzz tasks found to schedule.')
    return False
  tasks.bulk_add_tasks(fuzz_tasks)
  logs.info(f'Scheduled {len(fuzz_tasks)} fuzz tasks.')

  end = time.time()
  total = end - start
  logs.info(f'Task scheduling took {total} seconds.')
  return True


def main():
  return 0 if schedule_fuzz_tasks() else 1


if __name__ == '__main__':
  sys.exit(main())

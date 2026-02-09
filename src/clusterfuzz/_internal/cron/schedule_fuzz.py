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

from google.cloud import monitoring_v3

from clusterfuzz._internal.base import feature_flags
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs

PREPROCESS_TARGET_SIZE_DEFAULT = 10000


def get_queue_size(creds, project_id, subscription_id):
  """Returns the size of the queue (unacked messages)."""
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


class BaseFuzzTaskScheduler:
  """Base fuzz task scheduler for any deployment of ClusterFuzz."""

  def __init__(self, num_tasks):
    self.num_tasks = num_tasks

  def get_fuzz_tasks(self):
    raise NotImplementedError('Child class must implement.')


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

  def get_fuzz_tasks(self) -> list[tasks.Task]:
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

    projects_by_name = {project.name: project for project in projects}

    # Then get FuzzTaskCandidate weights.
    logs.info('Getting jobs.')
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

    fuzz_tasks_count = self.num_tasks
    logs.info(f'Scheduling {fuzz_tasks_count} fuzz tasks for OSS-Fuzz.')

    choices = random.choices(
        fuzz_task_candidates, weights=weights, k=fuzz_tasks_count)
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

  def get_fuzz_tasks(self) -> list[tasks.Task]:
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
    fuzz_tasks_count = self.num_tasks
    logs.info(f'Scheduling {fuzz_tasks_count} fuzz tasks for Chrome.')

    if not fuzz_task_candidates:
      return []

    choices = random.choices(
        fuzz_task_candidates, weights=weights, k=fuzz_tasks_count)
    fuzz_tasks = [
        tasks.Task(
            'fuzz',
            candidate.fuzzer,
            candidate.job,
            extra_info={'base_os_version': candidate.base_os_version})
        for candidate in choices
    ]
    return fuzz_tasks


def get_fuzz_tasks(num_tasks: int) -> list[tasks.Task]:
  if utils.is_oss_fuzz():
    scheduler = OssfuzzFuzzTaskScheduler(num_tasks)
  else:
    scheduler = ChromeFuzzTaskScheduler(num_tasks)
  fuzz_tasks = scheduler.get_fuzz_tasks()
  return fuzz_tasks


def schedule_fuzz_tasks() -> bool:
  """Schedules fuzz tasks."""

  project = utils.get_application_id()
  start = time.time()
  creds = credentials.get_default()[0]
  preprocess_queue_size = get_queue_size(creds, project, tasks.PREPROCESS_QUEUE)

  target_size = PREPROCESS_TARGET_SIZE_DEFAULT
  target_size_flag = feature_flags.FeatureFlags.PREPROCESS_QUEUE_SIZE_LIMIT
  if target_size_flag.enabled and target_size_flag.content:
    target_size = int(target_size_flag.content)

  num_tasks = target_size - preprocess_queue_size
  logs.info(f'Preprocess queue size: {preprocess_queue_size}. '
            f'Target: {target_size}. Needed: {num_tasks}.')

  if num_tasks <= 0:
    logs.info('Queue size met or exceeded. Not scheduling tasks.')
    return False

  fuzz_tasks = get_fuzz_tasks(num_tasks)
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

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

from abc import ABC
from abc import abstractmethod
import collections
import random
import time

from google.cloud import monitoring_v3

from clusterfuzz._internal import swarming
from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.feature_flags import FeatureFlags
from clusterfuzz._internal.base.tasks.pub_sub_task_queue import \
    SWARMING_PREPROCESS_QUEUE
from clusterfuzz._internal.base.tasks.pub_sub_task_queue import PREPROCESS_QUEUE
from clusterfuzz._internal.base.tasks.pub_sub_task_queue import PubSubTaskQueue
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs


@memoize.wrap(memoize.InMemory(60))
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


class BaseFuzzTaskProvider(ABC):
  """Base fuzz task provider for any deployment of ClusterFuzz."""

  @abstractmethod
  def get_fuzz_tasks(self, num_tasks: int) -> list[tasks.Task]:
    """Returns a list of fuzz tasks."""


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


class OssfuzzFuzzTaskProvider(BaseFuzzTaskProvider):
  """Fuzz task provider for OSS-Fuzz."""

  def get_fuzz_tasks(self, num_tasks: int) -> list[tasks.Task]:
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

    logs.info(f'Scheduling {num_tasks} fuzz tasks for OSS-Fuzz.')

    choices = random.choices(fuzz_task_candidates, weights=weights, k=num_tasks)
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


class ChromeFuzzTaskProvider(BaseFuzzTaskProvider):
  """Fuzz task provider for Chrome."""

  _candidates: list[FuzzTaskCandidate]

  def __init__(self, jobs: list[data_types.Job]):
    self._candidates = _create_candidates_from_jobs(jobs)

  def get_fuzz_tasks(self, num_tasks: int) -> list[tasks.Task]:
    """Returns fuzz tasks for chrome, weighted by job weight."""
    logs.info('Getting jobs for Chrome.')

    weights = [candidate.weight for candidate in self._candidates]
    logs.info(f'Scheduling {num_tasks} fuzz tasks for Chrome.')

    if not self._candidates:
      return []

    choices = random.choices(self._candidates, weights=weights, k=num_tasks)
    fuzz_tasks = [
        tasks.Task(
            'fuzz',
            candidate.fuzzer,
            candidate.job,
            extra_info={'base_os_version': candidate.base_os_version})
        for candidate in choices
    ]
    return fuzz_tasks


def _get_jobs_for_platforms(platforms: list[str]) -> list[data_types.Job]:
  """Returns all jobs for the given platforms."""
  return list(data_types.Job.query(data_types.Job.platform.IN(platforms)))


def _get_swarming_jobs():
  """Returns all jobs that have swarming environment variables."""
  jobs = _get_jobs_for_platforms(['ANDROID', 'LINUX'])
  return [
      job for job in jobs
      if swarming.has_swarming_env_vars(job.get_environment())
  ]


def _remaining_queue_capacity(queue: PubSubTaskQueue) -> int:
  """Returns the remaining capacity of the given queue."""
  project = utils.get_application_id()
  creds = credentials.get_default()[0]
  preprocess_queue_size = get_queue_size(creds, project, queue.name)

  target_size = queue.get_max_target_size()

  num_tasks = target_size - preprocess_queue_size
  logs.info(f'Queue {queue.name} size: {preprocess_queue_size}. '
            f'Target: {target_size}. Needed: {num_tasks}.')

  return num_tasks


def _fill_queue(queue: PubSubTaskQueue, provider: BaseFuzzTaskProvider):
  """Fills the given queue with tasks from the provider."""
  start = time.time()
  num_tasks = _remaining_queue_capacity(queue)

  if num_tasks <= 0:
    logs.info('Queue size met or exceeded. Not scheduling tasks.')
    return

  fuzz_tasks = provider.get_fuzz_tasks(num_tasks)
  if not fuzz_tasks:
    logs.error(f'No fuzz tasks found to schedule in queue {queue.name}.')
    return

  logs.info(f'Adding {len(fuzz_tasks)} tasks to queue {queue.name}.')
  tasks.bulk_add_tasks(fuzz_tasks, queue=queue.name, eta_now=True)
  logs.info(f'Scheduled {len(fuzz_tasks)} tasks on queue {queue.name}.')

  end = time.time()
  total = end - start
  logs.info(f'Task scheduling took {total} seconds.')


def _create_candidates_from_jobs(
    jobs: list[data_types.Job]) -> list[FuzzTaskCandidate]:
  """Create candidates from jobs & assign weights to them."""
  if not jobs:
    return []

  jobs_by_name = {job.name: job for job in jobs}
  fuzzer_job_query = ndb_utils.get_all_from_query(
      data_types.FuzzerJob.query(
          data_types.FuzzerJob.job.IN(list(jobs_by_name.keys()))))
  fuzz_task_candidates = []

  for fuzzer_job in fuzzer_job_query:
    job = jobs_by_name[fuzzer_job.job]
    fuzz_task_candidate = FuzzTaskCandidate(
        job=job.name,
        project=job.project,
        base_os_version=job.base_os_version,
        fuzzer=fuzzer_job.fuzzer,
        weight=fuzzer_job.actual_weight,
    )
    fuzz_task_candidates.append(fuzz_task_candidate)

  return fuzz_task_candidates


def schedule_chrome_fuzz_tasks():
  """Schedules fuzz tasks for Chrome."""
  default_jobs = _get_jobs_for_platforms(['LINUX'])
  default_provider = ChromeFuzzTaskProvider(default_jobs)
  _fill_queue(PREPROCESS_QUEUE, default_provider)

  if not FeatureFlags.SWARMING_REMOTE_EXECUTION.enabled:
    return

  swarming_jobs = _get_swarming_jobs()
  swarming_provider = ChromeFuzzTaskProvider(swarming_jobs)
  _fill_queue(SWARMING_PREPROCESS_QUEUE, swarming_provider)


def schedule_fuzz_tasks():
  """Schedules fuzz tasks based on deployment type."""
  if utils.is_oss_fuzz():
    _fill_queue(PREPROCESS_QUEUE, OssfuzzFuzzTaskProvider())
  else:
    schedule_chrome_fuzz_tasks()


def main():
  schedule_fuzz_tasks()

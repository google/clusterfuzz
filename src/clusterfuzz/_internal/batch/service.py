# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Batch service.

This module provides a high-level API for creating and managing remote tasks
on GCP Batch. It abstracts away the details of the underlying batch client
and provides a simple interface for scheduling ClusterFuzz tasks.
"""
import collections
import json
import random
from typing import Dict
from typing import List
import urllib.request

import google.auth.transport.requests

from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.batch.data_structures import BatchTask
from clusterfuzz._internal.batch.data_structures import BatchWorkloadSpec
from clusterfuzz._internal.batch.gcp import GcpBatchClient
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

# See https://cloud.google.com/batch/quotas#job_limits
MAX_CONCURRENT_VMS_PER_JOB = 1000

MAX_QUEUE_SIZE = 50


class AllRegionsOverloadedError(Exception):
  """Raised when all batch regions are overloaded."""


@memoize.wrap(memoize.Memcache(60))
def get_region_load(project: str, region: str) -> int:
  """Gets the current load (queued and scheduled jobs) for a region."""
  creds, _ = credentials.get_default()
  if not creds.valid:
    creds.refresh(google.auth.transport.requests.Request())

  headers = {
      'Authorization': f'Bearer {creds.token}',
      'Content-Type': 'application/json'
  }

  try:
    url = (f'https://batch.googleapis.com/v1alpha/projects/{project}/locations/'
           f'{region}/jobs:countByState?states=QUEUED&states=SCHEDULED')
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as response:
      if response.status != 200:
        logs.error(
            f'Batch countByState failed: {response.status} {response.read()}')
        return 0

      data = json.loads(response.read())
      logs.info(f'Batch countByState response for {region}: {data}')
      # The API returns a list of state counts.
      # Example: { "jobCounts": { "state": "QUEUED", "count": "10" } }
      total = 0

      # Log data for debugging first few times if needed, or just rely on structure.
      # We'll assume the structure is standard for Google APIs.
      job_counts = data.get('jobCounts', [])
      for item in job_counts:
        state = item.get('state')
        count = int(item.get('count', 0))
        if state in ('QUEUED', 'SCHEDULED'):
          total += count
        else:
          logs.error(f'Unknown state: {state}')

      return total
  except Exception as e:
    logs.error(f'Failed to get region load for {region}: {e}')
    return 0


def _get_batch_config():
  """Returns the batch config. This function was made to make mocking easier."""
  return local_config.BatchConfig()


def is_remote_task(command: str, job_name: str) -> bool:
  """Returns whether a task is configured to run remotely on GCP Batch.

  This is determined by checking if a valid batch workload specification can
  be found for the given command and job type.
  """
  try:
    _get_specs_from_config([BatchTask(command, job_name, None)])
    return True
  except ValueError:
    return False


def _get_config_names(batch_tasks: List[BatchTask]):
  """"Gets the name of the configs for each batch_task. Returns a dict
  that is indexed by command and job_type for efficient lookup."""
  job_names = {task.job_type for task in batch_tasks}
  query = data_types.Job.query(data_types.Job.name.IN(list(job_names)))
  jobs = ndb_utils.get_all_from_query(query)
  job_map = {job.name: job for job in jobs}
  config_map = {}
  for task in batch_tasks:
    if task.job_type not in job_map:
      logs.error(f"{task.job_type} doesn't exist.")
      continue
    if task.command == 'fuzz':
      suffix = '-PREEMPTIBLE-UNPRIVILEGED'
    else:
      suffix = '-NONPREEMPTIBLE-UNPRIVILEGED'
    job = job_map[task.job_type]
    platform = job.platform if not utils.is_oss_fuzz() else 'LINUX'
    disk_size_gb = environment.get_value(
        'DISK_SIZE_GB', env=job.get_environment())
    # Get the OS version from the job, this is the least specific version.
    base_os_version = job.base_os_version

    # If we are running in the oss-fuzz context, the project-specific config
    # is more specific and overrides the job-level one.
    if utils.is_oss_fuzz():
      oss_fuzz_project = data_types.OssFuzzProject.query(
          data_types.OssFuzzProject.name == job.project).get()
      if oss_fuzz_project and oss_fuzz_project.base_os_version:
        base_os_version = oss_fuzz_project.base_os_version

    config_map[(task.command, task.job_type)] = (f'{platform}{suffix}',
                                                 disk_size_gb, base_os_version)
  # TODO(metzman): Come up with a more systematic way for configs to
  # be overridden by jobs.
  return config_map


def _get_task_duration(command):
  return tasks.TASK_LEASE_SECONDS_BY_COMMAND.get(command,
                                                 tasks.TASK_LEASE_SECONDS)


WeightedSubconfig = collections.namedtuple('WeightedSubconfig',
                                           ['name', 'weight'])


def _get_subconfig(batch_config, instance_spec):
  all_subconfigs = batch_config.get('subconfigs', {})
  instance_subconfigs = instance_spec['subconfigs']

  queue_check_regions = batch_config.get('queue_check_regions')
  if not queue_check_regions:
    logs.info(
        'Skipping batch load check because queue_check_regions is not configured.'
    )
    weighted_subconfigs = [
        WeightedSubconfig(subconfig['name'], subconfig['weight'])
        for subconfig in instance_subconfigs
    ]
    weighted_subconfig = utils.random_weighted_choice(weighted_subconfigs)
    return all_subconfigs[weighted_subconfig.name]

  # Check load for configured regions.
  healthy_subconfigs = []
  project = batch_config.get('project')

  for subconfig in instance_subconfigs:
    name = subconfig['name']
    conf = all_subconfigs[name]
    region = conf['region']

    if region in queue_check_regions:
      load = get_region_load(project, region)
      logs.info(f'Region {region} has {load} queued/scheduled jobs.')
      if load >= MAX_QUEUE_SIZE:
        logs.info(f'Region {region} overloaded (load={load}). Skipping.')
        continue

    healthy_subconfigs.append(name)

  if not healthy_subconfigs:
    logs.error('All candidate regions are overloaded.')
    raise AllRegionsOverloadedError('All candidate regions are overloaded.')

  # Randomly pick one from healthy regions to avoid thundering herd.
  chosen_name = random.choice(healthy_subconfigs)
  return all_subconfigs[chosen_name]


def _get_specs_from_config(batch_tasks) -> Dict:
  """Gets the configured specifications for a batch workload."""
  if not batch_tasks:
    return {}
  batch_config = _get_batch_config()
  config_map = _get_config_names(batch_tasks)
  specs = {}
  subconfig_map = {}
  for task in batch_tasks:
    if (task.command, task.job_type) in specs:
      # Don't repeat work for no reason.
      continue
    config_name, disk_size_gb, base_os_version = config_map[(task.command,
                                                             task.job_type)]

    instance_spec = batch_config.get('mapping').get(config_name)
    if instance_spec is None:
      raise ValueError(f'No mapping for {config_name}')

    # Decide which docker image to use.
    versioned_images_map = instance_spec.get('versioned_docker_images')
    if (base_os_version and versioned_images_map and
        base_os_version in versioned_images_map):
      docker_image_uri = versioned_images_map[base_os_version]
    else:
      # Fallback/legacy path: Use the original docker_image key.
      docker_image_uri = instance_spec['docker_image']

    project_name = batch_config.get('project')
    clusterfuzz_release = instance_spec.get('clusterfuzz_release', 'prod')
    # Lower numbers are a lower priority, meaning less likely to run From:
    # https://cloud.google.com/batch/docs/reference/rest/v1/projects.locations.jobs
    priority = 0 if task.command == 'fuzz' else 1
    max_run_duration = f'{_get_task_duration(task.command)}s'
    # This saves us time and reduces fragementation, e.g. every linux fuzz task
    # run in this call will run in the same zone.
    if config_name not in subconfig_map:
      subconfig = _get_subconfig(batch_config, instance_spec)
      subconfig_map[config_name] = subconfig

    should_retry = instance_spec.get('retry', False)
    if should_retry and task.command == 'corpus_pruning':
      should_retry = False  # It is naturally retried the next day.

    disk_size_gb = (disk_size_gb or instance_spec['disk_size_gb'])
    subconfig = subconfig_map[config_name]
    spec = BatchWorkloadSpec(
        docker_image=docker_image_uri,
        disk_size_gb=disk_size_gb,
        disk_type=instance_spec['disk_type'],
        user_data=instance_spec['user_data'],
        service_account_email=instance_spec['service_account_email'],
        preemptible=instance_spec['preemptible'],
        machine_type=instance_spec['machine_type'],
        gce_region=subconfig['region'],
        network=subconfig['network'],
        subnetwork=subconfig['subnetwork'],
        project=project_name,
        clusterfuzz_release=clusterfuzz_release,
        priority=priority,
        max_run_duration=max_run_duration,
        retry=should_retry,
    )
    specs[(task.command, task.job_type)] = spec
  return specs


class BatchService:
  """A high-level service for creating and managing remote tasks.

  This service provides a simple interface for scheduling ClusterFuzz tasks on
  GCP Batch. It handles the details of creating batch jobs and tasks, and
  provides a way to check if a task is configured to run remotely.
  """

  def __init__(self):
    self._client = GcpBatchClient()

  def create_uworker_main_batch_job(self, module: str, job_type: str,
                                    input_download_url: str):
    """Creates a single batch job for a uworker main task."""
    command = task_utils.get_command_from_module(module)
    batch_tasks = [BatchTask(command, job_type, input_download_url)]
    result = self.create_uworker_main_batch_jobs(batch_tasks)
    if result is None:
      return result
    return result[0]

  def create_uworker_main_batch_jobs(self, batch_tasks: List[BatchTask]):
    """Creates a batch job for a list of uworker main tasks.

    This method groups the tasks by their workload specification and creates a
    separate batch job for each group. This allows tasks with similar
    requirements to be processed together, which can improve efficiency.
    """
    job_specs = collections.defaultdict(list)
    specs = _get_specs_from_config(batch_tasks)
    for batch_task in batch_tasks:
      logs.info(f'Scheduling {batch_task.command}, {batch_task.job_type}.')
      spec = specs[(batch_task.command, batch_task.job_type)]
      job_specs[spec].append(batch_task.input_download_url)

    logs.info('Creating batch jobs.')
    jobs = []

    logs.info('Batching utask_mains.')
    for spec, input_urls in job_specs.items():
      for input_urls_portion in utils.batched(input_urls,
                                              MAX_CONCURRENT_VMS_PER_JOB - 1):
        jobs.append(self._client.create_job(spec, input_urls_portion))

    return jobs

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

"""Batch service.

This module provides a high-level API for creating and managing remote tasks
on GCP Batch. It abstracts away the details of the underlying batch client
and provides a simple interface for scheduling ClusterFuzz tasks.
"""
import collections
import random
import threading
from typing import Dict
from typing import List
from typing import Tuple
import uuid

from google.cloud import batch_v1 as batch

from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import retry
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.system import environment

# A named tuple that defines the execution environment for a batch workload.
# This includes details about the machine, disk, network, and container image,
# as well as ClusterFuzz-specific settings.
BatchWorkloadSpec = collections.namedtuple('BatchWorkloadSpec', [
    'clusterfuzz_release',
    'disk_size_gb',
    'disk_type',
    'docker_image',
    'user_data',
    'service_account_email',
    'subnetwork',
    'preemptible',
    'project',
    'machine_type',
    'network',
    'gce_region',
    'priority',
    'max_run_duration',
    'retry',
])

WeightedSubconfig = collections.namedtuple('WeightedSubconfig',
                                           ['name', 'weight'])

# See https://cloud.google.com/batch/quotas#job_limits
MAX_CONCURRENT_VMS_PER_JOB = 1000

MAX_QUEUE_SIZE = 50


class AllRegionsOverloadedError(Exception):
  """Raised when all batch regions are overloaded."""


_local = threading.local()

DEFAULT_RETRY_COUNT = 0

# Controls how many containers (ClusterFuzz tasks) can run on a single VM.
# THIS SHOULD BE 1 OR THERE WILL BE SECURITY PROBLEMS.
TASK_COUNT_PER_NODE = 1


def _create_batch_client_new():
  """Creates a batch client."""
  creds, _ = credentials.get_default()
  return batch.BatchServiceClient(credentials=creds)


def _batch_client():
  """Gets the batch client, creating it if it does not exist."""
  if hasattr(_local, 'client'):
    return _local.client

  _local.client = _create_batch_client_new()
  return _local.client


def get_job_name():
  return 'j-' + str(uuid.uuid4()).lower()


def _get_task_spec(batch_workload_spec):
  """Gets the task spec based on the batch workload spec."""
  runnable = batch.Runnable()
  runnable.container = batch.Runnable.Container()
  runnable.container.image_uri = batch_workload_spec.docker_image
  clusterfuzz_release = batch_workload_spec.clusterfuzz_release
  runnable.container.options = (
      '--memory-swappiness=40 --shm-size=1.9g --rm --net=host '
      '-e HOST_UID=1337 -P --privileged --cap-add=all '
      f'-e CLUSTERFUZZ_RELEASE={clusterfuzz_release} '
      '--name=clusterfuzz -e UNTRUSTED_WORKER=False -e UWORKER=True '
      '-e USE_GCLOUD_STORAGE_RSYNC=1 '
      '-e UWORKER_INPUT_DOWNLOAD_URL')
  runnable.container.volumes = ['/var/scratch0:/mnt/scratch0']
  task_spec = batch.TaskSpec()
  task_spec.runnables = [runnable]
  if batch_workload_spec.retry:
    # Tasks in general have 6 hours to run (except pruning which has 24).
    # Our signed URLs last 24 hours. Therefore, the maxiumum number of retries
    # is 4. This is a temporary solution anyway.
    task_spec.max_retry_count = 4
  else:
    task_spec.max_retry_count = DEFAULT_RETRY_COUNT
  task_spec.max_run_duration = batch_workload_spec.max_run_duration
  return task_spec


def _set_preemptible(instance_policy, batch_workload_spec) -> None:
  if batch_workload_spec.preemptible:
    instance_policy.provisioning_model = (
        batch.AllocationPolicy.ProvisioningModel.PREEMPTIBLE)
  else:
    instance_policy.provisioning_model = (
        batch.AllocationPolicy.ProvisioningModel.STANDARD)


def _get_allocation_policy(spec):
  """Returns the allocation policy for a BatchWorkloadSpec."""
  disk = batch.AllocationPolicy.Disk()
  disk.image = 'batch-cos'
  disk.size_gb = spec.disk_size_gb
  disk.type = spec.disk_type
  instance_policy = batch.AllocationPolicy.InstancePolicy()
  instance_policy.boot_disk = disk
  instance_policy.machine_type = spec.machine_type
  _set_preemptible(instance_policy, spec)
  instances = batch.AllocationPolicy.InstancePolicyOrTemplate()
  instances.policy = instance_policy

  # Don't use external ip addresses which use quota, cost money, and are
  # unnecessary.
  network_interface = batch.AllocationPolicy.NetworkInterface()
  network_interface.no_external_ip_address = True
  network_interface.network = spec.network
  network_interface.subnetwork = spec.subnetwork
  network_interfaces = [network_interface]
  network_policy = batch.AllocationPolicy.NetworkPolicy()
  network_policy.network_interfaces = network_interfaces

  allocation_policy = batch.AllocationPolicy()
  allocation_policy.instances = [instances]
  allocation_policy.network = network_policy
  service_account = batch.ServiceAccount(email=spec.service_account_email)  # pylint: disable=no-member
  allocation_policy.service_account = service_account
  return allocation_policy


@retry.wrap(
    retries=3,
    delay=2,
    function='google_cloud_utils.batch._send_create_job_request')
def _send_create_job_request(create_request):
  return _batch_client().create_job(create_request)


def count_queued_or_scheduled_tasks(project: str,
                                    region: str) -> Tuple[int, int]:
  """Counts the number of queued and scheduled tasks."""
  region = f'projects/{project}/locations/{region}'
  jobs_filter = 'Status.State="SCHEDULED" OR Status.State="QUEUED"'
  req = batch.types.ListJobsRequest(parent=region, filter=jobs_filter)
  queued = 0
  scheduled = 0
  for job in _batch_client().list_jobs(request=req):
    if job.status.state == batch.JobStatus.State.SCHEDULED:
      scheduled += job.task_groups[0].task_count
    elif job.status.state == batch.JobStatus.State.QUEUED:
      queued += job.task_groups[0].task_count
  return (queued, scheduled)


@memoize.wrap(memoize.Memcache(60))
def get_region_load(project: str, region: str) -> int:
  """Gets the current load (queued and scheduled jobs) for a region."""
  try:
    return sum(count_queued_or_scheduled_tasks(project, region))
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
    _get_specs_from_config(
        [remote_task_types.RemoteTask(command, job_name, None)])
    return True
  except ValueError:
    return False


def _get_config_names(batch_tasks: List[remote_task_types.RemoteTask]):
  """Gets the name of the configs for each batch_task. Returns a dict
  that is indexed by command and job_type for efficient lookup."""
  job_names = {task.job_type for task in batch_tasks}
  query = data_types.Job.query(data_types.Job.name.IN(list(job_names)))
  jobs = ndb_utils.get_all_from_query(query)
  job_map = {job.name: job for job in jobs}
  config_map = {}
  for task in batch_tasks:
    if task.job_type not in job_map:
      logs.error(f'{task.job_type} doesn\'t exist.')
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


def _get_specs_from_config(
    batch_tasks: List[remote_task_types.RemoteTask]) -> Dict:
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
    max_run_duration = f'{tasks.get_task_duration(task.command)}s'
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


class GcpBatchService(remote_task_types.RemoteTaskInterface):
  """A high-level service for creating and managing remote tasks.

  This service provides a simple interface for scheduling ClusterFuzz tasks on
  GCP Batch. It handles the details of creating batch jobs and tasks, and
  provides a way to check if a task is configured to run remotely.
  """

  def create_job(self, spec: BatchWorkloadSpec, input_urls: List[str]):
    """Creates and starts a batch job from |spec| that executes all tasks.
    
    This method creates a new GCP Batch job with a single task group. The
    task group is configured to run a containerized task for each of the
    input URLs. The tasks are run in parallel, with each task having its
    own VM, as defined by the TASK_COUNT_PER_NODE setting.
    """
    task_group = batch.TaskGroup()
    task_group.task_count = len(input_urls)
    assert task_group.task_count < MAX_CONCURRENT_VMS_PER_JOB
    task_environments = [
        batch.Environment(variables={'UWORKER_INPUT_DOWNLOAD_URL': input_url})
        for input_url in input_urls
    ]
    task_group.task_environments = task_environments
    task_group.task_spec = _get_task_spec(spec)
    task_group.task_count_per_node = TASK_COUNT_PER_NODE
    assert task_group.task_count_per_node == 1, 'This is a security issue'

    job = batch.Job()
    job.task_groups = [task_group]
    job.allocation_policy = _get_allocation_policy(spec)
    job.logs_policy = batch.LogsPolicy()
    job.logs_policy.destination = batch.LogsPolicy.Destination.CLOUD_LOGGING
    job.priority = spec.priority

    create_request = batch.CreateJobRequest()
    create_request.job = job
    job_name = get_job_name()
    create_request.job_id = job_name
    # The job's parent is the region in which the job will run
    project_id = spec.project
    create_request.parent = f'projects/{project_id}/locations/{spec.gce_region}'
    job_result = _send_create_job_request(create_request)
    logs.info(f'Created batch job id={job_name}.', spec=spec)
    return job_result

  def create_utask_main_job(self, module: str, job_type: str,
                            input_download_url: str):
    """Creates a single batch job for a uworker main task."""
    command = task_utils.get_command_from_module(module)
    batch_tasks = [
        remote_task_types.RemoteTask(command, job_type, input_download_url)
    ]
    result = self.create_utask_main_jobs(batch_tasks)
    if result is None:
      return result
    return result[0]

  def create_utask_main_jobs(self,
                             remote_tasks: List[remote_task_types.RemoteTask]):
    """Creates a batch job for a list of uworker main tasks.

    This method groups the tasks by their workload specification and creates a
    separate batch job for each group. This allows tasks with similar
    requirements to be processed together, which can improve efficiency.
    """
    job_specs = collections.defaultdict(list)
    specs = _get_specs_from_config(remote_tasks)
    for remote_task in remote_tasks:
      logs.info(f'Scheduling {remote_task.command}, {remote_task.job_type}.')
      spec = specs[(remote_task.command, remote_task.job_type)]
      job_specs[spec].append(remote_task.input_download_url)

    logs.info('Creating batch jobs.')
    jobs = []

    logs.info('Batching utask_mains.')
    for spec, input_urls in job_specs.items():
      for input_urls_portion in utils.batched(input_urls,
                                              MAX_CONCURRENT_VMS_PER_JOB - 1):
        jobs.append(self.create_job(spec, input_urls_portion).name)

    return jobs

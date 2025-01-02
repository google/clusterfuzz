# Copyright 2023 Google LLC
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
"""Cloud Batch helpers."""
import collections
import threading
from typing import Dict
from typing import List
from typing import Tuple
import uuid

from google.cloud import batch_v1 as batch

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs

# TODO(metzman): Change to from . import credentials when we are done
# developing.
from . import credentials

_local = threading.local()

DEFAULT_RETRY_COUNT = 0

# Controls how many containers (ClusterFuzz tasks) can run on a single VM.
# THIS SHOULD BE 1 OR THERE WILL BE SECURITY PROBLEMS.
TASK_COUNT_PER_NODE = 1

# See https://cloud.google.com/batch/quotas#job_limits
MAX_CONCURRENT_VMS_PER_JOB = 1000

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


class BatchTask:
  """Class reprensenting a ClusterFuzz task to be executed on Google Cloud
  Batch."""

  def __init__(self, command, job_type, input_download_url):
    self.command = command
    self.job_type = job_type
    self.input_download_url = input_download_url


def create_uworker_main_batch_job(module, job_type, input_download_url):
  command = task_utils.get_command_from_module(module)
  batch_tasks = [BatchTask(command, job_type, input_download_url)]
  result = create_uworker_main_batch_jobs(batch_tasks)
  if result is None:
    return result
  return result[0]


def create_uworker_main_batch_jobs(batch_tasks: List[BatchTask]):
  """Creates batch jobs."""
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
      jobs.append(_create_job(spec, input_urls_portion))

  return jobs


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


def _set_preemptible(instance_policy,
                     batch_workload_spec: BatchWorkloadSpec) -> None:
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


def _create_job(spec, input_urls):
  """Creates and starts a batch job from |spec| that executes all tasks."""
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


@retry.wrap(
    retries=3,
    delay=2,
    function='google_cloud_utils.batch._send_create_job_request')
def _send_create_job_request(create_request):
  return _batch_client().create_job(create_request)


def _get_batch_config():
  """Returns the batch config. This function was made to make mocking easier."""
  return local_config.BatchConfig()


def _get_job(job_name):
  """Returns the Job entity named by |job_name|. This function was made to make
  mocking easier."""
  return data_types.Job.query(data_types.Job.name == job_name).get()


def is_no_privilege_workload(command, job_name):
  return is_remote_task(command, job_name)


def is_remote_task(command, job_name):
  try:
    _get_specs_from_config([BatchTask(command, job_name, None)])
    return True
  except ValueError:
    return False


def _get_config_names(
    batch_tasks: List[BatchTask]) -> Dict[Tuple[str, str], str]:
  """"Gets the name of the configs for each batch_task. Returns a dict
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
    config_map[(task.command, task.job_type)] = f'{platform}{suffix}'
  return config_map


def _get_task_duration(command):
  return tasks.TASK_LEASE_SECONDS_BY_COMMAND.get(command,
                                                 tasks.TASK_LEASE_SECONDS)


WeightedSubconfig = collections.namedtuple('WeightedSubconfig',
                                           ['name', 'weight'])


def _get_subconfig(batch_config, instance_spec):
  # TODO(metzman): Make this pick one at random or based on conditions.
  all_subconfigs = batch_config.get('subconfigs', {})
  instance_subconfigs = instance_spec['subconfigs']
  weighted_subconfigs = [
      WeightedSubconfig(subconfig['name'], subconfig['weight'])
      for subconfig in instance_subconfigs
  ]
  weighted_subconfig = utils.random_weighted_choice(weighted_subconfigs)
  return all_subconfigs[weighted_subconfig.name]


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
    config_name = config_map[(task.command, task.job_type)]

    instance_spec = batch_config.get('mapping').get(config_name)
    if instance_spec is None:
      raise ValueError(f'No mapping for {config_name}')
    config_name = config_map[(task.command, task.job_type)]
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

    subconfig = subconfig_map[config_name]
    spec = BatchWorkloadSpec(
        docker_image=instance_spec['docker_image'],
        disk_size_gb=instance_spec['disk_size_gb'],
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

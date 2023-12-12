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
import uuid

from google.cloud import batch_v1 as batch

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks.utasks import utask_utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs

# TODO(metzman): Change to from . import credentials when we are done
# developing.
from . import credentials

_local = threading.local()

MAX_DURATION = '3600s'
RETRY_COUNT = 1
TASK_COUNT = 1

# Controls how many containers (ClusterFuzz tasks) can run on a single VM.
# THIS SHOULD BE 1 OR THERE WILL BE SECURITY PROBLEMS.
TASK_COUNT_PER_NODE = 1

# See https://cloud.google.com/batch/quotas#job_limits
MAX_CONCURRENT_VMS_PER_JOB = 1000

BatchWorkloadSpec = collections.namedtuple('BatchWorkloadSpec', [
    'disk_size_gb',
    'disk_type',
    'docker_image',
    'user_data',
    'service_account_email',
    'subnetwork',
    'preemptible',
    'project',
    'gce_zone',
    'machine_type',
])


def _create_batch_client_new():
  """Creates a batch client."""
  creds, project = credentials.get_default()
  if not project:
    project = utils.get_application_id()

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
  command = utask_utils.get_command_from_module(module)
  batch_tasks = [BatchTask(command, job_type, input_download_url)]
  result = create_uworker_main_batch_jobs(batch_tasks)
  if result is None:
    return result
  return result[0]


def create_uworker_main_batch_jobs(batch_tasks):
  # Define what will be done as part of the job.
  job_specs = collections.defaultdict(list)
  for batch_task in batch_tasks:
    spec = get_spec_from_config(batch_task.command, batch_task.job_type)
    job_specs[spec].append(batch_task.input_download_url)

  logs.log('Creating batch jobs.')
  return [
      _create_job(spec, input_urls) for spec, input_urls in job_specs.items()
  ]


def _get_task_spec(batch_workload_spec):
  """Gets the task spec based on the batch workload spec."""
  runnable = batch.Runnable()
  runnable.container = batch.Runnable.Container()
  runnable.container.image_uri = batch_workload_spec.docker_image
  runnable.container.options = (
      '--memory-swappiness=40 --shm-size=1.9g --rm --net=host '
      '-e HOST_UID=1337 -P --privileged --cap-add=all '
      '--name=clusterfuzz -e UNTRUSTED_WORKER=False -e UWORKER=True '
      '-e UWORKER_INPUT_DOWNLOAD_URL')
  runnable.container.volumes = ['/var/scratch0:/mnt/scratch0']
  task_spec = batch.TaskSpec()
  task_spec.runnables = [runnable]
  task_spec.max_retry_count = RETRY_COUNT
  # TODO(metzman): Change this for production.
  task_spec.max_run_duration = MAX_DURATION
  return task_spec


def _get_allocation_policy(spec):
  """Returns the allocation policy for a BatchWorkloadSpec."""
  instance_policy = batch.AllocationPolicy.InstancePolicy()
  disk = batch.AllocationPolicy.Disk()
  disk.image = 'batch-cos'
  disk.size_gb = spec.disk_size_gb
  disk.type = spec.disk_type
  instance_policy.boot_disk = disk
  instance_policy.machine_type = spec.machine_type
  instances = batch.AllocationPolicy.InstancePolicyOrTemplate()
  instances.policy = instance_policy
  allocation_policy = batch.AllocationPolicy()
  allocation_policy.instances = [instances]
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
  job.labels = {'env': 'testing', 'type': 'container'}
  job.logs_policy = batch.LogsPolicy()
  job.logs_policy.destination = batch.LogsPolicy.Destination.CLOUD_LOGGING
  location_policy = batch.AllocationPolicy.LocationPolicy()
  location_policy.allowed_locations = [f'zones/{spec.gce_zone}']
  job.location = location_policy

  create_request = batch.CreateJobRequest()
  create_request.job = job
  job_name = get_job_name()
  create_request.job_id = job_name
  # The job's parent is the region in which the job will run
  project_id = 'google.com:clusterfuzz'
  region = 'us-central1'
  create_request.parent = f'projects/{project_id}/locations/{region}'
  result = _send_create_job_request(create_request)
  logs.log('Created batch job.')
  return result


@retry.wrap(
    retries=3,
    delay=2,
    function='google_cloud_utils.batch._send_create_job_request')
def _send_create_job_request(create_request):
  return _batch_client().create_job(create_request)


def get_spec_from_config(command, job_name):
  """Gets the configured specifications for a batch workload."""
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  platform = job.platform
  if command == 'fuzz':
    platform += '-PREEMPTIBLE'
  else:
    platform += '-NONPREEMPTIBLE'
  batch_config = local_config.BatchConfig()
  instance_spec = batch_config.get('mapping').get(platform, None)
  if instance_spec is None:
    raise ValueError(f'No mapping for {platform}')
  project_name = batch_config.get('project')
  docker_image = instance_spec['docker_image']
  user_data = instance_spec['user_data']
  # TODO(https://github.com/google/clusterfuzz/issues/3008): Make this use a
  # low-privilege account.
  spec = BatchWorkloadSpec(
      docker_image=docker_image,
      user_data=user_data,
      disk_size_gb=instance_spec['disk_size_gb'],
      disk_type=instance_spec['disk_type'],
      service_account_email=instance_spec['service_account_email'],
      subnetwork=instance_spec['subnetwork'],
      gce_zone=instance_spec['gce_zone'],
      project=project_name,
      preemptible=instance_spec['preemptible'],
      machine_type=instance_spec['machine_type'])
  return spec

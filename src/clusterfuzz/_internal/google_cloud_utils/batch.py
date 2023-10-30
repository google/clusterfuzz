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

# TODO(metzman): Change to from . import credentials when we are done
# developing.
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks.utasks import utask_utils
from clusterfuzz._internal.config import local_config

from . import credentials

_local = threading.local()

MAX_DURATION = '3600s'
RETRY_COUNT = 1
TASK_COUNT = 1

BatchJobSpec = collections.namedtuple('BatchJobSpec', [
    'disk_size_gb',
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


def create_job(module_name, cf_job):
  """This is not a job in ClusterFuzz's meaning of the word."""
  # Define what will be done as part of the job.
  runnable = batch.Runnable()
  runnable.container = batch.Runnable.Container()
  spec = get_spec(module_name, cf_job)
  runnable.container.image_uri = spec.docker_image
  runnable.container.options = (
      '--memory-swappiness=40 --shm-size=1.9g --rm --net=host -e HOST_UID=1337 '
      '-P --privileged --cap-add=all '
      '--name=clusterfuzz -e UNTRUSTED_WORKER=False -e IS_UWORKER=True')
  runnable.container.volumes = ['/var/scratch0:/mnt/scratch0']
  # Jobs can be divided into tasks. In this case, we have only one task.
  task = batch.TaskSpec()
  task.runnables = [runnable]
  task.max_retry_count = RETRY_COUNT
  # TODO(metzman): Change this for production.
  task.max_run_duration = MAX_DURATION

  # Only one of these is currently possible.
  group = batch.TaskGroup()
  group.task_count = TASK_COUNT
  group.task_spec = task

  policy = batch.AllocationPolicy.InstancePolicy()
  disk = batch.AllocationPolicy.Disk()
  disk.image = 'batch-cos'
  disk.size_gb = spec.disk_size_gb
  policy.boot_disk = disk
  policy.machine_type = spec.machine_type
  instances = batch.AllocationPolicy.InstancePolicyOrTemplate()
  instances.policy = policy
  allocation_policy = batch.AllocationPolicy()
  allocation_policy.instances = [instances]
  service_account = batch.ServiceAccount(email=spec.service_account_email)  # pylint: disable=no-member
  allocation_policy.service_account = service_account

  job = batch.Job()
  job.task_groups = [group]
  job.allocation_policy = allocation_policy
  job.labels = {'env': 'testing', 'type': 'container'}
  job.logs_policy = batch.LogsPolicy()
  job.logs_policy.destination = batch.LogsPolicy.Destination.CLOUD_LOGGING

  create_request = batch.CreateJobRequest()
  create_request.job = job
  job_name = get_job_name()
  create_request.job_id = job_name
  # The job's parent is the region in which the job will run
  project_id = 'google.com:clusterfuzz'
  region = 'us-central1'
  create_request.parent = f'projects/{project_id}/locations/{region}'

  return _batch_client().create_job(create_request)


def get_spec(full_module_name, job):
  """Gets the specifications for a job."""
  platform = job.platform
  command = utask_utils.get_command_from_module(full_module_name)
  if command != 'fuzz':
    platform += '-HIGH-END'
  batch_config = local_config.BatchConfig()
  cluster_name = batch_config.get('mapping').get(platform, None)
  if cluster_name is None:
    return None
  project_name = batch_config.get('project')
  clusters_config = local_config.GCEClustersConfig()
  project_spec = clusters_config.get(project_name)
  templates = project_spec['instance_templates']
  cluster = project_spec['clusters'][cluster_name]
  template_name = cluster['instance_template']
  for template in templates:
    if template['name'] != template_name:
      continue
    break
  else:
    raise ValueError(f'Could not find template: {template_name}')

  properties = template['properties']
  items = properties['metadata']['items']
  docker_image = None
  user_data = None
  for item in items:
    if item['key'] == 'docker-image':
      docker_image = item['value']
    if item['key'] == 'user-data':
      user_data = item['value']
  assert docker_image is not None and user_data is not None
  disks = properties['disks']
  assert len(disks) == 1
  disk = disks[0]
  disk_params = disk['initializeParams']
  service_accounts = properties['serviceAccounts']
  assert len(service_accounts) == 1
  # TODO(https://github.com/google/clusterfuzz/issues/3008): Make this use a
  # low-privilege account.
  service_account_email = service_accounts[0]['email']
  network_interfaces = properties['networkInterfaces']
  assert len(network_interfaces) == 1
  network_interface = network_interfaces[0]
  subnetwork = network_interface.get('subnetwork', None)
  preemptible = bool(properties.get('scheduling') and properties['preemptible'])
  spec = BatchJobSpec(
      docker_image=docker_image,
      user_data=user_data,
      disk_size_gb=disk_params['diskSizeGb'],
      service_account_email=service_account_email,
      subnetwork=subnetwork,
      gce_zone=cluster['gce_zone'],
      project=project_name,
      preemptible=preemptible,
      machine_type=properties['machineType'])
  return spec

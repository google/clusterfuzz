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
"""GCP Cloud Batch helpers.

This module provides a client for interacting with the GCP Batch service. It is
used to run granular tasks that require a high degree of isolation, such as
executing untrusted code from fuzzing jobs. Each task is run in its own VM,
ensuring that any potential security issues are contained.
"""
import threading
from typing import List
from typing import Tuple
import uuid

from google.cloud import batch_v1 as batch

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import RemoteTaskInterface

_local = threading.local()

DEFAULT_RETRY_COUNT = 0

# Controls how many containers (ClusterFuzz tasks) can run on a single VM.
# THIS SHOULD BE 1 OR THERE WILL BE SECURITY PROBLEMS.
TASK_COUNT_PER_NODE = 1

# See https://cloud.google.com/batch/quotas#job_limits
MAX_CONCURRENT_VMS_PER_JOB = 1000


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


def _get_task_spec(batch_workload_spec, commands=None):
  """Gets the task spec based on the batch workload spec."""
  runnable = batch.Runnable()
  runnable.container = batch.Runnable.Container()
  runnable.container.image_uri = batch_workload_spec.docker_image
  if commands:
    runnable.container.commands = commands
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


class GcpBatchClient(RemoteTaskInterface):
  """A client for creating and managing jobs on the GCP Batch service.
  
  This client is responsible for translating ClusterFuzz task specifications
  into GCP Batch jobs. It handles the configuration of the job, including
  the machine type, disk size, and network settings, as well as the task
  specification, which defines the container image and command to run.
  """

  def create_job(self, spec, input_urls: List[str], commands=None):
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
    task_group.task_spec = _get_task_spec(spec, commands=commands)
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

  def get_job(self, name):
    """Gets a batch job."""
    return _batch_client().get_job(name=name)

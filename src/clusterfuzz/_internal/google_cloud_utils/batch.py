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

import threading
import uuid

# !!! Change to from . import storage
import credentials
from google.cloud import batch_v1 as batch

# from clusterfuzz._internal.google_cloud_utils import credentials

_local = threading.local()

MAX_DURATION = '3600s'
RETRY_COUNT = 2
TASK_COUNT = 1


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


def doit():
  create_job()


# !!!
EMAIL = 'untrusted-worker@clusterfuzz-external.iam.gserviceaccount.com'


def create_job(image_uri='gcr.io/clusterfuzz-images/oss-fuzz/worker',
               machine_type='e2-standard-2',
               email=EMAIL):
  """This is not a job in ClusterFuzz's meaning of the word."""
  # Define what will be done as part of the job.
  runnable = batch.Runnable()
  runnable.container = batch.Runnable.Container()
  runnable.container.image_uri = image_uri
  runnable.container.options = (
      '--memory-swappiness=40 --shm-size=1.9g --rm --net=host -e HOST_UID=1337 '
      '-P --privileged --cap-add=all '
      '--name=clusterfuzz -e UNTRUSTED_WORKER=False')
  runnable.container.volumes = ['/var/scratch0:/mnt/scratch0']
  # runnable.container.entrypoint = '/bin/sh'
  # runnable.container.commands = ['-c', 'echo Hello world! This is task ${BATCH_TASK_INDEX}. This job has a total of ${BATCH_TASK_COUNT} tasks.']

  # Jobs can be divided into tasks. In this case, we have only one task.
  task = batch.TaskSpec()
  task.runnables = [runnable]
  task.max_retry_count = RETRY_COUNT
  # TODO(metzman): Change.
  task.max_run_duration = MAX_DURATION

  # Only one of these is currently possible.
  group = batch.TaskGroup()
  group.task_count = TASK_COUNT
  group.task_spec = task

  policy = batch.AllocationPolicy.InstancePolicy()
  disk = batch.AllocationPolicy.Disk()
  disk.image = 'batch-cos'
  disk.size_gb = '100'
  policy.boot_disk = disk
  policy.machine_type = machine_type
  instances = batch.AllocationPolicy.InstancePolicyOrTemplate()
  instances.policy = policy
  allocation_policy = batch.AllocationPolicy()
  allocation_policy.instances = [instances]
  service_account = batch.ServiceAccount(email=email)
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
  project_id = 'clusterfuzz-external'
  region = 'us-central1'
  create_request.parent = f'projects/{project_id}/locations/{region}'

  return _batch_client().create_job(create_request)


doit()

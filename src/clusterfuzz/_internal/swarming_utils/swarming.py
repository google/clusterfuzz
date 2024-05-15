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
"""Swarming helpers."""

import uuid

import requests

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import swarming_pb2


def is_swarming_task(command: str, job_name: str):
  """Returns True if the task is supposed to run on swarming. """
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if not job or not job.requires_gpu:
    return False
  try:
    _get_new_task_spec(command, job_name, '')
    return True
  except ValueError:
    return False


def get_task_name():
  return 't-' + str(uuid.uuid4()).lower()


def _get_job(job_name: str):
  """Returns the Job entity named by |job_name|. This function was made to make
  mocking easier."""
  return data_types.Job.query(data_types.Job.name == job_name).get()


def _get_swarming_config():
  """Returns the swarming config. This function was made to make mocking easier."""
  return local_config.SwarmingConfig()


def _get_new_task_spec(command: str, job_name: str, download_url: str):
  """Gets the configured specifications for a swarming task."""
  job = _get_job(job_name)
  config_name = job.platform
  if command == 'fuzz':
    config_name += '-PREEMPTIBLE'
  else:
    config_name += '-NONPREEMPTIBLE'
  swarming_config = _get_swarming_config()
  instance_spec = swarming_config.get('mapping').get(config_name, None)
  if instance_spec is None:
    raise ValueError(f'No mapping for {config_name}')
  swarming_pool = swarming_config.get('swarming_pool')
  swarming_realm = swarming_config.get('swarming_realm')
  # The command to launch the startup script
  command = instance_spec['command']
  # The cas instance storing the startup script
  cas_instance = instance_spec['cas_instance']
  # The startup script archive hash
  digest_hash = instance_spec['digest_hash']
  # The startup script size in bytes
  digest_size_bytes = instance_spec['digest_size_bytes']
  # The service account that the task runs as.
  service_account = instance_spec['service_account']
  return swarming_pb2.NewTaskRequest(
      name=get_task_name(),
      priority=1,
      realm=swarming_realm,
      service_account=service_account,
      task_slices=[
          swarming_pb2.TaskSlice(
              expiration_secs=86400,
              properties=swarming_pb2.TaskProperties(
                  command=[command],
                  dimensions=[
                      swarming_pb2.StringPair(key='os', value=job.platform),
                      swarming_pb2.StringPair(key='pool', value=swarming_pool)
                  ],
                  cas_input_root=swarming_pb2.CASReference(
                      cas_instance=cas_instance,
                      digest=swarming_pb2.Digest(
                          hash=digest_hash, size_bytes=digest_size_bytes)),
                  execution_timeout_secs=86400,
                  env=[
                      swarming_pb2.StringPair(
                          key='UWORKER_INPUT_DOWNLOAD_URL', value=download_url),
                      swarming_pb2.StringPair(key='UWORKER', value=True),
                      swarming_pb2.StringPair(key='SWARMING_BOT', value=True)
                  ]))
      ])


def push_swarming_task(command, download_url, job_type):
  """Schedules a task on swarming."""
  job = data_types.Job.query(data_types.Job.name == job_type).get()
  if not job:
    raise ValueError('invalid job_name')

  task_spec = _get_new_task_spec(command, job_type, download_url)
  creds, _ = credentials.get_default()
  headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': creds.token
  }
  swarming_server = _get_swarming_config().get('swarming_server')
  url = f'https://{swarming_server}/prpc/swarming.v2.Tasks/NewTask'
  r = requests.post(
      url=url, data=task_spec.SerializeToString(), headers=headers)
  logs.log(r.status_code)

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

import base64
import uuid

from google.protobuf import json_format

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.system import environment


def _requires_gpu() -> bool:
  """Checks whether the REQUIRES_GPU env variable is set. This means
  that the current job needs a gpu enabled device."""
  requires_gpu = environment.get_value('REQUIRES_GPU')
  return bool(utils.string_is_true(requires_gpu))


def is_swarming_task(command: str, job_name: str):
  """Returns True if the task is supposed to run on swarming."""
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if not job or not _requires_gpu():
    return False
  try:
    _get_new_task_spec(command, job_name, '')
    return True
  except ValueError:
    return False


def _get_task_name():
  return 't-' + str(uuid.uuid4()).lower()


def _get_swarming_config():
  """Returns the swarming config."""
  return local_config.SwarmingConfig()


def _get_new_task_spec(command: str, job_name: str,
                       download_url: str) -> swarming_pb2.NewTaskRequest:  # pylint: disable=no-member
  """Gets the configured specifications for a swarming task."""
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  config_name = job.platform
  swarming_config = _get_swarming_config()
  instance_spec = swarming_config.get('mapping').get(config_name, None)
  if instance_spec is None:
    raise ValueError(f'No mapping for {config_name}')
  swarming_pool = swarming_config.get('swarming_pool')
  swarming_realm = swarming_config.get('swarming_realm')
  logs_project_id = swarming_config.get('logs_project_id')
  priority = instance_spec['priority']
  startup_command = instance_spec['command']
  # The service account that the task runs as.
  service_account = instance_spec['service_account_email']
  # If this task request slice is not scheduled after waiting this long,
  # the task state will be set to EXPIRED.
  expiration_secs = instance_spec['expiration_secs']
  # Maximum number of seconds the task can run before its process is
  # forcibly terminated and the task results in TIMED_OUT.
  execution_timeout_secs = instance_spec['execution_timeout_secs']
  if command == 'fuzz':
    execution_timeout_secs = swarming_config.get('fuzz_task_duration')

  # The cipd_input contains the cipd_packages that need to be installed
  # before running the task (if any).
  cipd_input = instance_spec.get('cipd_input', {})
  # env_prefixes allows the modification of existing environment variables by
  # adding the values as prefixes to the env variable.
  env_prefixes = instance_spec.get('env_prefixes', {})
  task_environment = [
      swarming_pb2.StringPair(key='UWORKER', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(key='SWARMING_BOT', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(  # pylint: disable=no-member
          key='LOGGING_CLOUD_PROJECT_ID',
          value=logs_project_id),
  ]

  env = instance_spec.get('env', None)
  if env:
    for var in env:
      task_environment.append(
          swarming_pb2.StringPair(key=var['key'], value=var['value']))  # pylint: disable=no-member

  if instance_spec.get('docker_image'):
    task_environment.append(
        swarming_pb2.StringPair(  # pylint: disable=no-member
            key='DOCKER_IMAGE',
            value=instance_spec['docker_image']))

  task_dimensions = [
      swarming_pb2.StringPair(key='os', value=job.platform),  # pylint: disable=no-member
      swarming_pb2.StringPair(key='pool', value=swarming_pool)  # pylint: disable=no-member
  ]

  dimensions = instance_spec.get('dimensions', None)
  if dimensions:
    for dimension in dimensions:
      task_dimensions.append(
          swarming_pb2.StringPair(  # pylint: disable=no-member
              key=dimension['key'],
              value=dimension['value']))

  cas_input_root = instance_spec.get('cas_input_root', {})

  new_task_request = swarming_pb2.NewTaskRequest(  # pylint: disable=no-member
      name=_get_task_name(),
      priority=priority,
      realm=swarming_realm,
      service_account=service_account,
      task_slices=[
          swarming_pb2.TaskSlice(  # pylint: disable=no-member
              expiration_secs=expiration_secs,
              properties=swarming_pb2.TaskProperties(  # pylint: disable=no-member
                  command=startup_command,
                  dimensions=task_dimensions,
                  cipd_input=cipd_input,
                  cas_input_root=cas_input_root,
                  execution_timeout_secs=execution_timeout_secs,
                  env=task_environment,
                  env_prefixes=env_prefixes,
                  secret_bytes=base64.b64encode(download_url.encode('utf-8'))))
      ])

  return new_task_request


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
  utils.post_url(
      url=url, data=json_format.MessageToJson(task_spec), headers=headers)

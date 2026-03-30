# Copyright 2026 Google LLC
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
"""Swarming service."""

import base64
import json
import uuid

from google.auth.transport import requests
from google.protobuf import json_format

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.feature_flags import FeatureFlags
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.system import environment

_SWARMING_SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/userinfo.email'
]


def is_swarming_task(command: str, job_name: str) -> bool:
  """Returns True if the task is supposed to run on swarming.

  Args:
    command: The command to run (e.g. 'fuzz').
    job_name: The name of the job.

  Returns:
    True if the task should run on swarming, False otherwise.
  """
  if not FeatureFlags.SWARMING_REMOTE_EXECUTION.enabled:
    return False
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if not job:
    return False

  job_environment = job.get_environment()
  if not utils.string_is_true(job_environment.get('IS_SWARMING_JOB')):
    return False

  try:
    _get_new_task_spec(command, job_name, '')
    return True
  except ValueError:
    return False


def _get_task_name() -> str:
  """Returns a unique task name."""
  return 't-' + str(uuid.uuid4()).lower()


def _get_swarming_config():
  """Returns the swarming configuration."""
  return local_config.SwarmingConfig()


def _get_task_dimensions(job: data_types.Job, platform_specific_dimensions: list
                        ) -> list[swarming_pb2.StringPair]:  # pylint: disable=no-member
  """Gets all swarming dimensions for a task.

  Job dimensions have more precedence than static dimensions.

  Args:
    job: The Job entity.
    platform_specific_dimensions: A list of platform-specific dimensions.

  Returns:
    A list of swarming_pb2.StringPair dimensions.
  """
  unique_dimensions = {}
  unique_dimensions['os'] = job.platform
  unique_dimensions['pool'] = _get_swarming_config().get('swarming_pool')

  for dimension in platform_specific_dimensions:
    unique_dimensions[dimension['key'].lower()] = dimension['value']

  swarming_dimensions = environment.get_value('SWARMING_DIMENSIONS')
  if isinstance(swarming_dimensions, dict):
    for key, value in swarming_dimensions.items():
      unique_dimensions[key.lower()] = value

  task_dimensions = []
  for dimension, value in unique_dimensions.items():
    task_dimensions.append(
        swarming_pb2.StringPair(  # pylint: disable=no-member
            key=dimension, value=value))
  return task_dimensions


def _env_vars_to_json(
    env_vars: list[swarming_pb2.StringPair]) -> swarming_pb2.StringPair:  # pylint: disable=no-member
  """Compresses environment variables into a single JSON string.

  This JSON string will be used to set up the environment variables in
  swarming bots that launch ClusterFuzz using a docker container.

  Args:
    env_vars: A list of swarming_pb2.StringPair environment variables.

  Returns:
    A swarming_pb2.StringPair containing the JSON-encoded environment variables.
  """
  env_vars_dict = {pair.key: pair.value for pair in env_vars}
  return swarming_pb2.StringPair(  # pylint: disable=no-member
      key='DOCKER_ENV_VARS',
      value=json.dumps(env_vars_dict))


def _get_new_task_spec(command: str, job_name: str,
                       download_url: str) -> swarming_pb2.NewTaskRequest:  # pylint: disable=no-member
  """Gets the configured specifications for a swarming task.

  Args:
    command: The command to run.
    job_name: The name of the job.
    download_url: The URL to download the task input.

  Returns:
    A swarming_pb2.NewTaskRequest containing the task specification.

  Raises:
    ValueError: If no mapping is found for the job's platform.
  """
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  config_name = job.platform
  swarming_config = _get_swarming_config()
  instance_spec = swarming_config.get('mapping').get(config_name, None)
  if instance_spec is None:
    raise ValueError(f'No mapping for {config_name}')
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
  default_task_environment = [
      swarming_pb2.StringPair(key='UWORKER', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(key='SWARMING_BOT', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(  # pylint: disable=no-member
          key='LOGGING_CLOUD_PROJECT_ID',
          value=logs_project_id),
  ]

  platform_specific_env = instance_spec.get('env', [])
  swarming_bot_environment = []
  swarming_bot_environment.append(
      swarming_pb2.StringPair(  # pylint: disable=no-member
          key='DOCKER_IMAGE',
          value=instance_spec.get('docker_image', '')))
  for var in platform_specific_env:
    swarming_bot_environment.append(
        swarming_pb2.StringPair(key=var['key'], value=var['value']))  # pylint: disable=no-member
  swarming_bot_environment.append(_env_vars_to_json(default_task_environment))
  swarming_bot_environment.extend(default_task_environment)
  dimensions = instance_spec.get('dimensions', [])
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
                  dimensions=_get_task_dimensions(job, dimensions),
                  cipd_input=cipd_input,
                  cas_input_root=cas_input_root,
                  execution_timeout_secs=execution_timeout_secs,
                  env=swarming_bot_environment,
                  env_prefixes=env_prefixes,
                  secret_bytes=base64.b64encode(download_url.encode('utf-8'))))
      ])

  return new_task_request


def push_swarming_task(command: str, download_url: str, job_type: str):
  """Schedules a task on swarming.

  Args:
    command: The command to run.
    download_url: The URL to download the task input.
    job_type: The name of the job.

  Raises:
    ValueError: If the job_type is invalid.
  """
  job = data_types.Job.query(data_types.Job.name == job_type).get()
  if not job:
    raise ValueError('invalid job_name')

  task_spec = _get_new_task_spec(command, job_type, download_url)
  creds, _ = credentials.get_default(_SWARMING_SCOPES)

  if not creds.token:
    creds.refresh(requests.Request())

  headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': f'Bearer {creds.token}'
  }
  swarming_server = _get_swarming_config().get('swarming_server')
  url = f'https://{swarming_server}/prpc/swarming.v2.Tasks/NewTask'
  utils.post_url(
      url=url, data=json_format.MessageToJson(task_spec), headers=headers)


class SwarmingService(remote_task_types.RemoteTaskInterface):
  """Remote task service implementation for Swarming."""

  def create_utask_main_job(self, module: str, job_type: str,
                            input_download_url: str):
    """Creates a single swarming task for a uworker main task."""
    command = task_utils.get_command_from_module(module)
    swarming_task = remote_task_types.RemoteTask(command, job_type,
                                                 input_download_url)
    result = self.create_utask_main_jobs([swarming_task])

    if not result:
      return None

    return result[0]

  def create_utask_main_jobs(self,
                             remote_tasks: list[remote_task_types.RemoteTask]
                            ) -> list[remote_task_types.RemoteTask]:
    """Creates many remote tasks for uworker main tasks.

    Returns the tasks that couldn't be created.
    """
    unscheduled_tasks = []
    for task in remote_tasks:
      try:
        if not is_swarming_task(task.command, task.job_type):
          unscheduled_tasks.append(task)
          continue

        push_swarming_task(task.command, task.input_download_url, task.job_type)
      except Exception:  # pylint: disable=broad-except
        logs.error(
            f'Failed to push task to Swarming: {task.command}, {task.job_type}.'
        )
        unscheduled_tasks.append(task)
    return unscheduled_tasks

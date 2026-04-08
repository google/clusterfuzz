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
import json
import uuid

from google.auth.transport import requests
from google.protobuf import json_format

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.errors import BadConfigError
from clusterfuzz._internal.base.feature_flags import FeatureFlags
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import compute_metadata
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.system import environment

_SWARMING_SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/userinfo.email'
]


def is_swarming_task(job_name: str, job: data_types.Job | None = None) -> bool:
  """Returns True if the task is supposed to run on swarming."""
  if not FeatureFlags.SWARMING_REMOTE_EXECUTION.enabled:
    logs.info('[DEBUG] Flag is disabled', job_name=job_name)
    return False
  if job is None:
    job = data_types.Job.query(data_types.Job.name == job_name).get()
    if not job:
      logs.info('[Swarming DEBUG] Job not found', job_name=job_name)
      return False

  job_environment = job.get_environment()
  if not utils.string_is_true(job_environment.get(
      'IS_SWARMING_JOB')) and not job_environment.get('SWARMING_DIMENSIONS'):
    logs.info('[Swarming DEBUG] No swarming env var', job_name=job_name)
    return False

  swarming_config = _get_swarming_config()
  if swarming_config is None:
    logs.warning(
        """[Swarming DEBUG] current task is not suitable for swarming. 
    'Reason: failed to retrieve config.""",
        job_name=job_name)
    return False

  return _get_instance_spec(swarming_config, job) is not None


def _get_instance_spec(swarming_config: local_config.SwarmingConfig,
                       job: data_types.Job) -> dict | None:
  return swarming_config.get('mapping').get(job.platform, None)


def _get_task_name(job_name: str):
  return f't-{str(uuid.uuid4()).lower()}-{job_name}'


def _get_swarming_config() -> local_config.SwarmingConfig | None:
  """Returns the swarming config."""
  try:
    return local_config.SwarmingConfig()
  except (BadConfigError, ValueError) as e:
    logs.error(f'[Swarming] Failed to retrieve config: {e}')
    return None


def _get_task_dimensions(job: data_types.Job, platform_specific_dimensions: list
                        ) -> list[swarming_pb2.StringPair]:  # pylint: disable=no-member
  """ Gets all swarming dimensions for a task.
  Job dimensions have more precedence than static dimensions"""
  swarming_config = _get_swarming_config()
  if not swarming_config:
    logs.error(
        '[Swarming] No dimensions set. Reason: failed to retrieve config')
    return []

  unique_dimensions = {}
  unique_dimensions['os'] = str(job.platform).capitalize()
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


def _append_metadata_env_var(
    env_vars: list[swarming_pb2.StringPair],  # pylint: disable=no-member
    env_var_name: str,
    metadata_path: str):
  """Attempts to get a variable from the environment
  or metadata and appends it."""
  value = environment.get_value(env_var_name)
  if not value:
    try:
      value = compute_metadata.get(metadata_path)
    except Exception:
      pass

  if value:
    env_vars.append(
        swarming_pb2.StringPair(  # pylint: disable=no-member
            key=env_var_name, value=str(value)))
  else:
    logs.warning(f'{env_var_name} is not set or cannot be fetched.')


def _get_env_vars(logs_project_id: str,
                  instance_spec: dict) -> list[swarming_pb2.StringPair]:  # pylint: disable=no-member
  """Retrieve required environment variables from metadata and config."""
  default_task_environment = [
      swarming_pb2.StringPair(key='UWORKER', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(key='SWARMING_BOT', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(key='IS_K8S_ENV', value='True'),  # pylint: disable=no-member
      swarming_pb2.StringPair(  # pylint: disable=no-member
          key='LOGGING_CLOUD_PROJECT_ID',
          value=logs_project_id or ''),
  ]

  _append_metadata_env_var(default_task_environment, 'DEPLOYMENT_BUCKET',
                           'project/attributes/deployment-bucket')
  _append_metadata_env_var(default_task_environment, 'HOST_JOB_SELECTION',
                           'instance/attributes/host-job-selection')
  _append_metadata_env_var(default_task_environment, 'DEPLOYMENT_ZIP',
                           'project/attributes/deployment-zip')

  env_vars = []
  env_vars.append(
      swarming_pb2.StringPair(  # pylint: disable=no-member
          key='DOCKER_IMAGE',
          value=instance_spec.get('docker_image', '')))

  platform_specific_env = instance_spec.get('env', [])
  for var in platform_specific_env:
    env_vars.append(swarming_pb2.StringPair(key=var['key'], value=var['value']))  # pylint: disable=no-member

  env_vars.append(_env_vars_to_json(default_task_environment))
  env_vars.extend(default_task_environment)

  return env_vars


def _env_vars_to_json(
    env_vars: list[swarming_pb2.StringPair]) -> swarming_pb2.StringPair:  # pylint: disable=no-member
  """
  Compresses all env variables into a single JSON string , which will be used
  to set up the env variables in swarming bots that launch clusterfuzz 
  using a docker container.
  """
  env_vars_dict = {pair.key: pair.value for pair in env_vars}
  return swarming_pb2.StringPair(  # pylint: disable=no-member
      key='DOCKER_ENV_VARS',
      value=json.dumps(env_vars_dict))


def create_new_task_request(command: str, job_name: str, download_url: str
                           ) -> swarming_pb2.NewTaskRequest | None:  # pylint: disable=no-member
  """Gets the configured specifications for a swarming task. 
  Returns None if the task should'nt be executed on swarming 
  or if the SWARMING_REMOTE_EXECUTION flag is disabled."""
  if not FeatureFlags.SWARMING_REMOTE_EXECUTION.enabled:
    return None

  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if job is None:
    return None

  swarming_config = _get_swarming_config()
  if not swarming_config:
    return None

  instance_spec = _get_instance_spec(swarming_config, job)
  if instance_spec is None:
    return None

  swarming_realm = swarming_config.get('swarming_realm',)
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
  swarming_bot_environment = _get_env_vars(logs_project_id, instance_spec)
  dimensions = instance_spec.get('dimensions', [])
  cas_input_root = instance_spec.get('cas_input_root', {})

  new_task_request = swarming_pb2.NewTaskRequest(  # pylint: disable=no-member
      name=_get_task_name(job_name),
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


def push_swarming_task(task_request: swarming_pb2.NewTaskRequest):  # pylint: disable=no-member
  """Schedules a task on swarming."""
  swarming_config = _get_swarming_config()
  if not swarming_config:
    logs.error(
        '[Swarming] Failed to push task into swarming. Reason: No config.')
    return
  creds = credentials.get_scoped_service_account_credentials(_SWARMING_SCOPES)
  if not creds:
    logs.error(
        '[Swarming] Failed to push task into swarming. Reason: No credentials.')
    return

  if not creds.token:
    creds.refresh(requests.Request())

  headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': f'Bearer {creds.token}'
  }
  swarming_server = _get_swarming_config().get('swarming_server')
  url = f'https://{swarming_server}/prpc/swarming.v2.Tasks/NewTask'
  message_body = json_format.MessageToJson(task_request)
  logs.info(
      f"""[Swarming] Pushing task {task_request.name}
            as {creds.service_account_email}""",
      url=url,
      body=message_body)
  response = utils.post_url(url=url, data=message_body, headers=headers)
  logs.info(f'[Swarming] Response from {task_request.name}', response=response)

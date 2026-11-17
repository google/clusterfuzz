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

from google.api_core import exceptions as api_exceptions
from google.cloud.ndb import exceptions as ndb_exceptions

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.errors import BadConfigError
from clusterfuzz._internal.base.feature_flags import FeatureFlags
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import compute_metadata
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.system import environment

# Swarming priorities range from 1 (highest) to 255 (lowest).
MAX_SWARMING_PRIORITY = 255
# Added to a platform's configured priority for fuzz tasks so non-fuzz tasks
# run first while preserving per-platform base priorities. We penalize fuzz
# instead of subtracting from non-fuzz because some platforms use priority 20,
# and Swarming clamps non-admin values below 20 back up to 20.
FUZZ_PRIORITY_PENALTY = 10


def has_swarming_env_vars(job_environment: dict) -> bool:
  """Returns True if the job environment contains swarming env vars."""
  return bool(
      utils.string_is_true(job_environment.get('IS_SWARMING_JOB')) or
      job_environment.get('SWARMING_DIMENSIONS'))


def is_swarming_enabled() -> bool:
  """Checks whether swarming is enabled in the current CF instance.

  Note: This method requires DB connection, else returns False.

  Returns:
    True if the current ClusterFuzz instance has swarming enabled.
  """
  try:
    return FeatureFlags.SWARMING_REMOTE_EXECUTION.enabled
  except (api_exceptions.PermissionDenied, ndb_exceptions.ContextError):
    logs.error(
        '[Swarming] Unauthorized bot tried to query the DB for FeatureFlag')
    return False


def is_swarming_job(job_name: str, job: data_types.Job | None = None) -> bool:
  """Validates that the current job is meant to be scheduled on swarming.

  Args:
    job_name: The name of the job.
    job: The job object, use if available to avoid querying datastore.

  Returns:
    True if the job is supposed to run on swarming.
  """
  if job is None:
    job = data_types.Job.query(data_types.Job.name == job_name).get()
    if not job:
      logs.debug('[Swarming] Job not found', job_name=job_name)
      return False

  if not has_swarming_env_vars(job.get_environment()):
    logs.debug('[Swarming] No swarming env var', job_name=job_name)
    return False

  swarming_config = get_swarming_config()
  if swarming_config is None:
    logs.warning(
        """[Swarming] current task is not suitable for swarming.
    Reason: failed to retrieve config.""",
        job_name=job_name)
    return False

  return _get_instance_spec(swarming_config, job) is not None


def is_swarming_applicable(job_name: str,
                           job: data_types.Job | None = None) -> bool:
  """Returns True if swarming remote execution is enabled and the job is a
  swarming job."""
  return is_swarming_enabled() and is_swarming_job(job_name, job=job)


def _get_instance_spec(swarming_config: local_config.SwarmingConfig,
                       job: data_types.Job) -> dict | None:
  return swarming_config.get('mapping').get(job.platform, None)


def _get_task_name(job_name: str):
  return f't-{uuid.uuid4().hex[:8]}-{job_name}'


def get_swarming_config() -> local_config.SwarmingConfig | None:
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
  swarming_config = get_swarming_config()
  if not swarming_config:
    logs.debug(
        '[Swarming] No dimensions set. Reason: failed to retrieve config')
    return []

  unique_dimensions = {}
  if job.platform == 'ANDROID_EMULATOR':
    unique_dimensions['os'] = 'Linux'
  else:
    unique_dimensions['os'] = str(job.platform).capitalize()
  unique_dimensions['pool'] = swarming_config.get('swarming_pool')

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


def _set_metadata_env_var(env_vars: dict[str, str], env_var_name: str,
                          metadata_path: str) -> None:
  """Attempts to get a variable from the environment or metadata and sets it.

  Args:
    env_vars: The dict of env vars to store the retrieved value in.
    env_var_name: The name of the environment variable to check and set.
    metadata_path: The path in the compute metadata to check if not set in env.
  """
  value = environment.get_value(env_var_name)
  if not value:
    try:
      value = compute_metadata.get(metadata_path)
    except Exception:
      pass

  if value:
    env_vars[env_var_name] = str(value)
  else:
    logs.info(f'[Swarming] Metadata {env_var_name} cannot be fetched.')


def _get_env_vars(logs_project_id: str,
                  instance_spec: dict) -> list[swarming_pb2.StringPair]:  # pylint: disable=no-member
  """Retrieve required environment variables from metadata and config."""
  default_task_environment = {
      'UWORKER': 'True',
      'SWARMING_BOT': 'True',
      'LOG_TO_GCP': 'True',
      'IS_K8S_ENV': 'True',
      'DISABLE_MOUNTS': 'True',
      'LOGGING_CLOUD_PROJECT_ID': logs_project_id or '',
  }

  _set_metadata_env_var(default_task_environment, 'DEPLOYMENT_BUCKET',
                        'project/attributes/deployment-bucket')
  _set_metadata_env_var(default_task_environment, 'HOST_JOB_SELECTION',
                        'instance/attributes/host-job-selection')
  _set_metadata_env_var(default_task_environment, 'DEPLOYMENT_ZIP',
                        'project/attributes/deployment-zip')

  env_vars = {
      'DOCKER_IMAGE': instance_spec.get('docker_image', ''),
  }

  for key, value in default_task_environment.items():
    env_vars[key] = str(value)

  # Platform-specific env vars in swarming.yaml take precedence over scheduler
  # host/metadata defaults (e.g., DEPLOYMENT_ZIP=macos_arm64-3.zip over
  # linux-3.zip on Linux utask-main-scheduler hosts).
  platform_specific_env = instance_spec.get('env', [])
  for var in platform_specific_env:
    env_vars[var['key']] = str(var['value'])

  # Compress all env variables into a single JSON string, which is used to set
  # up the env variables in Swarming bots that launch ClusterFuzz using a
  # Docker container.
  env_vars['DOCKER_ENV_VARS'] = json.dumps(env_vars)

  return [
      swarming_pb2.StringPair(key=key, value=value)  # pylint: disable=no-member
      for key, value in env_vars.items()
  ]


def create_new_task_request(command: str, job_name: str, download_url: str
                           ) -> swarming_pb2.NewTaskRequest | None:  # pylint: disable=no-member
  """Gets the configured specifications for a swarming task.
  Returns None if the task shouldn't be executed on swarming."""

  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if job is None:
    logs.debug('[Swarming] Job not found', job_name=job_name)
    return None

  swarming_config = get_swarming_config()
  if not swarming_config:
    logs.debug('[Swarming] Config not found', job_name=job_name)
    return None

  instance_spec = _get_instance_spec(swarming_config, job)
  if instance_spec is None:
    logs.warning(
        '[Swarming] No matching spec in swarming config for job.',
        job_name=job_name)
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
    priority = min(priority + FUZZ_PRIORITY_PENALTY, MAX_SWARMING_PRIORITY)
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
      tags=[f'spec_name:clusterfuzz.{job.platform.lower()}:{command}'],
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
                  secret_bytes=download_url.encode('utf-8')))
      ])

  return new_task_request

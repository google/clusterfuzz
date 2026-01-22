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
"""Cloud Run remote task service."""

import collections
import typing
import uuid

import google.auth
from googleapiclient import discovery

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.system import environment

CloudRunJobConfig = collections.namedtuple('CloudRunJobConfig', [
    'job_type',
    'docker_image',
    'command',
    'disk_size_gb',
    'service_account_email',
    'clusterfuzz_release',
    'gce_region',
])


def _get_config_names(remote_tasks: typing.List[remote_task_types.RemoteTask]):
  """Gets the name of the configs for each batch_task."""
  job_names = {task.job_type for task in remote_tasks}
  query = data_types.Job.query(data_types.Job.name.IN(list(job_names)))
  jobs = ndb_utils.get_all_from_query(query)
  job_map = {job.name: job for job in jobs}
  config_map = {}
  for task in remote_tasks:
    if task.job_type not in job_map:
      logs.error(f"{task.job_type} doesn't exist.")
      continue
    if task.command == 'fuzz':
      suffix = '-PREEMPTIBLE-UNPRIVILEGED'
    else:
      suffix = '-NONPREEMPTIBLE-UNPRIVILEGED'
    job = job_map[task.job_type]
    platform = job.platform if not utils.is_oss_fuzz() else 'LINUX'
    disk_size_gb = environment.get_value(
        'DISK_SIZE_GB', env=job.get_environment())
    base_os_version = job.base_os_version
    if utils.is_oss_fuzz():
      oss_fuzz_project = data_types.OssFuzzProject.query(
          data_types.OssFuzzProject.name == job.project).get()
      if oss_fuzz_project and oss_fuzz_project.base_os_version:
        base_os_version = oss_fuzz_project.base_os_version
    config_map[(task.command, task.job_type)] = (f'{platform}{suffix}',
                                                 disk_size_gb, base_os_version)

  return config_map


def _get_cloud_run_job_configs(
    remote_tasks: typing.List[remote_task_types.RemoteTask]
) -> typing.Dict[typing.Tuple[str, str], CloudRunJobConfig]:
  """Gets the configured specifications for a Cloud Run workload."""
  if not remote_tasks:
    return {}

  batch_config = local_config.BatchConfig()
  config_map = _get_config_names(remote_tasks)
  configs = {}
  for task in remote_tasks:
    if (task.command, task.job_type) in configs:
      continue
    config_name, disk_size_gb, base_os_version = config_map[(task.command,
                                                             task.job_type)]
    instance_spec = batch_config.get('mapping').get(config_name)
    if instance_spec is None:
      raise ValueError(f'No mapping for {config_name}')

    versioned_images_map = instance_spec.get('versioned_docker_images')
    if (base_os_version and versioned_images_map and
        base_os_version in versioned_images_map):
      docker_image_uri = versioned_images_map[base_os_version]
    else:
      docker_image_uri = instance_spec['docker_image']

    disk_size_gb = (disk_size_gb or instance_spec['disk_size_gb'])
    clusterfuzz_release = instance_spec.get('clusterfuzz_release', 'prod')

    # Cloud Run needs a region. We can pick one from subconfigs or use a default.
    # For now, let's pick the first one from subconfigs if available.
    gce_region = 'us-central1'
    subconfigs = instance_spec.get('subconfigs')
    if subconfigs:
      subconfig_name = subconfigs[0]['name']
      gce_region = batch_config.get('subconfigs').get(subconfig_name).get(
          'region', gce_region)

    config = CloudRunJobConfig(
        job_type=task.job_type,
        docker_image=docker_image_uri,
        command=task.command,
        disk_size_gb=disk_size_gb,
        service_account_email=instance_spec['service_account_email'],
        clusterfuzz_release=clusterfuzz_release,
        gce_region=gce_region,
    )
    configs[(task.command, task.job_type)] = config

  return configs


class CloudRunService(remote_task_types.RemoteTaskInterface):
  """Cloud Run remote task service implementation."""

  def __init__(self):
    credentials, _ = google.auth.default()
    self._client = discovery.build('run', 'v2', credentials=credentials)
    self._project = utils.get_application_id()

  def create_job(self, config: CloudRunJobConfig, input_url: str) -> str:
    """Creates a Cloud Run job."""
    job_id = f'cf-job-{str(uuid.uuid4())}'.lower()
    parent = f'projects/{self._project}/locations/{config.gce_region}'

    # Cloud Run Job body
    body = {
        'template': {
            'template': {
                'containers': [{
                    'image':
                        config.docker_image,
                    'env': [
                        {
                            'name': 'HOST_UID',
                            'value': '1337'
                        },
                        {
                            'name': 'CLUSTERFUZZ_RELEASE',
                            'value': config.clusterfuzz_release
                        },
                        {
                            'name': 'UNTRUSTED_WORKER',
                            'value': 'False'
                        },
                        {
                            'name': 'UWORKER',
                            'value': 'True'
                        },
                        {
                            'name': 'USE_GCLOUD_STORAGE_RSYNC',
                            'value': '1'
                        },
                        {
                            'name': 'UWORKER_INPUT_DOWNLOAD_URL',
                            'value': input_url
                        },
                    ],
                    'resources': {
                        'limits': {
                            'cpu': '2',
                            'memory': '4Gi'
                        }
                    }
                }],
                'serviceAccount': config.service_account_email,
                'maxRetries': 0,
                'timeout': f'{tasks.get_task_duration(config.command)}s',
            }
        }
    }

    # Create the job
    # pylint: disable=no-member
    request = self._client.projects().locations().jobs().create(
        parent=parent, body=body, jobId=job_id)
    response = request.execute()

    # After creating the job, we need to execute it (create an execution)
    job_name = response['name']
    execute_request = self._client.projects().locations().jobs().run(
        name=job_name)
    execute_request.execute()

    logs.info(f'Created and started Cloud Run job {job_id} in {config.gce_region}.')
    return job_name

  def create_utask_main_job(self, module: str, job_type: str,
                            input_download_url: str):
    """Creates a single Cloud Run job for a uworker main task."""
    command = task_utils.get_command_from_module(module)
    remote_tasks = [
        remote_task_types.RemoteTask(command, job_type, input_download_url)
    ]
    result = self.create_utask_main_jobs(remote_tasks)
    return result[0] if result else None

  def create_utask_main_jobs(
      self, remote_tasks: typing.List[remote_task_types.RemoteTask]):
    """Creates multiple Cloud Run jobs."""
    configs = _get_cloud_run_job_configs(remote_tasks)
    jobs = []
    for task in remote_tasks:
      config = configs.get((task.command, task.job_type))
      if not config:
        continue
      jobs.append(self.create_job(config, task.input_download_url))
    return jobs

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
"""Cloud Run service."""
import collections
import os
from typing import Dict
from typing import List
import uuid

import google.auth
from googleapiclient import discovery
from googleapiclient import errors
import jinja2
import yaml

from clusterfuzz._internal.base import feature_flags
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.system import environment

CLOUD_RUN_JOBS_PENDING_LIMIT_DEFAULT = 1000

# A named tuple that defines the execution environment for a Cloud Run workload.
CloudRunWorkloadSpec = collections.namedtuple('CloudRunWorkloadSpec', [
    'clusterfuzz_release',
    'disk_size_gb',
    'disk_type',
    'docker_image',
    'user_data',
    'service_account_email',
    'subnetwork',
    'preemptible',
    'project',
    'machine_type',
    'network',
    'region',
    'max_run_duration',
    'cpu',
    'memory',
])

WeightedSubconfig = collections.namedtuple('WeightedSubconfig',
                                           ['name', 'weight'])


def _get_batch_config():
  """Returns the batch config."""
  return local_config.BatchConfig()


def _get_config_names(remote_tasks: List[remote_task_types.RemoteTask]):
  """Gets the name of the configs for each task."""
  job_names = {task.job_type for task in remote_tasks}
  query = data_types.Job.query(data_types.Job.name.IN(list(job_names)))
  jobs = ndb_utils.get_all_from_query(query)
  job_map = {job.name: job for job in jobs}
  config_map = {}
  for task in remote_tasks:
    if task.job_type not in job_map:
      print(f"{task.job_type} doesn't exist.")
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


def _get_subconfig(batch_config, instance_spec):
  all_subconfigs = batch_config.get('subconfigs', {})
  instance_subconfigs = instance_spec['subconfigs']
  weighted_subconfigs = [
      WeightedSubconfig(subconfig['name'], subconfig['weight'])
      for subconfig in instance_subconfigs
  ]
  weighted_subconfig = utils.random_weighted_choice(weighted_subconfigs)
  return all_subconfigs[weighted_subconfig.name]


def _get_specs_from_config(
    remote_tasks: List[remote_task_types.RemoteTask]) -> Dict:
  """Gets the configured specifications for a workload."""
  if not remote_tasks:
    return {}
  batch_config = _get_batch_config()
  config_map = _get_config_names(remote_tasks)
  specs = {}
  subconfig_map = {}
  for task in remote_tasks:
    if (task.command, task.job_type) in specs:
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

    project_name = batch_config.get('project')
    clusterfuzz_release = instance_spec.get('clusterfuzz_release', 'prod')
    max_run_duration = f'{tasks.get_task_duration(task.command)}s'

    if config_name not in subconfig_map:
      subconfig = _get_subconfig(batch_config, instance_spec)
      subconfig_map[config_name] = subconfig

    disk_size_gb = (disk_size_gb or instance_spec['disk_size_gb'])
    subconfig = subconfig_map[config_name]

    # Cloud Run specific settings, falling back to defaults if not in config
    cpu = instance_spec.get('cpu', '2')
    memory = instance_spec.get('memory', '32Gi')

    spec = CloudRunWorkloadSpec(
        docker_image=docker_image_uri,
        disk_size_gb=disk_size_gb,
        disk_type=instance_spec['disk_type'],
        user_data=instance_spec['user_data'],
        service_account_email=instance_spec['service_account_email'],
        preemptible=instance_spec['preemptible'],
        machine_type=instance_spec['machine_type'],
        region=subconfig['region'],
        network=subconfig['network'],
        subnetwork=subconfig['subnetwork'],
        project=project_name,
        clusterfuzz_release=clusterfuzz_release,
        max_run_duration=max_run_duration,
        cpu=cpu,
        memory=memory,
    )
    specs[(task.command, task.job_type)] = spec
  return specs


def _create_job_body(spec: CloudRunWorkloadSpec, input_url: str,
                     job_name: str) -> dict:
  """Creates the body of a Cloud Run job."""

  # Set up Jinja2 environment and load the template.
  template_dir = os.path.dirname(__file__)
  jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
  template = jinja_env.get_template('job_template.yaml')

  context = {
      'max_run_duration':
          spec.max_run_duration,
      'service_account_email':
          spec.service_account_email,
      'docker_image':
          spec.docker_image,
      'cpu':
          spec.cpu,
      'memory':
          spec.memory,
      'clusterfuzz_release':
          spec.clusterfuzz_release,
      'input_url':
          input_url,
      'network':
          spec.network,
      'subnetwork':
          spec.subnetwork,
      'deployment_bucket':
          environment.get_value(
              'DEPLOYMENT_BUCKET',
              'deployment.clusterfuzz-development.appspot.com'),
      'job_name':
          job_name,
  }

  rendered_spec = template.render(context)
  return yaml.safe_load(rendered_spec)


class CloudRunService(remote_task_types.RemoteTaskInterface):
  """Cloud Run Service."""

  def __init__(self):
    credentials, _ = google.auth.default()
    self._service = discovery.build('run', 'v2', credentials=credentials)

  def _get_pending_executions_count(self, project: str, region: str) -> int:
    """Returns the number of pending/running executions."""
    parent = f'projects/{project}/locations/{region}'
    try:
      request = self._service.projects().locations().executions().list(
          parent=parent, showDeleted=False)
      response = request.execute()
      executions = response.get('executions', [])

      active_count = 0
      for execution in executions:
        if 'completionTime' not in execution:
          active_count += 1

      return active_count
    except Exception as e:
      print(f'Failed to list executions in {region}: {e}')
      return 0

  def create_job(self, spec: CloudRunWorkloadSpec, input_url: str):
    """Creates a Cloud Run job."""
    job_name = f'j-{str(uuid.uuid4()).lower()}'
    parent = f'projects/{spec.project}/locations/{spec.region}'
    job_full_name = f'{parent}/jobs/{job_name}'
    print(spec)
    body = _create_job_body(spec, input_url, job_name)
    print(body)
    try:
      request = self._service.projects().locations().jobs().create(
          parent=parent, jobId=job_name, body=body)
      operation = request.execute()
      print(operation)
      print(f'Created Cloud Run job {job_name}.')

      # We also need to RUN the job immediately after creating it
      run_request = self._service.projects().locations().jobs().run(
          name=job_full_name)
      run_operation = run_request.execute()
      print(f'Started Cloud Run job {job_name}.')
      return run_operation

    except Exception as e:
      print(f'Failed to create/run Cloud Run job {job_name}: {e}')
      raise

  def create_utask_main_job(self, module: str, job_type: str,
                            input_download_url: str):
    """Creates a single Cloud Run job for a uworker main task."""
    command = task_utils.get_command_from_module(module)
    batch_tasks = [
        remote_task_types.RemoteTask(command, job_type, input_download_url)
    ]
    result = self.create_utask_main_jobs(batch_tasks)
    if not result:
      return None
    return result[0]

  def create_utask_main_jobs(self,
                             remote_tasks: List[remote_task_types.RemoteTask]):
    """Creates Cloud Run jobs for a list of uworker main tasks."""
    spec_map = collections.defaultdict(list)
    specs = _get_specs_from_config(remote_tasks)

    for remote_task in remote_tasks:
      print(f'Scheduling {remote_task.command}, {remote_task.job_type}.')
      spec = specs[(remote_task.command, remote_task.job_type)]
      spec_map[spec].append(remote_task)

    uncreated_tasks = []
    checked_regions = {}

    flag = feature_flags.FeatureFlags.CLOUD_RUN_JOBS_PENDING_LIMIT.flag
    limit = int(
        flag.value
    ) if flag and flag.enabled else CLOUD_RUN_JOBS_PENDING_LIMIT_DEFAULT

    print('Creating Cloud Run jobs.')
    for spec, tasks in spec_map.items():
      region = spec.region
      project = spec.project

      if region not in checked_regions:
        checked_regions[region] = self._get_pending_executions_count(
            project, region)

      if checked_regions[region] >= limit:
        print(
            f'Pending executions {checked_regions[region]} in {region} reached limit {limit}.'
        )
        uncreated_tasks.extend(tasks)
        continue

      for task in tasks:
        self.create_job(spec, task.input_download_url)

    return uncreated_tasks

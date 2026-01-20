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
"""Kubernetes batch client."""
import base64
import collections
import os
import tempfile
import typing
import uuid

import google.auth
from google.auth.transport import requests as google_requests
from googleapiclient import discovery
import jinja2
from kubernetes import client as k8s_client
import yaml

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.system import environment

CLUSTER_NAME = 'clusterfuzz-cronjobs-gke'

KubernetesJobConfig = collections.namedtuple('KubernetesJobConfig', [
    'job_type',
    'docker_image',
    'command',
    'disk_size_gb',
    'service_account_email',
    'clusterfuzz_release',
    'is_kata',
])


def _get_config_names(remote_tasks: typing.List[remote_task_types.RemoteTask]):
  """"Gets the name of the configs for each batch_task. Returns a dict

  that is indexed by command and job_type for efficient lookup."""

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
    # Get the OS version from the job, this is the least specific version.
    base_os_version = job.base_os_version
    # If we are running in the oss-fuzz context, the project-specific config
    # is more specific and overrides the job-level one.
    if utils.is_oss_fuzz():
      oss_fuzz_project = data_types.OssFuzzProject.query(
          data_types.OssFuzzProject.name == job.project).get()
      if oss_fuzz_project and oss_fuzz_project.base_os_version:
        base_os_version = oss_fuzz_project.base_os_version
    config_map[(task.command, task.job_type)] = (f'{platform}{suffix}',
                                                 disk_size_gb, base_os_version)

  return config_map


def _get_k8s_job_configs(
    remote_tasks: typing.List[remote_task_types.RemoteTask]
) -> typing.Dict[typing.Tuple[str, str], KubernetesJobConfig]:
  """Gets the configured specifications for a batch workload."""

  if not remote_tasks:
    return {}
  # TODO(javanlacerda): Create remote task config
  batch_config = local_config.BatchConfig()
  config_map = _get_config_names(remote_tasks)
  configs = {}
  for task in remote_tasks:
    if (task.command, task.job_type) in configs:
      # Don't repeat work for no reason.
      continue
    config_name, disk_size_gb, base_os_version = config_map[(task.command,
                                                             task.job_type)]
    instance_spec = batch_config.get('mapping').get(config_name)
    if instance_spec is None:
      raise ValueError(f'No mapping for {config_name}')
    # Decide which docker image to use.
    versioned_images_map = instance_spec.get('versioned_docker_images')
    if (base_os_version and versioned_images_map and
        base_os_version in versioned_images_map):
      # New path: Use the versioned image if specified and available.
      docker_image_uri = versioned_images_map[base_os_version]
    else:
      # Fallback/legacy path: Use the original docker_image key.
      docker_image_uri = instance_spec['docker_image']
    disk_size_gb = (disk_size_gb or instance_spec['disk_size_gb'])
    clusterfuzz_release = instance_spec.get('clusterfuzz_release', 'prod')
    config = KubernetesJobConfig(
        job_type=task.job_type,
        docker_image=docker_image_uri,
        command=task.command,
        disk_size_gb=disk_size_gb,
        service_account_email=instance_spec['service_account_email'],
        clusterfuzz_release=clusterfuzz_release,
        is_kata=instance_spec.get('is_kata', True),
    )
    configs[(task.command, task.job_type)] = config

  return configs


def _create_job_body(config: KubernetesJobConfig, input_url: str,
                     service_account_name: str) -> dict:
  """Creates the body of a Kubernetes job."""

  job_name = f'cf-job-{str(uuid.uuid4())}'
  job_name = job_name.lower()

  # Set up Jinja2 environment and load the template.
  template_dir = os.path.dirname(__file__)
  jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
  template = jinja_env.get_template('job_template.yaml')

  # Define the context with all the dynamic values.
  context = {
      'job_name': job_name,
      'active_deadline_seconds': tasks.get_task_duration(config.command),
      'service_account_name': service_account_name,
      'docker_image': config.docker_image,
      'clusterfuzz_release': config.clusterfuzz_release,
      'input_url': input_url,
      'is_kata': config.is_kata,
      'task_name': config.command,
      'clusterfuzz_job_name': config.job_type,
      'restart_policy': 'Never' if config.command == 'fuzz' else 'OnFailure'
  }

  # Render the template and load as YAML.
  rendered_spec = template.render(context)
  return yaml.safe_load(rendered_spec)


class KubernetesService(remote_task_types.RemoteTaskInterface):
  """A remote task execution client for Kubernetes."""

  def __init__(self, k8s_config_loaded: bool = False):
    # In e2e tests, the kubeconfig is already loaded by the test setup.
    if not k8s_config_loaded:
      self._load_gke_credentials()

    self._core_api = k8s_client.CoreV1Api()
    self._batch_api = k8s_client.BatchV1Api()

  def _load_gke_credentials(self):
    """Loads GKE credentials and configures the Kubernetes client."""
    credentials, _ = google.auth.default()
    project = utils.get_application_id()
    service = discovery.build('container', 'v1', credentials=credentials)
    parent = f"projects/{project}/locations/-"

    try:
      # pylint: disable=no-member
      response = service.projects().locations().clusters().list(
          parent=parent).execute()
      clusters = response.get('clusters', [])
      cluster = next((c for c in clusters if c['name'] == CLUSTER_NAME), None)

      if not cluster:
        logs.error(f"Cluster {CLUSTER_NAME} not found in project {project}.")
        print(f"DEBUG: Cluster {CLUSTER_NAME} not found in project {project}.")
        return

    except Exception as e:
      logs.error(f"Failed to list clusters in {project}: {e}")
      return

    endpoint = cluster['endpoint']
    # ca_cert is base64 encoded.
    ca_cert = base64.b64decode(cluster['masterAuth']['clusterCaCertificate'])

    # Write CA cert to a temporary file.
    fd, ca_cert_path = tempfile.mkstemp()
    with os.fdopen(fd, 'wb') as f:
      f.write(ca_cert)

    configuration = k8s_client.Configuration()
    configuration.host = f'https://{endpoint}'
    configuration.ssl_ca_cert = ca_cert_path
    configuration.verify_ssl = True

    def get_token(creds):
      request = google_requests.Request()
      if not creds.valid or creds.expired:
        creds.refresh(request)
      return {"authorization": "Bearer " + creds.token}

    configuration.refresh_api_key_hook = lambda _: get_token(credentials)
    configuration.api_key = get_token(credentials)

    k8s_client.Configuration.set_default(configuration)
    logs.info("GKE credentials loaded successfully.")

  def _create_service_account_if_needed(self,
                                        service_account_email: str) -> str:
    """Creates a Kubernetes Service Account if it doesn't exist."""
    service_account_name = service_account_email.split('@')[0]
    namespace = 'default'
    try:
      self._core_api.read_namespaced_service_account(service_account_name,
                                                     namespace)
      return service_account_name
    except k8s_client.rest.ApiException as e:
      if e.status != 404:
        raise

    logs.info(f'Creating Service Account {service_account_name} for '
              f'{service_account_email}.')
    metadata = k8s_client.V1ObjectMeta(
        name=service_account_name,
        annotations={'iam.gke.io/gcp-service-account': service_account_email})
    body = k8s_client.V1ServiceAccount(metadata=metadata)
    self._core_api.create_namespaced_service_account(namespace, body)
    return service_account_name

  def create_job(self, config: KubernetesJobConfig, input_url: str) -> str:
    """Creates a Kubernetes job.
    Args:
      config: The Kubernetes job configuration.
      input_url: The URL to be passed as an environment variable to the
        job's container.
    Returns:
      The name of the created Kubernetes job.
    """
    service_account_name = self._create_service_account_if_needed(
        config.service_account_email)
    job_body = _create_job_body(config, input_url, service_account_name)
    self._batch_api.create_namespaced_job(body=job_body, namespace='default')
    return job_body['metadata']['name']

  def _get_pending_jobs_count(self) -> int:
    """Returns the number of pending jobs."""
    try:
      pods = self._core_api.list_namespaced_pod(
          namespace='default',
          label_selector='app.kubernetes.io/name=clusterfuzz-kata-job',
          field_selector='status.phase=Pending')
      logs.info(f"Found {len(pods.items)} pending jobs.")
      return len(pods.items)
    except Exception as e:
      logs.error(f"Failed to list pods: {e}")
      return 0

  def create_utask_main_job(self, module: str, job_type: str,
                            input_download_url: str):
    """Creates a single batch job for a uworker main task."""

    command = task_utils.get_command_from_module(module)
    batch_tasks = [
        remote_task_types.RemoteTask(command, job_type, input_download_url)
    ]
    result = self.create_utask_main_jobs(batch_tasks)

    if result is None:
      return result
    return result[0]

  def create_utask_main_jobs(
      self, remote_tasks: typing.List[remote_task_types.RemoteTask]):
    """Creates a batch job for a list of uworker main tasks.

    This method groups the tasks by their workload specification and creates a
    separate batch job for each group. This allows tasks with similar
    requirements to be processed together, which can improve efficiency.
    """
    job_specs = collections.defaultdict(list)
    configs = _get_k8s_job_configs(remote_tasks)
    for remote_task in remote_tasks:
      logs.info(f'Scheduling {remote_task.command}, {remote_task.job_type}.')
      config = configs[(remote_task.command, remote_task.job_type)]
      job_specs[config].append(remote_task.input_download_url)
    logs.info('Creating batch jobs.')
    jobs = []
    logs.info('Batching utask_mains.')
    for config, input_urls in job_specs.items():
      for input_url in input_urls:
        jobs.append(self.create_job(config, input_url))

    return jobs

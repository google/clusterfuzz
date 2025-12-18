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
import collections
from typing import List
import uuid

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.batch.service import _get_specs_from_config
from clusterfuzz._internal.batch.service import MAX_CONCURRENT_VMS_PER_JOB
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.remote_task import RemoteTask
from clusterfuzz._internal.remote_task import RemoteTaskInterface


class KubernetesService(RemoteTaskInterface):
  """A remote task execution client for Kubernetes."""

  def __init__(self):
    k8s_config.load_kube_config()
    self._core_api = k8s_client.CoreV1Api()
    self._batch_api = k8s_client.BatchV1Api()

  def _create_job_client_wrapper(self, container_image: str, job_spec: dict,
                                 input_urls: List[str]) -> str:
    """Creates a Kubernetes job using the internal client."""
    job_body = job_spec

    # See https://github.com/kubernetes-client/python/blob/master/kubernetes/
    # docs/V1Job.md
    job_name = job_body['metadata']['name'] + '-' + str(uuid.uuid4()).split(
        '-', maxsplit=1)[0]
    job_body['metadata']['name'] = job_name
    container = job_body['spec']['template']['spec']['containers'][0]
    if 'env' not in container:
      container['env'] = []
    container['image'] = container_image
    container['env'].extend([{
        'name': f'UWORKER_INPUT_DOWNLOAD_URL_{i}',
        'value': url
    } for i, url in enumerate(input_urls)])

    self._batch_api.create_namespaced_job(body=job_body, namespace='default')
    return job_name

  def create_job(self, remote_task: RemoteTaskInterface,
                 input_urls: List[str]) -> str:
    """Creates a Kubernetes job.

    Args:
      remote_task: The remote task specification.
      input_urls: A list of URLs to be passed as environment variables to the
        job's container.
    Returns:
      The name of the created Kubernetes job.
    """
    # Default job spec for non-kata containers (needs to be defined).
    job_spec = {
        'apiVersion': 'batch/v1',
        'kind': 'Job',
        'metadata': {
            'name':
                remote_task.job_type  # Use job_type as base name
        },
        'spec': {
            'template': {
                'spec': {
                    'containers': [{
                        'name': 'clusterfuzz-worker',
                        'imagePullPolicy': 'IfNotPresent',
                        'command': ['echo', 'hello world']  # Default command
                    }],
                    'restartPolicy':
                        'Never'
                }
            },
            'backoffLimit': 0
        }
    }
    return self._create_job_client_wrapper(remote_task.docker_image, job_spec,
                                           input_urls)

  def create_uworker_main_batch_job(self, module: str, job_type: str,
                                    input_download_url: str):
    """Creates a single batch job for a uworker main task."""
    command = task_utils.get_command_from_module(module)
    batch_tasks = [RemoteTask(command, job_type, input_download_url)]
    result = self.create_uworker_main_batch_jobs(batch_tasks)
    if result is None:
      return result
    return result[0]

  def create_uworker_main_batch_jobs(self, batch_tasks: List[RemoteTask]):
    """Creates a batch job for a list of uworker main tasks.
    
    This method groups the tasks by their workload specification and creates a
    separate batch job for each group. This allows tasks with similar
    requirements to be processed together, which can improve efficiency.
    """
    job_specs = collections.defaultdict(list)
    specs = _get_specs_from_config(batch_tasks)
    for batch_task in batch_tasks:
      logs.info(f'Scheduling {batch_task.command}, {batch_task.job_type}.')
      spec = specs[(batch_task.command, batch_task.job_type)]
      job_specs[spec].append(batch_task.input_download_url)

    logs.info('Creating batch jobs.')
    jobs = []

    logs.info('Batching utask_mains.')
    for spec, input_urls in job_specs.items():
      for input_urls_portion in utils.batched(input_urls,
                                              MAX_CONCURRENT_VMS_PER_JOB - 1):
        jobs.append(self.create_job(spec, input_urls_portion))

    return jobs

  def create_kata_container_job(self, container_image: str,
                                input_urls: List[str]) -> str:
    """Creates a Kubernetes job that runs in a Kata container."""
    job_spec = {
        'apiVersion': 'batch/v1',
        'kind': 'Job',
        'metadata': {
            'name': 'clusterfuzz-kata-job'
        },
        'spec': {
            'template': {
                'metadata': {
                    'labels': {
                        'app.kubernetes.io/name': 'clusterfuzz-kata-job'
                    }
                },
                'spec': {
                    'runtimeClassName':
                        'kata',
                    'dnsPolicy':
                        'ClusterFirstWithHostNet',
                    'containers': [{
                        'name': 'clusterfuzz-worker',
                        'imagePullPolicy': 'IfNotPresent',
                        'lifecycle': {
                            'postStart': {
                                'exec': {
                                    'command': [
                                        '/bin/sh', '-c',
                                        'mkdir -p /tmp/.X11-unix && '
                                        'chmod 1777 /tmp/.X11-unix'
                                    ]
                                }
                            }
                        },
                        'securityContext': {
                            'privileged': True,
                            'capabilities': {
                                'add': ['SYS_ADMIN']
                            }
                        },
                        'resources': {
                            'requests': {
                                'cpu': '1',
                                'memory': '3.75Gi'
                            },
                            'limits': {
                                'cpu': '1',
                                'memory': '3.75Gi'
                            }
                        }
                    }],
                    'restartPolicy':
                        'Never',
                    'volumes': [{
                        'name': 'dshm',
                        'emptyDir': {
                            'medium': 'Memory',
                            'sizeLimit': '1.9G'
                        }
                    }],
                    'nodeSelector': {
                        'cloud.google.com/gke-nodepool': 'kata-enabled-pool'
                    }
                }
            },
            'backoffLimit': 0
        }
    }
    return self._create_job_client_wrapper(container_image, job_spec,
                                           input_urls)

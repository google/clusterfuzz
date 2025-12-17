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
"""Kubernetes service."""

from typing import List

from clusterfuzz._internal.k8s.service import KubernetesJobClient
from clusterfuzz._internal.metrics import logs


def create_job(job_name: str, container_image: str, job_spec: dict,
               input_urls: List[str]):
  """Creates a Kubernetes job.

  Args:
    job_name: The name of the Kubernetes job.
    container_image: The container image to use for the job.
    job_spec: A dictionary representing the Kubernetes job specification.
    input_urls: A list of URLs to be passed as environment variables to the
      job's container.
  """
  client = KubernetesJobClient(job_name, container_image, job_spec)
  client.create_job(None, input_urls)
  logs.info(f'Created Kubernetes job id={job_name}.')


def create_kata_container_job(job_name: str, container_image: str,
                              input_urls: List[str]):
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
  create_job(job_name, container_image, job_spec, input_urls)

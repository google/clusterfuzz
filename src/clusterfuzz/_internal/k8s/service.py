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
import logging
import time

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

from clusterfuzz._internal.remote_task import RemoteTaskInterface

# Time in seconds to wait for a job to be deleted.
DELETION_WAIT_TIMEOUT = 10


class KubernetesJobClient(RemoteTaskInterface):
  """A remote task execution client for Kubernetes."""

  def __init__(self, job_name, container_image, job_spec):
    self._job_name = job_name
    self._container_image = container_image
    self._job_spec = job_spec
    k8s_config.load_kube_config()
    self._core_api = k8s_client.CoreV1Api()
    self._batch_api = k8s_client.BatchV1Api()

  def _delete_job(self, job_name, namespace='default'):
    """Deletes a job and waits for it to be deleted."""
    try:
      self._batch_api.delete_namespaced_job(
          name=job_name,
          namespace=namespace,
          body=k8s_client.V1DeleteOptions(propagation_policy='Foreground'))
    except k8s_client.ApiException as e:
      if e.status == 404:
        logging.info('Job %s not found for deletion.', job_name)
        return
      raise

    # Wait for the job to be deleted.
    for _ in range(DELETION_WAIT_TIMEOUT):
      try:
        self._batch_api.read_namespaced_job(job_name, namespace)
        time.sleep(1)
      except k8s_client.ApiException as e:
        if e.status == 404:
          return
        raise
    logging.warning('Job %s was not deleted in time.', job_name)

  def create_job(self, spec, input_urls):
    """Creates a Kubernetes job."""
    self._delete_job(self._job_name)
    job_body = self._job_spec

    # See https://github.com/kubernetes-client/python/blob/master/kubernetes/
    # docs/V1Job.md
    job_body['metadata']['name'] = self._job_name
    container = job_body['spec']['template']['spec']['containers'][0]
    if 'env' not in container:
      container['env'] = []
    container['image'] = self._container_image
    container['env'].extend([{
        'name': f'UWORKER_INPUT_DOWNLOAD_URL_{i}',
        'value': url
    } for i, url in enumerate(input_urls)])

    self._batch_api.create_namespaced_job(body=job_body, namespace='default')

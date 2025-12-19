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
from clusterfuzz._internal.remote_task import RemoteTaskInterface


class KubernetesJobClient(RemoteTaskInterface):
  """A remote task execution client for Kubernetes.
  
  This class is a placeholder for a future implementation of a remote task
  execution client that uses Kubernetes. It is not yet implemented.
  """

  def create_job(self, spec, input_urls):
    """Creates a Kubernetes job."""
    raise NotImplementedError('Kubernetes batch client is not implemented yet.')

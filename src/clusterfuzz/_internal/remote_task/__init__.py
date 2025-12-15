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
"""Remote task interface.

This module defines the interface for a remote task execution client. This
abstraction allows ClusterFuzz to support multiple remote execution
environments, such as GCP Batch and Kubernetes, without tightly coupling
the task creation logic to a specific implementation.
"""
import abc


class RemoteTaskInterface(abc.ABC):
  """Interface for a remote task execution client.
  
  This interface defines the contract for a client that can create and manage
  remote jobs. Each client is responsible for translating a ClusterFuzz task
  specification into a job that can be executed in its target environment.
  """

  @abc.abstractmethod
  def create_job(self, spec, input_urls):
    """Creates a remote job.
    
    This method is responsible for creating a new job in the remote execution
    environment. It takes a workload specification and a list of input URLs,
    and returns a representation of the created job.
    """
    raise NotImplementedError

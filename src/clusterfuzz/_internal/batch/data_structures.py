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
"""Batch module data structures."""
import collections

# A named tuple that defines the execution environment for a batch workload.
# This includes details about the machine, disk, network, and container image,
# as well as ClusterFuzz-specific settings.
BatchWorkloadSpec = collections.namedtuple('BatchWorkloadSpec', [
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
    'gce_region',
    'priority',
    'max_run_duration',
    'retry',
])


class BatchTask:
  """Represents a single ClusterFuzz task to be executed on a remote worker.
  
  This class holds the necessary information to execute a ClusterFuzz command,
  such as 'fuzz' or 'progression', in a remote environment like GCP Batch. It
  is used to enqueue tasks and track their state.
  """

  def __init__(self, command, job_type, input_download_url):
    self.command = command
    self.job_type = job_type
    self.input_download_url = input_download_url

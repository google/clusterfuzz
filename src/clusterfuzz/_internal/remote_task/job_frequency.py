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
"""Configurable job frequencies for remote task execution.

This module provides a way to define how frequently certain jobs are executed
on different remote backends, such as GCP Batch and Kubernetes. This allows for
A/B testing and performance comparisons between the two platforms.
"""

from clusterfuzz._internal.system import environment

# By default, all jobs are sent to the GCP Batch backend. This can be
# overridden on a per-job basis by setting the `K8S_JOBS_FREQUENCY`
# environment variable.
DEFAULT_FREQUENCY = {'gcp_batch': 1.0, 'kubernetes': 0.0}


def get_job_frequency():
  """Returns the frequency for a given job.
  
  If the frequency is not explicitly defined in the `K8S_JOBS_FREQUENCY`
  environment variable, the default frequency is returned.
  """
  return DEFAULT_FREQUENCY
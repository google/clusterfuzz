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
DEFAULT_FREQUENCY = {'gcp_batch': 1.0, 'kubernetes': 0.3}


def _get_job_frequencies_from_env():
  """Parses the `K8S_JOBS_FREQUENCY` environment variable.
  
  The variable should be a comma-separated list of key-value pairs, where the
  key is the job name and the value is the frequency (a float between 0 and 1).
  For example: `libfuzzer_asan_chrome=0.5,libfuzzer_msan_chrome=0.2`.
  """
  job_frequencies = {}
  frequency_string = environment.get_value('K8S_JOBS_FREQUENCY')
  if not frequency_string:
    return {}

  for item in frequency_string.split(','):
    key, value = item.split('=')
    job_frequencies[key] = float(value)
  return job_frequencies


def get_job_frequency(job_name):
  """Returns the frequency for a given job.
  
  If the frequency is not explicitly defined in the `K8S_JOBS_FREQUENCY`
  environment variable, the default frequency is returned.
  """
  job_frequencies = _get_job_frequencies_from_env()
  if job_name in job_frequencies:
    kubernetes_frequency = job_frequencies[job_name]
    return {
        'gcp_batch': 1.0 - kubernetes_frequency,
        'kubernetes': kubernetes_frequency
    }
  return DEFAULT_FREQUENCY

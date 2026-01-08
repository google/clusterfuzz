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

from clusterfuzz._internal.datastore import feature_flags
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

# By default, all jobs are sent to the GCP Batch backend. This can be
# overridden on a per-job basis by setting the `K8S_JOBS_FREQUENCY`
# feature flag.
DEFAULT_FREQUENCY = {'gcp_batch': 1.0, 'kubernetes': 0.0}


def get_job_frequency():
  """Returns the frequency for a given job.
  
  If the frequency is not explicitly defined in the `K8S_JOBS_FREQUENCY`
  environment variable, the default frequency is returned.
  """
  frequency = DEFAULT_FREQUENCY

  kubernetes_frequency = feature_flags.FeatureFlags.K8S_JOBS_FREQUENCY.content
  if not isinstance(
      kubernetes_frequency,
      float) or kubernetes_frequency < 0 or kubernetes_frequency > 1:
    logs.warning(
        "Kubernetes frequency inconsistent",
        kubernetes_frequency=kubernetes_frequency)
    kubernetes_frequency = None

  elif not feature_flags.FeatureFlags.K8S_JOBS_FREQUENCY.enabled:
    kubernetes_frequency = None

  if kubernetes_frequency:
    frequency = {
        'gcp_batch': 1.0 - kubernetes_frequency,
        'kubernetes': kubernetes_frequency
    }
  logs.info("Job frequency", frequency=frequency)
  return frequency

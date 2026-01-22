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
"""Remote task adapters."""

from enum import Enum

from clusterfuzz._internal.base import feature_flags
from clusterfuzz._internal.batch import service as batch_service
from clusterfuzz._internal.k8s import service as k8s_service


class RemoteTaskAdapters(Enum):
  """Defines the supported remote task execution backends.

  This enum serves as the single source of truth for all supported remote
  execution platforms. Each member represents a different backend and holds
  the necessary configuration for it.

  Attributes:
    id: A unique string identifier for the adapter (e.g., 'kubernetes').
    service: The service class responsible for interacting with the backend.
    feature_flag: The feature flag that controls the frequency of this backend.
    default_weight: The default frequency if the feature flag is not set.
  """
  KUBERNETES = ('kubernetes', k8s_service.KubernetesService,
                feature_flags.FeatureFlags.K8S_JOBS_FREQUENCY, 0.0)
  GCP_BATCH = ('gcp_batch', batch_service.GcpBatchService, None, 1.0)

  def __init__(self, adapter_id, service, feature_flag, default_weight):
    self.id = adapter_id
    self.feature_flag = feature_flag
    self.default_weight = default_weight
    self.service = service

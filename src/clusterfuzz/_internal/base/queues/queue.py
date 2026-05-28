# Copyright 2026 Google LLC
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
"""Queue data class."""

from dataclasses import dataclass

from clusterfuzz._internal.base.feature_flags import FeatureFlags


@dataclass
class Queue:
  """Data class that holds information about a pub/sub queue.

  Attributes:
      name: The name of the Pub/Sub subscription associated with the queue.
      default_target_size: Number of tasks that should be kept in the queue.
      target_size_flag: Feature flag used to override the default target size.
  """

  name: str
  default_target_size: int
  target_size_flag: FeatureFlags

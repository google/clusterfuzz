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
"""Module for Pub/Sub task queue definitions."""

from dataclasses import dataclass

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base.feature_flags import FeatureFlags


@dataclass
class PubSubTaskQueue:
  """Data class that holds information about a pub/sub queue.

  Attributes:
      name: The name of the Pub/Sub subscription associated with the queue.
      default_target_size: Number of tasks that should be kept in the queue.
      target_size_flag: Feature flag used to override the default target size.
  """

  name: str
  default_target_size: int
  target_size_flag: FeatureFlags

  def get_max_target_size(self) -> int:
    """Get the effective maximum target size for this queue.

    Uses the feature flag for the queue size limit if its enabled.
    Otherwise returns the default target size.
    """
    flag = self.target_size_flag
    if flag.enabled and flag.content is not None:
      return int(flag.content)
    return self.default_target_size


# Default target size for the preprocess queue.
PREPROCESS_TARGET_SIZE_DEFAULT = 10000

# Default limit for the utask main queue.
UTASK_MAIN_QUEUE_LIMIT_DEFAULT = 10000

# Default target size for the swarming preprocess queue.
SWARMING_PREPROCESS_TARGET_SIZE_DEFAULT = 10

# Default limit for the swarming utask main queue.
SWARMING_UTASK_MAIN_QUEUE_LIMIT_DEFAULT = 25

PREPROCESS_QUEUE = PubSubTaskQueue(
    name=tasks.PREPROCESS_QUEUE,
    default_target_size=PREPROCESS_TARGET_SIZE_DEFAULT,
    target_size_flag=FeatureFlags.PREPROCESS_QUEUE_SIZE_LIMIT,
)

SWARMING_PREPROCESS_QUEUE = PubSubTaskQueue(
    name=tasks.SWARMING_QUEUES[tasks.PREPROCESS_QUEUE],
    default_target_size=SWARMING_PREPROCESS_TARGET_SIZE_DEFAULT,
    target_size_flag=FeatureFlags.SWARMING_PREPROCESS_QUEUE_SIZE_LIMIT,
)

UTASK_MAIN_QUEUE = PubSubTaskQueue(
    name=tasks.UTASK_MAIN_QUEUE,
    default_target_size=UTASK_MAIN_QUEUE_LIMIT_DEFAULT,
    target_size_flag=FeatureFlags.UTASK_MAIN_QUEUE_LIMIT,
)

SWARMING_UTASK_MAIN_QUEUE = PubSubTaskQueue(
    name=tasks.SWARMING_QUEUES[tasks.UTASK_MAIN_QUEUE],
    default_target_size=SWARMING_UTASK_MAIN_QUEUE_LIMIT_DEFAULT,
    target_size_flag=FeatureFlags.SWARMING_MAX_PENDING_TASKS,
)

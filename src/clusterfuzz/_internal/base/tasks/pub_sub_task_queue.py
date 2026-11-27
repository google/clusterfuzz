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


@dataclass(frozen=True)
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
    return get_max_size_for_queue(self.default_target_size,
                                  self.target_size_flag)


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

# Swarming 3-stage UTask queues:
# - Preprocess queues receive fuzz tasks from schedule_fuzz and are drained by
#   platform-specific tworker pools that prepare signed uworker_input bundles.
# - utask_main queues receive preprocessed tasks (both fuzz and non-fuzz) and
#   are drained by utask-main-scheduler to create LUCI Swarming tasks.
#
# LINUX and ANDROID_EMULATOR share the legacy default Swarming queues
# (*_DEFAULT), while MAC_ARM64 uses dedicated per-platform queues (*_MAC_ARM64)
# for independent backpressure, metrics, and kill-switch rollback.
SWARMING_PREPROCESS_QUEUE_DEFAULT = PubSubTaskQueue(
    name=tasks.SWARMING_PREPROCESS_QUEUE_DEFAULT,
    default_target_size=SWARMING_PREPROCESS_TARGET_SIZE_DEFAULT,
    target_size_flag=FeatureFlags.SWARMING_PREPROCESS_QUEUE_SIZE_LIMIT,
)

SWARMING_PREPROCESS_QUEUE_MAC_ARM64 = PubSubTaskQueue(
    name=tasks.SWARMING_PREPROCESS_QUEUE_MAC_ARM64,
    default_target_size=SWARMING_PREPROCESS_TARGET_SIZE_DEFAULT,
    target_size_flag=(
        FeatureFlags.SWARMING_PREPROCESS_QUEUE_SIZE_LIMIT_MAC_ARM64),
)

SWARMING_PREPROCESS_QUEUES_BY_PLATFORM = {
    'LINUX': SWARMING_PREPROCESS_QUEUE_DEFAULT,
    'ANDROID_EMULATOR': SWARMING_PREPROCESS_QUEUE_DEFAULT,
    'MAC_ARM64': SWARMING_PREPROCESS_QUEUE_MAC_ARM64,
}

SWARMING_PREPROCESS_QUEUES = (
    SWARMING_PREPROCESS_QUEUE_DEFAULT,
    SWARMING_PREPROCESS_QUEUE_MAC_ARM64,
)

UTASK_MAIN_QUEUE = PubSubTaskQueue(
    name=tasks.UTASK_MAIN_QUEUE,
    default_target_size=UTASK_MAIN_QUEUE_LIMIT_DEFAULT,
    target_size_flag=FeatureFlags.UTASK_MAIN_QUEUE_LIMIT,
)

SWARMING_UTASK_MAIN_QUEUE_DEFAULT = PubSubTaskQueue(
    name=tasks.SWARMING_UTASK_MAIN_QUEUE_DEFAULT,
    default_target_size=SWARMING_UTASK_MAIN_QUEUE_LIMIT_DEFAULT,
    target_size_flag=FeatureFlags.SWARMING_UTASK_MAIN_QUEUE_SIZE_LIMIT,
)

SWARMING_UTASK_MAIN_QUEUE_MAC_ARM64 = PubSubTaskQueue(
    name=tasks.SWARMING_UTASK_MAIN_QUEUE_MAC_ARM64,
    default_target_size=SWARMING_UTASK_MAIN_QUEUE_LIMIT_DEFAULT,
    target_size_flag=(
        FeatureFlags.SWARMING_UTASK_MAIN_QUEUE_SIZE_LIMIT_MAC_ARM64),
)

SWARMING_UTASK_MAIN_QUEUES_BY_PLATFORM = {
    'LINUX': SWARMING_UTASK_MAIN_QUEUE_DEFAULT,
    'ANDROID_EMULATOR': SWARMING_UTASK_MAIN_QUEUE_DEFAULT,
    'MAC_ARM64': SWARMING_UTASK_MAIN_QUEUE_MAC_ARM64,
}

SWARMING_UTASK_MAIN_QUEUES = (
    SWARMING_UTASK_MAIN_QUEUE_DEFAULT,
    SWARMING_UTASK_MAIN_QUEUE_MAC_ARM64,
)


def get_max_size_for_queue(default_size: int,
                           size_limit_flag: FeatureFlags) -> int:
  """Returns the maximum size for a queue, checking feature flags.

  Args:
    default_size: The default maximum size.
    size_limit_flag: The feature flag to check for a custom limit.

  Returns:
    The maximum size as an integer.
  """
  flag = size_limit_flag
  if flag.enabled and flag.content is not None:
    return int(flag.content)
  return default_size

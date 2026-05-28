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
"""Queue definitions."""

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base.feature_flags import FeatureFlags
from clusterfuzz._internal.base.queues.queue import Queue

PREPROCESS_TARGET_SIZE_DEFAULT = 10000
UTASK_MAIN_QUEUE_LIMIT_DEFAULT = 10000
SWARMING_PREPROCESS_TARGET_SIZE_DEFAULT = 10
SWARMING_UTASK_MAIN_QUEUE_LIMIT_DEFAULT = 25

PREPROCESS_QUEUE = Queue(
    name=tasks.PREPROCESS_QUEUE,
    default_target_size=PREPROCESS_TARGET_SIZE_DEFAULT,
    target_size_flag=FeatureFlags.PREPROCESS_QUEUE_SIZE_LIMIT,
)

SWARMING_PREPROCESS_QUEUE = Queue(
    name=tasks.SWARMING_QUEUES[tasks.PREPROCESS_QUEUE],
    default_target_size=SWARMING_PREPROCESS_TARGET_SIZE_DEFAULT,
    target_size_flag=FeatureFlags.SWARMING_PREPROCESS_QUEUE_SIZE_LIMIT,
)

UTASK_MAIN_QUEUE = Queue(
    name=tasks.UTASK_MAIN_QUEUE,
    default_target_size=UTASK_MAIN_QUEUE_LIMIT_DEFAULT,
    target_size_flag=FeatureFlags.UTASK_MAIN_QUEUE_LIMIT,
)

SWARMING_UTASK_MAIN_QUEUE = Queue(
    name=tasks.SWARMING_QUEUES[tasks.UTASK_MAIN_QUEUE],
    default_target_size=SWARMING_UTASK_MAIN_QUEUE_LIMIT_DEFAULT,
    target_size_flag=FeatureFlags.SWARMING_MAX_PENDING_TASKS,
)

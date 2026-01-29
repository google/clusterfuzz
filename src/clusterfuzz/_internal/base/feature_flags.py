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
"""FeatureFlags."""

from enum import Enum

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types


class FeatureFlags(Enum):
  """Feature flags"""
  # Example flag.
  TEST_FLAG = 'test_flag'
  TEST_FLOAT_FLAG = 'test_float_flag'

  K8S_JOBS_FREQUENCY = 'k8s_jobs_frequency'
  K8S_JOBS_PENDING_LIMIT = 'k8s_jobs_pending_limit'

  UTASK_MAIN_QUEUE_LIMIT = 'utask_main_queue_limit'

  @property
  def flag(self):
    """Get the feature flag."""
    flag = ndb.Key(data_types.FeatureFlag, self.value).get()
    if not flag:
      return None
    return flag

  @property
  def enabled(self):
    """Check if a feature flag is enabled."""
    flag = self.flag
    if not flag:
      return False
    return flag.enabled

  @property
  def content(self):
    """Get the feature flag content."""
    flag = self.flag
    if not flag or flag.value is None:
      return None
    return flag.value

  @property
  def description(self):
    """Get the feature flag description."""
    flag = self.flag
    if not flag or flag.description is None:
      return ''
    return flag.description

  @property
  def string_value(self):
    """Get the feature flag string value."""
    flag = self.flag
    if not flag or flag.string_value is None:
      return ''
    return flag.string_value

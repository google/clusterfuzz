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
"""Tests for pub_sub_task_queue."""

import unittest

from clusterfuzz._internal.base.feature_flags import FeatureFlags
from clusterfuzz._internal.base.tasks.pub_sub_task_queue import PubSubTaskQueue
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class PubSubTaskQueueTest(unittest.TestCase):
  """Tests for PubSubTaskQueue."""

  def test_get_max_target_size_without_feature_flag(self):
    """Test that the default max pending tasks is returned when flag is not set."""
    queue = PubSubTaskQueue(
        name='test-queue',
        default_target_size=25,
        target_size_flag=FeatureFlags.SWARMING_MAX_PENDING_TASKS)
    self.assertEqual(queue.get_max_target_size(), 25)

  def test_get_max_target_size_with_zero_value(self):
    """Test that the max pending tasks returns 0 when flag is set to 0 and is enabled"""
    data_types.FeatureFlag(
        id='swarming_max_pending_tasks', enabled=True, value=0.0).put()

    queue = PubSubTaskQueue(
        name='test-queue',
        default_target_size=25,
        target_size_flag=FeatureFlags.SWARMING_MAX_PENDING_TASKS)
    self.assertEqual(queue.get_max_target_size(), 0)

  def test_get_max_target_size_with_value(self):
    """Test that the max pending tasks returns the flag value when set and enabled"""
    data_types.FeatureFlag(
        id='swarming_max_pending_tasks', enabled=True, value=50.0).put()

    queue = PubSubTaskQueue(
        name='test-queue',
        default_target_size=25,
        target_size_flag=FeatureFlags.SWARMING_MAX_PENDING_TASKS)
    self.assertEqual(queue.get_max_target_size(), 50)

  def test_get_max_target_size_with_disabled_flag(self):
    """Test that the default max pending tasks is returned when flag is disabled."""
    data_types.FeatureFlag(
        id='swarming_max_pending_tasks', enabled=False, value=50.0).put()

    queue = PubSubTaskQueue(
        name='test-queue',
        default_target_size=25,
        target_size_flag=FeatureFlags.SWARMING_MAX_PENDING_TASKS)
    self.assertEqual(queue.get_max_target_size(), 25)

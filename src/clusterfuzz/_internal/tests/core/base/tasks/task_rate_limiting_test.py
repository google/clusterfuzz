# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for task_rate_limiting."""

import datetime
import unittest

from clusterfuzz._internal.base.tasks import task_rate_limiting
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class TaskRateLimiterTest(unittest.TestCase):
  """Tests for TaskRateLimiter."""

  def setUp(self):
    self.now = datetime.datetime.utcnow()
    self.rate_limiter = task_rate_limiting.TaskRateLimiter(
        'test_task', 'test_arg', 'test_job')
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.task_rate_limiting._get_datetime_now',
    ])
    self.mock.return_value = self.now

  def test_record_task(self):
    """Test record_task()."""

    self.rate_limiter.record_task(True)
    tasks = list(ndb_utils.get_all_from_model(data_types.WindowRateLimitTask))
    self.assertEqual(len(tasks), 1)
    first_task = tasks[0]
    self.assertEqual(first_task.task_name, 'test_task')
    self.assertEqual(first_task.task_argument, 'test_arg')
    self.assertEqual(first_task.job_name, 'test_job')
    self.assertEqual(first_task.status, data_types.TaskState.FINISHED)

    # Now record and error.
    self.rate_limiter.record_task(False)
    tasks = list(ndb_utils.get_all_from_model(data_types.WindowRateLimitTask))
    self.assertEqual(len(tasks), 2)
    self.assertEqual(tasks[1].status, data_types.TaskState.ERROR)

  def test_is_rate_limited_no_limit(self):
    """Test is_rate_limited() with no rate limiting."""
    self.assertFalse(self.rate_limiter.is_rate_limited())

  def test_is_rate_limited_completion_limit(self):
    """Test is_rate_limited() with completion rate limiting."""
    # Add enough tasks to trigger the completion limit.
    self._create_n_tasks(
        task_rate_limiting.TaskRateLimiter.TASK_RATE_LIMIT_MAX_COMPLETIONS + 1)
    self.assertTrue(self.rate_limiter.is_rate_limited())

  def test_is_rate_limited_error_limit(self):
    """Test is_rate_limited() with error rate limiting."""
    self.rate_limiter = task_rate_limiting.TaskRateLimiter(
        'test_task', 'test_arg', 'test_job')

    # Add enough tasks to trigger the error limit.
    self._create_n_tasks(
        task_rate_limiting.TaskRateLimiter.TASK_RATE_LIMIT_MAX_ERRORS - 1,
        status=data_types.TaskState.ERROR)

    self.assertFalse(self.rate_limiter.is_rate_limited())
    self._create_n_tasks(1, status=data_types.TaskState.ERROR)
    self.assertTrue(self.rate_limiter.is_rate_limited())

  def test_is_rate_limited_uworker_task(self):
    """Test is_rate_limited() with uworker pseudotasks."""
    for task_name in ['uworker_main', 'postprocess', 'preprocess']:
      rate_limiter = task_rate_limiting.TaskRateLimiter(task_name, 'test_arg',
                                                        'test_job')
      self.assertFalse(rate_limiter.is_rate_limited())

  def test_is_rate_limited_old_tasks(self):
    """Test is_rate_limited() with old tasks outside the window."""
    # Add tasks outside the time window.
    window_start = (
        self.now - task_rate_limiting.TaskRateLimiter.TASK_RATE_LIMIT_WINDOW)
    self._create_n_tasks(
        task_rate_limiting.TaskRateLimiter.TASK_RATE_LIMIT_MAX_COMPLETIONS + 1,
        timestamp=window_start - datetime.timedelta(minutes=10))
    self.assertFalse(self.rate_limiter.is_rate_limited())

  def _create_n_tasks(self,
                      n,
                      status=data_types.TaskState.FINISHED,
                      timestamp=None):
    """Create |n| WindowRateLimitTasks."""
    if timestamp is None:
      timestamp = self.now
    for _ in range(n):
      task = data_types.WindowRateLimitTask(
          task_name='test_task',
          task_argument='test_arg',
          job_name='test_job',
          status=status,
          timestamp=self.now)
      task.put()

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
"""Tests for SwarmingService."""

import unittest
from unittest import mock

from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.swarming import service
from clusterfuzz._internal.tests.test_libs import helpers


class SwarmingServiceTest(unittest.TestCase):
  """Tests for SwarmingService."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.swarming.is_swarming_task',
        'clusterfuzz._internal.swarming.push_swarming_task',
        'clusterfuzz._internal.swarming.create_new_task_request',
        'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module',
        'clusterfuzz._internal.metrics.logs.error',
        'clusterfuzz._internal.google_cloud_utils.compute_metadata.get',
    ])
    self.service = service.SwarmingService()
    self.mock.create_new_task_request.return_value = 'fake_request'
    self.mock.get.return_value = None

  def test_create_utask_main_job_success(self):
    """Test creating a single task successfully."""
    self.mock.get_command_from_module.return_value = 'fuzz'
    self.mock.is_swarming_task.return_value = True

    result = self.service.create_utask_main_job('fuzz_task', 'job_type',
                                                'http://url')

    # Success returns None in this interface (consistent with GcpBatchService)
    self.assertIsNone(result)

    self.mock.push_swarming_task.assert_called_once_with('fake_request')

  def test_create_utask_main_job_failure(self):
    """Test creating a single task that is not a swarming task."""
    self.mock.get_command_from_module.return_value = 'fuzz'
    self.mock.is_swarming_task.return_value = False

    result = self.service.create_utask_main_job('fuzz_task', 'job_type',
                                                'http://url')

    # Failure returns the task itself
    self.assertIsInstance(result, remote_task_types.RemoteTask)
    self.assertEqual(result.command, 'fuzz')
    self.mock.push_swarming_task.assert_not_called()

  def test_create_utask_main_jobs_mixed_results(self):
    """Test creating multiple tasks with mixed success/failure."""
    tasks = [
        remote_task_types.RemoteTask('fuzz', 'job1', 'url1'),
        remote_task_types.RemoteTask('fuzz', 'job2', 'url2'),
        remote_task_types.RemoteTask('fuzz', 'job3', 'url3'),
    ]

    # job1 succeeds, job2 fails (not a swarming task), job3 succeeds
    self.mock.is_swarming_task.side_effect = [True, False, True]

    unscheduled = self.service.create_utask_main_jobs(tasks)

    self.assertEqual(len(unscheduled), 1)
    self.assertEqual(unscheduled[0].job_type, 'job2')

    self.assertEqual(self.mock.push_swarming_task.call_count, 2)
    self.mock.push_swarming_task.assert_has_calls([
        mock.call('fake_request'),
        mock.call('fake_request'),
    ])

  def test_create_utask_main_jobs_all_success(self):
    """Test creating multiple tasks where all succeed."""
    tasks = [
        remote_task_types.RemoteTask('fuzz', 'job1', 'url1'),
        remote_task_types.RemoteTask('fuzz', 'job2', 'url2'),
    ]
    self.mock.is_swarming_task.return_value = True

    unscheduled = self.service.create_utask_main_jobs(tasks)

    self.assertEqual(unscheduled, [])
    self.assertEqual(self.mock.push_swarming_task.call_count, 2)

  def test_create_utask_main_jobs_all_fail(self):
    """Test creating multiple tasks where all fail."""
    tasks = [
        remote_task_types.RemoteTask('fuzz', 'job1', 'url1'),
        remote_task_types.RemoteTask('fuzz', 'job2', 'url2'),
    ]
    self.mock.is_swarming_task.return_value = False

    unscheduled = self.service.create_utask_main_jobs(tasks)

    self.assertEqual(unscheduled, tasks)
    self.mock.push_swarming_task.assert_not_called()

  def test_create_utask_main_jobs_empty(self):
    """Test creating tasks with an empty list."""
    unscheduled = self.service.create_utask_main_jobs([])
    self.assertEqual(unscheduled, [])
    self.mock.push_swarming_task.assert_not_called()

  def test_create_utask_main_jobs_exception(self):
    """Test creating tasks when push_swarming_task raises an exception."""
    tasks = [
        remote_task_types.RemoteTask('fuzz', 'job1', 'url1'),
    ]

    self.mock.is_swarming_task.return_value = True
    self.mock.push_swarming_task.side_effect = Exception('error')

    unscheduled = self.service.create_utask_main_jobs(tasks)

    self.assertEqual(len(unscheduled), 1)
    self.assertEqual(unscheduled[0].job_type, 'job1')
    self.mock.error.assert_called_once_with(
        'Failed to push task to Swarming: fuzz, job1.')

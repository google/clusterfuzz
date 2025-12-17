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
"""Tests for the gcp module."""
import unittest
from unittest import mock

from google.cloud import batch_v1 as batch

from clusterfuzz._internal.batch import gcp
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils

class GcpTest(unittest.TestCase):
  """Tests for gcp module."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.batch.gcp._batch_client',
    ])
    self.mock_batch_client_instance = mock.Mock()
    self.mock._batch_client.return_value = self.mock_batch_client_instance

  def test_check_congestion_jobs(self):
    """Tests that check_congestion_jobs counts correctly."""
    # Create mock jobs with different states
    job_succeeded = mock.Mock()
    job_succeeded.status.state = batch.JobStatus.State.SUCCEEDED
    
    job_running = mock.Mock()
    job_running.status.state = batch.JobStatus.State.RUNNING
    
    job_failed = mock.Mock()
    job_failed.status.state = batch.JobStatus.State.FAILED
    
    job_queued = mock.Mock()
    job_queued.status.state = batch.JobStatus.State.QUEUED

    # Mock get_job to return these based on job name
    def get_job_side_effect(name):
      if name == 'job-succeeded':
        return job_succeeded
      if name == 'job-running':
        return job_running
      if name == 'job-failed':
        return job_failed
      if name == 'job-queued':
        return job_queued
      raise Exception("Job not found")

    self.mock_batch_client_instance.get_job.side_effect = get_job_side_effect

    # Check that SUCCEEDED, RUNNING, FAILED are counted (3 total)
    # QUEUED is not counted
    # Non-existent job is not counted
    job_ids = ['job-succeeded', 'job-running', 'job-failed', 'job-queued', 'job-missing']
    count = gcp.check_congestion_jobs(job_ids)
    
    self.assertEqual(count, 3)

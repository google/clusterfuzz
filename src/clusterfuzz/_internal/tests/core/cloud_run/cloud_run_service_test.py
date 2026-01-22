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
"""Tests for the Cloud Run service."""

import unittest
from unittest import mock

from clusterfuzz._internal.cloud_run import service
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class CloudRunServiceTest(unittest.TestCase):
  """Tests for the CloudRunService class."""

  def setUp(self):
    self.patcher1 = mock.patch('google.auth.default')
    self.mock_auth_default = self.patcher1.start()
    self.mock_auth_default.return_value = (mock.Mock(), 'test-project')

    self.patcher2 = mock.patch('googleapiclient.discovery.build')
    self.mock_discovery_build = self.patcher2.start()
    self.mock_client = mock.Mock()
    self.mock_discovery_build.return_value = self.mock_client

    self.patcher3 = mock.patch('clusterfuzz._internal.base.utils.get_application_id')
    self.mock_get_application_id = self.patcher3.start()
    self.mock_get_application_id.return_value = 'test-project'

    self.addCleanup(self.patcher1.stop)
    self.addCleanup(self.patcher2.stop)
    self.addCleanup(self.patcher3.stop)

    data_types.Job(name='job1', platform='LINUX').put()

  def test_create_job(self):
    """Tests create_job."""
    config = service.CloudRunJobConfig(
        job_type='job1',
        docker_image='test-image',
        command='fuzz',
        disk_size_gb=10,
        service_account_email='test-email',
        clusterfuzz_release='prod',
        gce_region='us-central1')

    # Mock the API responses
    mock_jobs = self.mock_client.projects().locations().jobs()
    mock_jobs.create().execute.return_value = {'name': 'projects/test-project/locations/us-central1/jobs/cf-job-uuid'}
    
    svc = service.CloudRunService()
    svc.create_job(config, 'url1')

    # Verify create call
    self.assertTrue(mock_jobs.create.called)
    call_args = mock_jobs.create.call_args
    self.assertEqual(call_args.kwargs['parent'], 'projects/test-project/locations/us-central1')
    self.assertEqual(call_args.kwargs['body']['template']['template']['containers'][0]['image'], 'test-image')

    # Verify run call
    self.assertTrue(mock_jobs.run.called)
    self.assertEqual(mock_jobs.run.call_args.kwargs['name'], 'projects/test-project/locations/us-central1/jobs/cf-job-uuid')

  def test_create_utask_main_jobs(self):
    """Tests create_utask_main_jobs."""
    tasks = [
        remote_task_types.RemoteTask('fuzz', 'job1', 'url1'),
        remote_task_types.RemoteTask('fuzz', 'job1', 'url2'),
    ]

    svc = service.CloudRunService()
    with mock.patch.object(svc, 'create_job') as mock_create_job:
      mock_create_job.return_value = 'job-name'
      result = svc.create_utask_main_jobs(tasks)
      self.assertEqual(len(result), 2)
      self.assertEqual(mock_create_job.call_count, 2)

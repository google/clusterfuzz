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
"""Tests for the cloud_run service."""
import os
import unittest
from unittest import mock
import uuid

from clusterfuzz._internal.cloud_run import service as cloud_run_service
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.remote_task import remote_task_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils

UUIDS = [f'00000000-0000-0000-0000-{str(i).zfill(12)}' for i in range(100)]


def _get_expected_job_body(job_name, spec, input_url):
  """Gets the expected job body."""
  env_vars = [
      {
          'name': 'HOST_UID',
          'value': '1337'
      },
      {
          'name': 'CLUSTERFUZZ_RELEASE',
          'value': spec.clusterfuzz_release
      },
      {
          'name': 'UNTRUSTED_WORKER',
          'value': 'False'
      },
      {
          'name': 'UWORKER',
          'value': 'True'
      },
      {
          'name': 'USE_GCLOUD_STORAGE_RSYNC',
          'value': '1'
      },
      {
          'name': 'UWORKER_INPUT_DOWNLOAD_URL',
          'value': input_url
      },
      {
          'name': 'IS_K8S_ENV',
          'value': 'true'
      },
      {
          'name': 'DISABLE_MOUNTS',
          'value': 'true'
      },
      {
          'name': 'UPDATE_WEB_TESTS',
          'value': 'False'
      },
      {
          'name': 'LOCAL_DEVELOPMENT',
          'value': 'True'
      },
      {
          'name': 'DEPLOYMENT_BUCKET',
          'value': 'deployment-bucket'
      },
  ]

  container = {
      'image': spec.docker_image,
      'resources': {
          'limits': {
              'cpu': spec.cpu,
              'memory': spec.memory
          }
      },
      'env': env_vars,
  }

  task_template = {
      'containers': [container],
      'maxRetries': 0,
      'timeout': spec.max_run_duration,
      'serviceAccount': spec.service_account_email,
      'executionEnvironment': 'EXECUTION_ENVIRONMENT_GEN2',
  }

  if spec.subnetwork:
    task_template['vpcAccess'] = {
        'networkInterfaces': [{
            'network': spec.network,
            'subnetwork': spec.subnetwork,
            'tags': ['clusterfuzz-worker']
        }],
        'egress':
            'ALL_TRAFFIC'
    }

  return {
      'template': {
          'template': task_template,
          'taskCount': 1,
      },
      'launchStage': 'BETA'
  }


@test_utils.with_cloud_emulators('datastore')
class CloudRunServiceTest(unittest.TestCase):
  """Tests for CloudRunService."""

  def setUp(self):
    helpers.patch(self, [
        'google.auth.default',
        'googleapiclient.discovery.build',
        'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module',
        'uuid.uuid4',
    ])
    self.mock.default.return_value = (mock.Mock(), 'project-id')
    self.mock_service = mock.Mock()
    self.mock.build.return_value = self.mock_service
    self.cloud_run_service = cloud_run_service.CloudRunService()
    self.mock.uuid4.side_effect = [uuid.UUID(u) for u in UUIDS]

    helpers.patch_environ(self)
    os.environ['DEPLOYMENT_BUCKET'] = 'deployment-bucket'

    # Mocking chain: projects().locations().jobs().create()
    self.mock_locations = self.mock_service.projects.return_value.locations.return_value
    self.mock_jobs = self.mock_locations.jobs.return_value
    self.mock_jobs.create.return_value.execute.return_value = {'name': 'job-op'}
    self.mock_jobs.run.return_value.execute.return_value = {'name': 'run-op'}

    self.mock_executions = self.mock_locations.executions.return_value
    self.mock_executions.list.return_value.execute.return_value = {
        'executions': []
    }

  def test_create_uworker_main_jobs(self):
    """Tests that create_utask_main_jobs works as expected."""
    spec1 = cloud_run_service.CloudRunWorkloadSpec(
        clusterfuzz_release='release1',
        disk_size_gb=10,
        disk_type='type1',
        docker_image='image1',
        user_data='user_data1',
        service_account_email='email1',
        subnetwork='subnetwork1',
        preemptible=True,
        project='project1',
        machine_type='machine1',
        network='network1',
        region='region1',
        max_run_duration='1s',
        cpu='2',
        memory='4Gi')

    with mock.patch(
        'clusterfuzz._internal.cloud_run.service._get_specs_from_config'
    ) as mock_get_specs_from_config:
      mock_get_specs_from_config.return_value = {
          ('command1', 'job1'): spec1,
      }
      tasks = [
          remote_task_types.RemoteTask('command1', 'job1', 'url1'),
      ]

      result = self.cloud_run_service.create_utask_main_jobs(tasks)

      job_name = f'j-{UUIDS[0]}'.lower()
      expected_body = _get_expected_job_body(job_name, spec1, 'url1')

      self.mock_jobs.create.assert_called_with(
          parent='projects/project1/locations/region1',
          jobId=job_name,
          body=expected_body)
      self.mock_jobs.run.assert_called_with(
          name=f'projects/project1/locations/region1/jobs/{job_name}')
      self.assertEqual(result, [])

  def test_create_uworker_main_job(self):
    """Tests that create_utask_main_job works as expected."""
    spec1 = cloud_run_service.CloudRunWorkloadSpec(
        clusterfuzz_release='release1',
        disk_size_gb=10,
        disk_type='type1',
        docker_image='image1',
        user_data='user_data1',
        service_account_email='email1',
        subnetwork='subnetwork1',
        preemptible=True,
        project='project1',
        machine_type='machine1',
        network='network1',
        region='region1',
        max_run_duration='1s',
        cpu='2',
        memory='4Gi')

    with mock.patch(
        'clusterfuzz._internal.cloud_run.service._get_specs_from_config'
    ) as mock_get_specs_from_config:
      mock_get_specs_from_config.return_value = {
          ('fuzz', 'job1'): spec1,
      }
      self.mock.get_command_from_module.return_value = 'fuzz'

      result = self.cloud_run_service.create_utask_main_job(
          'fuzz', 'job1', 'url1')

      job_name = f'j-{UUIDS[0]}'.lower()
      expected_body = _get_expected_job_body(job_name, spec1, 'url1')

      self.mock_jobs.create.assert_called_with(
          parent='projects/project1/locations/region1',
          jobId=job_name,
          body=expected_body)
      self.assertIsNone(result)

  @mock.patch(
      'clusterfuzz._internal.cloud_run.service.CloudRunService._get_pending_executions_count'
  )
  def test_create_uworker_main_jobs_limit_reached(self, mock_count):
    """Tests that jobs are not created when limit is reached."""
    mock_count.return_value = 1001

    spec1 = cloud_run_service.CloudRunWorkloadSpec(
        clusterfuzz_release='release1',
        disk_size_gb=10,
        disk_type='type1',
        docker_image='image1',
        user_data='user_data1',
        service_account_email='email1',
        subnetwork='subnetwork1',
        preemptible=True,
        project='project1',
        machine_type='machine1',
        network='network1',
        region='region1',
        max_run_duration='1s',
        cpu='2',
        memory='4Gi')

    with mock.patch(
        'clusterfuzz._internal.cloud_run.service._get_specs_from_config'
    ) as mock_get_specs_from_config:
      mock_get_specs_from_config.return_value = {
          ('command1', 'job1'): spec1,
      }
      tasks = [
          remote_task_types.RemoteTask('command1', 'job1', 'url1'),
      ]

      result = self.cloud_run_service.create_utask_main_jobs(tasks)

      self.assertEqual(len(result), 1)
      self.assertEqual(result[0], tasks[0])
      self.mock_jobs.create.assert_not_called()


if __name__ == '__main__':
  unittest.main()

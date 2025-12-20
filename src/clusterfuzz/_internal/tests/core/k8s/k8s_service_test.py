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
"""Tests for the Kubernetes batch client."""

import unittest
from unittest import mock

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.k8s import service
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
@mock.patch('kubernetes.config.load_kube_config')
class KubernetesServiceTest(unittest.TestCase):
  """Tests for the KubernetesService class."""

  def setUp(self):
    data_types.Job(name='job1', platform='LINUX').put()
    data_types.Job(
        name='job2', platform='LINUX',
        environment_string='CUSTOM_VAR = value').put()

  @mock.patch.object(service.KubernetesService, 'create_job')
  def test_create_uworker_main_batch_jobs(self, mock_create_job, _):
    """Tests the creation of uworker main batch jobs."""
    tasks = [
        service.RemoteTask('fuzz', 'job1', 'url1'),
        service.RemoteTask('fuzz', 'job1', 'url2'),
        service.RemoteTask('command2', 'job2', 'url3'),
    ]

    kube_service = service.KubernetesService()
    kube_service.create_uworker_main_batch_jobs(tasks)

    self.assertEqual(2, mock_create_job.call_count)
    # The order of calls is not guaranteed.
    args0 = mock_create_job.call_args_list[0].args
    args1 = mock_create_job.call_args_list[1].args
    if args0[1] == ['url1', 'url2']:
      self.assertEqual(['url3'], args1[1])
    else:
      self.assertEqual(['url3'], args0[1])
      self.assertEqual(['url1', 'url2'], args1[1])

  @mock.patch(
      'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module')
  @mock.patch.object(service.KubernetesService,
                     'create_uworker_main_batch_jobs')
  def test_create_uworker_main_batch_job(self, mock_create_batch_jobs,
                                         mock_get_command, _):
    """Tests the creation of a single uworker main batch job."""
    mock_get_command.return_value = 'command'
    kube_service = service.KubernetesService()
    kube_service.create_uworker_main_batch_job('module', 'job', 'url')

    self.assertEqual(1, mock_create_batch_jobs.call_count)
    tasks = mock_create_batch_jobs.call_args[0][0]
    self.assertEqual(1, len(tasks))
    self.assertEqual('command', tasks[0].command)
    self.assertEqual('job', tasks[0].job_type)
    self.assertEqual('url', tasks[0].input_download_url)

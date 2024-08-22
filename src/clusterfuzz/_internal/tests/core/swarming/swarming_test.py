# Copyright 2023 Google LLC
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
"""Swarming tests."""
import base64
import unittest

from google.protobuf import json_format

from clusterfuzz._internal import swarming
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class SwarmingTest(unittest.TestCase):
  """Tests for swarming utilss."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.post_url',
        'clusterfuzz._internal.swarming._get_task_name'
    ])
    self.mock._get_task_name.return_value = 'task_name'  # pylint: disable=protected-access
    self.maxDiff = None

  def test_get_spec_from_config_with_docker_image(self):
    """Tests that _get_new_task_spec works as expected."""
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    job.put()
    spec = swarming._get_new_task_spec(  # pylint: disable=protected-access
        'corpus_pruning', job.name, 'https://download_url')
    expected_spec = swarming_pb2.NewTaskRequest(
        name='task_name',
        priority=1,
        realm='realm-name',
        service_account='test-clusterfuzz-service-account-email',
        task_slices=[
            swarming_pb2.TaskSlice(
                expiration_secs=86400,
                properties=swarming_pb2.TaskProperties(
                    command=[
                        'luci-auth', 'context', '--', './linux_entry_point.sh'
                    ],
                    dimensions=[
                        swarming_pb2.StringPair(key='os', value=job.platform),
                        swarming_pb2.StringPair(key='pool', value='pool-name')
                    ],
                    cipd_input=swarming_pb2.CipdInput(),  # pylint: disable=no-member
                    cas_input_root=swarming_pb2.CASReference(
                        cas_instance=
                        'projects/server-name/instances/instance_name',
                        digest=swarming_pb2.Digest(
                            hash='linux_entry_point_archive_hash',
                            size_bytes=1234)),
                    execution_timeout_secs=86400,
                    env=[
                        swarming_pb2.StringPair(key='UWORKER', value='True'),
                        swarming_pb2.StringPair(
                            key='SWARMING_BOT', value='True'),
                        swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),
                        swarming_pb2.StringPair(
                            key='LOGGING_CLOUD_PROJECT_ID', value='project_id'),
                        swarming_pb2.StringPair(
                            key='DOCKER_IMAGE',
                            value=
                            'gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654'
                        ),
                    ],
                    secret_bytes=base64.b64encode(
                        'https://download_url'.encode('utf-8'))))
        ])

    self.assertEqual(spec, expected_spec)

  def test_get_spec_from_config_raises_error_on_unknown_config(self):
    """Tests that _get_new_task_spec raises error when there's no mapping for the config."""
    job = data_types.Job(name='some_job_name', platform='UNKNOWN-PLATFORM')
    job.put()
    with self.assertRaises(ValueError):
      swarming._get_new_task_spec(  # pylint: disable=protected-access
          'corpus_pruning', job.name, 'https://download_url')

  def test_get_spec_from_config_without_docker_image(self):
    """Tests that _get_new_task_spec works as expected (without a docker image)."""
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='MAC')
    job.put()
    spec = swarming._get_new_task_spec(  # pylint: disable=protected-access
        'corpus_pruning', job.name, 'https://download_url')
    expected_spec = swarming_pb2.NewTaskRequest(
        name='task_name',
        priority=1,
        realm='realm-name',
        service_account='test-clusterfuzz-service-account-email',
        task_slices=[
            swarming_pb2.TaskSlice(
                expiration_secs=86400,
                properties=swarming_pb2.TaskProperties(
                    command=[
                        'luci-auth', 'context', '--', './mac_entry_point.sh'
                    ],
                    dimensions=[
                        swarming_pb2.StringPair(key='os', value=job.platform),
                        swarming_pb2.StringPair(key='pool', value='pool-name'),
                        swarming_pb2.StringPair(key='key1', value='value1'),
                        swarming_pb2.StringPair(key='key2', value='value2'),
                    ],
                    cipd_input=swarming_pb2.CipdInput(packages=[
                        swarming_pb2.CipdPackage(
                            package_name='package1_name',
                            version='package1_version',
                            path='package_install_path'),
                        swarming_pb2.CipdPackage(
                            package_name='package2_name',
                            version='package2_version',
                            path='package_install_path'),
                    ]),
                    cas_input_root=swarming_pb2.CASReference(
                        cas_instance=
                        'projects/server-name/instances/instance_name',
                        digest=swarming_pb2.Digest(
                            hash='mac_entry_point_archive_hash',
                            size_bytes=456)),
                    execution_timeout_secs=86400,
                    env=[
                        swarming_pb2.StringPair(key='UWORKER', value='True'),
                        swarming_pb2.StringPair(
                            key='SWARMING_BOT', value='True'),
                        swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),
                        swarming_pb2.StringPair(
                            key='LOGGING_CLOUD_PROJECT_ID', value='project_id'),
                        swarming_pb2.StringPair(key='ENV_VAR1', value='VALUE1'),
                        swarming_pb2.StringPair(key='ENV_VAR2', value='VALUE2')
                    ],
                    env_prefixes=[
                        swarming_pb2.StringListPair(
                            key='PATH',
                            value=[
                                'package_install_path',
                                'package_install_path/bin'
                            ])
                    ],
                    secret_bytes=base64.b64encode(
                        'https://download_url'.encode('utf-8'))))
        ])
    self.assertEqual(spec, expected_spec)

  def test_get_spec_from_config_for_fuzz_task(self):
    """Tests that _get_new_task_spec works as expected for fuzz commands."""
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    job.put()
    spec = swarming._get_new_task_spec(  # pylint: disable=protected-access
        'fuzz', job.name, 'https://download_url')
    expected_spec = swarming_pb2.NewTaskRequest(
        name='task_name',
        priority=1,
        realm='realm-name',
        service_account='test-clusterfuzz-service-account-email',
        task_slices=[
            swarming_pb2.TaskSlice(
                expiration_secs=86400,
                properties=swarming_pb2.TaskProperties(
                    command=[
                        'luci-auth', 'context', '--', './linux_entry_point.sh'
                    ],
                    dimensions=[
                        swarming_pb2.StringPair(key='os', value=job.platform),
                        swarming_pb2.StringPair(key='pool', value='pool-name')
                    ],
                    cipd_input=swarming_pb2.CipdInput(),  # pylint: disable=no-member
                    cas_input_root=swarming_pb2.CASReference(
                        cas_instance=
                        'projects/server-name/instances/instance_name',
                        digest=swarming_pb2.Digest(
                            hash='linux_entry_point_archive_hash',
                            size_bytes=1234)),
                    execution_timeout_secs=12345,
                    env=[
                        swarming_pb2.StringPair(key='UWORKER', value='True'),
                        swarming_pb2.StringPair(
                            key='SWARMING_BOT', value='True'),
                        swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),
                        swarming_pb2.StringPair(
                            key='LOGGING_CLOUD_PROJECT_ID', value='project_id'),
                        swarming_pb2.StringPair(
                            key='DOCKER_IMAGE',
                            value=
                            'gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654'
                        ),
                    ],
                    secret_bytes=base64.b64encode(
                        'https://download_url'.encode('utf-8'))))
        ])
    self.assertEqual(spec, expected_spec)

  def test_push_swarming_task(self):
    """Tests that push_swarming_task works as expected."""
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    job.put()
    swarming.push_swarming_task('fuzz', 'https://download_url', job.name)

    expected_new_task_request = swarming_pb2.NewTaskRequest(
        name='task_name',
        priority=1,
        realm='realm-name',
        service_account='test-clusterfuzz-service-account-email',
        task_slices=[
            swarming_pb2.TaskSlice(
                expiration_secs=86400,
                properties=swarming_pb2.TaskProperties(
                    command=[
                        'luci-auth', 'context', '--', './linux_entry_point.sh'
                    ],
                    dimensions=[
                        swarming_pb2.StringPair(key='os', value=job.platform),
                        swarming_pb2.StringPair(key='pool', value='pool-name')
                    ],
                    cipd_input=swarming_pb2.CipdInput(),  # pylint: disable=no-member
                    cas_input_root=swarming_pb2.CASReference(
                        cas_instance=
                        'projects/server-name/instances/instance_name',
                        digest=swarming_pb2.Digest(
                            hash='linux_entry_point_archive_hash',
                            size_bytes=1234)),
                    execution_timeout_secs=12345,
                    env=[
                        swarming_pb2.StringPair(key='UWORKER', value='True'),
                        swarming_pb2.StringPair(
                            key='SWARMING_BOT', value='True'),
                        swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),
                        swarming_pb2.StringPair(
                            key='LOGGING_CLOUD_PROJECT_ID', value='project_id'),
                        swarming_pb2.StringPair(
                            key='DOCKER_IMAGE',
                            value=
                            'gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654'
                        ),
                    ],
                    secret_bytes=base64.b64encode(
                        'https://download_url'.encode('utf-8'))))
        ])

    creds, _ = credentials.get_default()
    expected_headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': creds.token
    }
    expected_url = 'https://server-name/prpc/swarming.v2.Tasks/NewTask'
    self.mock.post_url.assert_called_with(
        url=expected_url,
        data=json_format.MessageToJson(expected_new_task_request),
        headers=expected_headers)

  def test_job_requires_gpu(self):
    """Tests that _job_requires_gpu works as expected."""
    job = data_types.Job(
        name='libfuzzer_chrome_asan',
        platform='LINUX',
        environment_string='REQUIRES_GPU=True')
    self.assertTrue(swarming._job_requires_gpu(job))  # pylint: disable=protected-access

    job = data_types.Job(
        name='libfuzzer_chrome_asan',
        platform='LINUX',
        environment_string='REQUIRES_GPU=true')
    self.assertTrue(swarming._job_requires_gpu(job))  # pylint: disable=protected-access

    job = data_types.Job(
        name='libfuzzer_chrome_asan',
        platform='LINUX',
        environment_string='REQUIRES_GPU=false')
    self.assertFalse(swarming._job_requires_gpu(job))  # pylint: disable=protected-access

    job = data_types.Job(
        name='libfuzzer_chrome_asan',
        platform='LINUX',
        environment_string='REQUIRES_GPU=False')
    self.assertFalse(swarming._job_requires_gpu(job))  # pylint: disable=protected-access

    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    self.assertFalse(swarming._job_requires_gpu(job))  # pylint: disable=protected-access

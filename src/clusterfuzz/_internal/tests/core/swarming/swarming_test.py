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
import os
import unittest
from unittest import mock

from google.protobuf import json_format

from clusterfuzz._internal import swarming
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class SwarmingTest(unittest.TestCase):
  """Tests for swarming utils."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.post_url',
        'clusterfuzz._internal.swarming._get_task_name',
        'clusterfuzz._internal.google_cloud_utils.credentials.get_default',
        'clusterfuzz._internal.google_cloud_utils.credentials.get_scoped_service_account_credentials',
        'google.auth.transport.requests.Request',
        'clusterfuzz._internal.swarming.FeatureFlags',
        'clusterfuzz._internal.google_cloud_utils.compute_metadata.get',
    ])
    helpers.patch_environ(self)
    self.mock._get_task_name.return_value = 'task_name'  # pylint: disable=protected-access
    self.mock.FeatureFlags.SWARMING_REMOTE_EXECUTION.enabled = True
    self.mock.get.return_value = None
    self.maxDiff = None
    os.environ.pop('DEPLOYMENT_ZIP', None)
    os.environ.pop('DEPLOYMENT_BUCKET', None)
    os.environ.pop('PROJECT_NAME', None)
    os.environ.pop('HOST_JOB_SELECTION', None)

  def test_get_spec_from_config_with_docker_image(self):
    """Tests that create_new_task_request works as expected."""
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    job.put()
    spec = swarming.create_new_task_request('corpus_pruning', job.name,
                                            'https://download_url')
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
                        swarming_pb2.StringPair(
                            key='os', value=str(job.platform).capitalize()),
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
                        swarming_pb2.StringPair(
                            key='DOCKER_IMAGE',
                            value=
                            'gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654'
                        ),
                        swarming_pb2.StringPair(
                            key='DOCKER_ENV_VARS',
                            value=
                            '{"UWORKER": "True", "SWARMING_BOT": "True", "LOG_TO_GCP": "True", "IS_K8S_ENV": "True", "LOGGING_CLOUD_PROJECT_ID": "project_id"}'
                        ),
                        swarming_pb2.StringPair(key='UWORKER', value='True'),
                        swarming_pb2.StringPair(
                            key='SWARMING_BOT', value='True'),
                        swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),
                        swarming_pb2.StringPair(key='IS_K8S_ENV', value='True'),
                        swarming_pb2.StringPair(
                            key='LOGGING_CLOUD_PROJECT_ID', value='project_id'),
                    ],
                    secret_bytes=base64.b64encode(
                        'https://download_url'.encode('utf-8'))))
        ])
    self.assertEqual(spec, expected_spec)

  def test_get_spec_from_config_returns_none_on_unknown_config(self):
    """Tests that create_new_task_request returns None when there's no mapping for the config."""
    job = data_types.Job(name='some_job_name', platform='UNKNOWN-PLATFORM')
    job.put()
    spec = swarming.create_new_task_request('corpus_pruning', job.name,
                                            'https://download_url')
    self.assertIsNone(spec)

  def test_get_spec_from_config_without_docker_image(self):
    """Tests that create_new_task_request works as expected (without a docker image)."""
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='MAC')
    job.put()
    spec = swarming.create_new_task_request('corpus_pruning', job.name,
                                            'https://download_url')
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
                        swarming_pb2.StringPair(
                            key='os', value=str(job.platform).capitalize()),
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
                        swarming_pb2.StringPair(key='DOCKER_IMAGE', value=''),
                        swarming_pb2.StringPair(key='ENV_VAR1', value='VALUE1'),
                        swarming_pb2.StringPair(key='ENV_VAR2', value='VALUE2'),
                        swarming_pb2.StringPair(
                            key='DOCKER_ENV_VARS',
                            value=
                            '{"UWORKER": "True", "SWARMING_BOT": "True", "LOG_TO_GCP": "True", "IS_K8S_ENV": "True", "LOGGING_CLOUD_PROJECT_ID": "project_id"}'
                        ),
                        swarming_pb2.StringPair(key='UWORKER', value='True'),
                        swarming_pb2.StringPair(
                            key='SWARMING_BOT', value='True'),
                        swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),
                        swarming_pb2.StringPair(key='IS_K8S_ENV', value='True'),
                        swarming_pb2.StringPair(
                            key='LOGGING_CLOUD_PROJECT_ID', value='project_id'),
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
    """Tests that create_new_task_request works as expected for fuzz commands."""
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    job.put()
    spec = swarming.create_new_task_request('fuzz', job.name,
                                            'https://download_url')
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
                        swarming_pb2.StringPair(
                            key='os', value=str(job.platform).capitalize()),
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
                        swarming_pb2.StringPair(
                            key='DOCKER_IMAGE',
                            value=
                            'gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654'
                        ),
                        swarming_pb2.StringPair(
                            key='DOCKER_ENV_VARS',
                            value=
                            '{"UWORKER": "True", "SWARMING_BOT": "True", "LOG_TO_GCP": "True", "IS_K8S_ENV": "True", "LOGGING_CLOUD_PROJECT_ID": "project_id"}'
                        ),
                        swarming_pb2.StringPair(key='UWORKER', value='True'),
                        swarming_pb2.StringPair(
                            key='SWARMING_BOT', value='True'),
                        swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),
                        swarming_pb2.StringPair(key='IS_K8S_ENV', value='True'),
                        swarming_pb2.StringPair(
                            key='LOGGING_CLOUD_PROJECT_ID', value='project_id'),
                    ],
                    secret_bytes=base64.b64encode(
                        'https://download_url'.encode('utf-8'))))
        ])
    self.assertEqual(spec, expected_spec)

  def test_push_swarming_task(self):
    """Tests that push_swarming_task works as expected."""
    mock_creds = mock.MagicMock()
    mock_creds.token = 'fake_token'
    self.mock.get_scoped_service_account_credentials.return_value = mock_creds

    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    job.put()
    task_request = swarming.create_new_task_request('fuzz', job.name,
                                                    'https://download_url')
    swarming.push_swarming_task(task_request)

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
                        swarming_pb2.StringPair(
                            key='os', value=str(job.platform).capitalize()),
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
                        swarming_pb2.StringPair(
                            key='DOCKER_IMAGE',
                            value=
                            'gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654'
                        ),
                        swarming_pb2.StringPair(
                            key='DOCKER_ENV_VARS',
                            value=
                            '{"UWORKER": "True", "SWARMING_BOT": "True", "LOG_TO_GCP": "True", "IS_K8S_ENV": "True", "LOGGING_CLOUD_PROJECT_ID": "project_id"}'
                        ),
                        swarming_pb2.StringPair(key='UWORKER', value='True'),
                        swarming_pb2.StringPair(
                            key='SWARMING_BOT', value='True'),
                        swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),
                        swarming_pb2.StringPair(key='IS_K8S_ENV', value='True'),
                        swarming_pb2.StringPair(
                            key='LOGGING_CLOUD_PROJECT_ID', value='project_id'),
                    ],
                    secret_bytes=base64.b64encode(
                        'https://download_url'.encode('utf-8'))))
        ])

    self.mock.get_scoped_service_account_credentials.assert_called_with(
        swarming._SWARMING_SCOPES)  # pylint: disable=protected-access
    expected_headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer fake_token'
    }
    expected_url = 'https://server-name/prpc/swarming.v2.Tasks/NewTask'
    self.mock.post_url.assert_called_with(
        url=expected_url,
        data=json_format.MessageToJson(expected_new_task_request),
        headers=expected_headers)

  def test_push_swarming_task_with_refresh(self):
    """Tests that push_swarming_task refreshes credentials if token is missing."""
    mock_creds = mock.MagicMock()
    mock_creds.token = None
    self.mock.get_scoped_service_account_credentials.return_value = mock_creds

    def refresh_side_effect(_):
      mock_creds.token = 'refreshed_token'

    mock_creds.refresh.side_effect = refresh_side_effect

    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    job.put()
    request = swarming.create_new_task_request('fuzz', job.name,
                                               'https://download_url')
    swarming.push_swarming_task(request)

    mock_creds.refresh.assert_called_with(self.mock.Request.return_value)
    expected_headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer refreshed_token'
    }
    self.assertEqual(self.mock.post_url.call_args[1]['headers'],
                     expected_headers)

  def test_is_swarming_task(self):
    """Tests that is_swarming_task works as expected."""
    job = data_types.Job(
        name='libfuzzer_chrome_asan',
        platform='LINUX',
        environment_string='IS_SWARMING_JOB = True')
    job.put()
    self.assertTrue(swarming.is_swarming_task(job.name))

    job.environment_string = 'IS_SWARMING_JOB = False'
    job.put()
    self.assertFalse(swarming.is_swarming_task(job.name))

    job.environment_string = ''
    job.put()
    self.assertFalse(swarming.is_swarming_task(job.name))

  def test_is_swarming_task_with_job_instance(self):
    """Tests that is_swarming_task avoids DB query when job is provided."""
    # Mock query to prove that passing a job instance bypasses the Datastore query.
    helpers.patch(self,
                  ['clusterfuzz._internal.datastore.data_types.Job.query'])
    job = data_types.Job(
        name='libfuzzer_chrome_asan',
        platform='LINUX',
        environment_string='IS_SWARMING_JOB = True')
    job.put()  # Ensure it's valid, though it won't be queried

    # Call with job instance
    self.assertTrue(swarming.is_swarming_task(job.name, job=job))
    self.mock.query.assert_not_called()

  def test_is_swarming_task_without_job_instance(self):
    """Tests that is_swarming_task queries the DB when job is not provided."""
    # Mock query to prove that passing a job instance bypasses the Datastore query.
    helpers.patch(self,
                  ['clusterfuzz._internal.datastore.data_types.Job.query'])
    job = data_types.Job(
        name='libfuzzer_chrome_asan',
        platform='LINUX',
        environment_string='IS_SWARMING_JOB = True')
    job.put()

    mock_query_obj = mock.Mock()
    mock_query_obj.get.return_value = job
    self.mock.query.return_value = mock_query_obj

    self.assertTrue(swarming.is_swarming_task(job.name))
    self.mock.query.assert_called_once()

  def test_is_swarming_task_with_feature_flag_disabled(self):
    """Tests that is_swarming_task returns False when the feature flag is disabled."""
    self.mock.FeatureFlags.SWARMING_REMOTE_EXECUTION.enabled = False
    job = data_types.Job(
        name='libfuzzer_chrome_asan',
        platform='LINUX',
        environment_string='IS_SWARMING_JOB = True')
    job.put()
    self.assertFalse(swarming.is_swarming_task(job.name))

  def test_get_task_dimensions_with_env_var(self):
    """Tests that _get_task_dimensions handles SWARMING_DIMENSIONS env var."""
    environment.set_value('SWARMING_DIMENSIONS', {
        'cpu': 'x86',
        'os': 'windows'
    })
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    dimensions = swarming._get_task_dimensions(job, [])  # pylint: disable=protected-access

    expected_dimensions = [
        swarming_pb2.StringPair(key='os', value='windows'),
        swarming_pb2.StringPair(key='pool', value='pool-name'),
        swarming_pb2.StringPair(key='cpu', value='x86'),
    ]
    self.assertCountEqual(dimensions, expected_dimensions)

  def test_get_task_dimensions_job_precedence(self):
    """Tests that job swarming dimensions have more precedence than platform ones."""
    # Use 'MAC' platform which has static dimensions (key1, key2) in swarming.yaml.
    job = data_types.Job(name='mac_job', platform='MAC')
    job.put()

    # Platform dimensions for MAC are: key1: value1, key2: value2.
    # We set SWARMING_DIMENSIONS in the environment to override key1.
    environment.set_value('SWARMING_DIMENSIONS', {'key1': 'job_value1'})

    spec = swarming.create_new_task_request('fuzz', job.name,
                                            'https://download_url')
    dimensions = spec.task_slices[0].properties.dimensions

    expected_dimensions = [
        swarming_pb2.StringPair(key='os', value='Mac'),
        swarming_pb2.StringPair(key='pool', value='pool-name'),
        swarming_pb2.StringPair(key='key1', value='job_value1'),
        swarming_pb2.StringPair(key='key2', value='value2'),
    ]
    self.assertCountEqual(dimensions, expected_dimensions)

  def test_get_env_vars_with_metadata_server(self):
    """Tests that _get_env_vars uses values from the metadata server when available."""

    def metadata_get(path):
      if path == 'project/attributes/deployment-bucket':
        return 'test-bucket-from-metadata'
      return None

    self.mock.get.side_effect = metadata_get
    instance_spec = {
        "docker_image": "gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654"
    }
    env = swarming._get_env_vars('project_id', instance_spec)  # pylint: disable=protected-access

    expected_env = [
        swarming_pb2.StringPair(
            key='DOCKER_IMAGE',
            value='gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654'),
        swarming_pb2.StringPair(
            key='DOCKER_ENV_VARS',
            value=
            '{"UWORKER": "True", "SWARMING_BOT": "True", "LOG_TO_GCP": "True", "IS_K8S_ENV": "True", "LOGGING_CLOUD_PROJECT_ID": "project_id", "DEPLOYMENT_BUCKET": "test-bucket-from-metadata"}'
        ),
        swarming_pb2.StringPair(key='UWORKER', value='True'),
        swarming_pb2.StringPair(key='SWARMING_BOT', value='True'),
        swarming_pb2.StringPair(key='LOG_TO_GCP', value='True'),
        swarming_pb2.StringPair(key='IS_K8S_ENV', value='True'),
        swarming_pb2.StringPair(
            key='LOGGING_CLOUD_PROJECT_ID', value='project_id'),
        swarming_pb2.StringPair(
            key='DEPLOYMENT_BUCKET', value='test-bucket-from-metadata'),
    ]
    self.assertEqual(env, expected_env)

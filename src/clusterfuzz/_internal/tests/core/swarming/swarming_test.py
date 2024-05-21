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

from clusterfuzz._internal import swarming
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class GetSpecFromConfigTest(unittest.TestCase):
  """Tests for get_spec_from_config."""

  def setUp(self):
    self.maxDiff = None
    helpers.patch(self, ['clusterfuzz._internal.swarming._get_task_name'])
    self.mock._get_task_name.return_value = 'task_name'  # pylint: disable=protected-access

  def test_get_spec_from_config(self):
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
                    command=['./linux_entry_point.sh'],
                    dimensions=[
                        swarming_pb2.StringPair(key='os', value=job.platform),
                        swarming_pb2.StringPair(key='pool', value='pool-name')
                    ],
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

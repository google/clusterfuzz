# Copyright 2020 Google LLC
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
"""Tests for task_creation."""
import unittest

from bot.tasks import task_creation
from datastore import data_types
from tests.test_libs import helpers
from tests.test_libs import mock_config
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class RequestBisectionTest(unittest.TestCase):
  """Tests request_bisection."""

  def setUp(self):
    helpers.patch(self, [
        'build_management.revisions.get_component_range_list',
        'config.local_config.ProjectConfig',
        'google_cloud_utils.blobs.read_key',
        'google_cloud_utils.pubsub.PubSubClient.publish',
    ])

    data_types.FuzzTarget(
        id='libFuzzer_proj_target',
        engine='libFuzzer',
        project='proj',
        binary='target').put()

    self.testcase = data_types.Testcase(
        job_type='libfuzzer_asan_proj',
        fuzzer_name='libFuzzer',
        overridden_fuzzer_name='libFuzzer_proj_target',
        regression='123:456',
        fixed='123:456')
    self.testcase.put()

    self.mock.read_key.return_value = b'reproducer'
    self.mock.get_component_range_list.return_value = [
        {
            'link_text': 'old:new',
        },
    ]

    self.mock.ProjectConfig.return_value = mock_config.MockConfig({
        'bisect_service': {
            'pubsub_topic': '/projects/project/topics/topic',
        }
    })

  def _test(self, sanitizer, bisect_type):
    task_creation.request_bisection(self.testcase, bisect_type)
    publish_call = self.mock.publish.call_args[0]
    topic = publish_call[1]
    message = publish_call[2]
    self.assertEqual('/projects/project/topics/topic', topic)
    self.assertEqual(b'reproducer', message.data)
    self.assertDictEqual({
        'fuzz_target': 'target',
        'new_commit': 'new',
        'old_commit': 'old',
        'project_name': 'proj',
        'sanitizer': sanitizer,
        'testcase_id': 1,
        'type': bisect_type,
    }, message.attributes)

  def test_request_bisection_regressed(self):
    """Basic regressed test."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self._test('address', 'regressed')
    self.testcase.job_type = 'libfuzzer_msan_proj'
    self._test('memory', 'regressed')
    self.testcase.job_type = 'libfuzzer_ubsan_proj'
    self._test('undefined', 'regressed')

  def test_request_bisection_fixed(self):
    """Basic fixed test."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self._test('address', 'fixed')
    self.testcase.job_type = 'libfuzzer_msan_proj'
    self._test('memory', 'fixed')
    self.testcase.job_type = 'libfuzzer_ubsan_proj'
    self._test('undefined', 'fixed')

  def test_request_bisection_blackbox(self):
    """Test request bisection for blackbox."""
    self.testcase.job_type = 'blackbox'
    self.testcase.overridden_fuzzer_name = None
    task_creation.request_bisection(self.testcase, 'regressed')
    self.assertEqual(0, self.mock.publish.call_count)

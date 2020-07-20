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
        crash_type='crash-type',
        security_flag=True,
        bug_information='1337',
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

  def _test(self, sanitizer):
    """Test task publication."""
    task_creation.request_bisection(self.testcase)
    publish_calls = self.mock.publish.call_args_list
    bisect_types = ('regressed', 'fixed')

    self.assertEqual(2, len(publish_calls))
    for bisect_type, publish_call in zip(bisect_types, publish_calls):
      topic = publish_call[0][1]
      message = publish_call[0][2][0]
      self.assertEqual('/projects/project/topics/topic', topic)
      self.assertEqual(b'reproducer', message.data)
      self.assertDictEqual({
          'crash_type': 'crash-type',
          'security': 'True',
          'fuzz_target': 'target',
          'new_commit': 'new',
          'old_commit': 'old',
          'project_name': 'proj',
          'sanitizer': sanitizer,
          'testcase_id': '1',
          'issue_id': '1337',
          'type': bisect_type,
      }, message.attributes)

  def test_request_bisection_asan(self):
    """Basic regressed test (asan)."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self._test('address')

  def test_request_bisection_msan(self):
    """Basic regressed test (asan)."""
    self.testcase.job_type = 'libfuzzer_msan_proj'
    self._test('memory')

  def test_request_bisection_ubsan(self):
    """Basic regressed test (ubsan)."""
    self.testcase.job_type = 'libfuzzer_ubsan_proj'
    self._test('undefined')

  def test_request_bisection_blackbox(self):
    """Test request bisection for blackbox."""
    self.testcase.job_type = 'blackbox'
    self.testcase.overridden_fuzzer_name = None
    task_creation.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

  def test_request_bisection_non_security(self):
    """Test request bisection for non-security testcases."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self.testcase.security_flag = False
    task_creation.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

  def test_request_bisection_flaky(self):
    """Test request bisection for flaky testcases."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self.testcase.one_time_crasher_flag = True
    task_creation.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

  def test_request_bisection_no_bug(self):
    """Test request bisection for testcases with no bug attached."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self.testcase.bug_information = ''
    task_creation.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

  def test_request_bisection_invalid_range(self):
    """Test request bisection for testcases with no bug attached."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self.testcase.regression = 'NA'
    self.testcase.fixed = 'NA'
    task_creation.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

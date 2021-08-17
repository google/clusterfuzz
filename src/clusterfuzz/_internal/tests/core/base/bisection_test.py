# Copyright 2021 Google LLC
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
"""Tests for bisection."""
import datetime
import unittest

import mock

from clusterfuzz._internal.base import bisection
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import mock_config
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class RequestBisectionTest(unittest.TestCase):
  """Tests request_bisection."""

  def setUp(self):
    helpers.patch_environ(self)

    helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.get_primary_bucket_path',
        'clusterfuzz._internal.build_management.build_manager.get_revisions_list',
        'clusterfuzz._internal.build_management.revisions.get_component_range_list',
        'clusterfuzz._internal.config.local_config.ProjectConfig',
        'clusterfuzz._internal.google_cloud_utils.blobs.read_key',
        'clusterfuzz._internal.google_cloud_utils.pubsub.PubSubClient.publish',
    ])
    self.mock.ProjectConfig.return_value = mock_config.MockConfig({
        'env': {
            'PROJECT_NAME': 'test-project',
        },
        'bisect_service': {
            'pubsub_topic': '/projects/project/topics/topic',
        }
    })

    data_types.FuzzTarget(
        id='libFuzzer_proj_target',
        engine='libFuzzer',
        project='proj',
        binary='target').put()

    self.testcase = data_types.Testcase(
        timestamp=datetime.datetime(2021, 1, 1),
        crash_type='crash-type',
        crash_state='A\nB\nC',
        security_flag=True,
        bug_information='1337',
        job_type='libfuzzer_asan_proj',
        fuzzer_name='libFuzzer',
        overridden_fuzzer_name='libFuzzer_proj_target',
        regression='123:456',
        fixed='123:456',
        crash_revision=3,
        security_severity=data_types.SecuritySeverity.MEDIUM,
        additional_metadata='{"last_tested_crash_revision": 4}')
    self.testcase.put()

    self.mock.read_key.return_value = b'reproducer'
    self.mock.get_component_range_list.return_value = [
        {
            'link_text': 'old:new',
        },
    ]

  def _test(self, sanitizer, old_commit='old', new_commit='new'):
    """Test task publication."""
    bisection.request_bisection(self.testcase)
    publish_calls = self.mock.publish.call_args_list
    bisect_types = ('regressed', 'fixed')

    self.assertEqual(2, len(publish_calls))
    for bisect_type, publish_call in zip(bisect_types, publish_calls):
      topic = publish_call[0][1]
      message = publish_call[0][2][0]
      self.assertEqual('/projects/project/topics/topic', topic)
      self.assertEqual(b'reproducer', message.data)
      self.assertDictEqual({
          'crash_state': 'A\nB\nC',
          'crash_type': 'crash-type',
          'security': 'True',
          'severity': 'Medium',
          'fuzz_target': 'target',
          'new_commit': new_commit,
          'old_commit': old_commit,
          'project_name': 'proj',
          'sanitizer': sanitizer,
          'testcase_id': '1',
          'issue_id': '1337',
          'type': bisect_type,
          'timestamp': '2021-01-01T00:00:00',
      }, message.attributes)

    testcase = self.testcase.key.get()
    self.assertTrue(testcase.get_metadata('requested_regressed_bisect'))
    self.assertTrue(testcase.get_metadata('requested_fixed_bisect'))

  def test_request_bisection_asan(self):
    """Basic regressed test (asan)."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self.testcase.put()
    self._test('address')

  def test_request_bisection_msan(self):
    """Basic regressed test (asan)."""
    self.testcase.job_type = 'libfuzzer_msan_proj'
    self.testcase.put()
    self._test('memory')

  def test_request_bisection_ubsan(self):
    """Basic regressed test (ubsan)."""
    self.testcase.job_type = 'libfuzzer_ubsan_proj'
    self.testcase.put()
    self._test('undefined')

  def test_request_bisection_blackbox(self):
    """Test request bisection for blackbox."""
    self.testcase.job_type = 'blackbox'
    self.testcase.overridden_fuzzer_name = None
    self.testcase.put()
    bisection.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

  def test_request_bisection_non_security(self):
    """Test request bisection for non-security testcases."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self.testcase.security_flag = False
    self.testcase.put()
    bisection.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

  def test_request_bisection_flaky(self):
    """Test request bisection for flaky testcases."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self.testcase.one_time_crasher_flag = True
    self.testcase.put()
    bisection.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

  def test_request_bisection_no_bug(self):
    """Test request bisection for testcases with no bug attached."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self.testcase.bug_information = ''
    self.testcase.put()
    bisection.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

  def test_request_bisection_invalid_range(self):
    """Test request bisection for testcases with no bug attached."""
    self.testcase.job_type = 'libfuzzer_asan_proj'
    self.testcase.regression = 'NA'
    self.testcase.fixed = 'NA'
    self.testcase.put()
    bisection.request_bisection(self.testcase)

    publish_calls = self.mock.publish.call_args_list
    self.assertEqual(1, len(publish_calls))

    publish_call = publish_calls[0]
    topic = publish_call[0][1]
    message = publish_call[0][2][0]
    self.assertEqual('/projects/project/topics/topic', topic)
    self.assertEqual(b'', message.data)
    self.assertDictEqual({
        'testcase_id': '1',
        'type': 'invalid',
    }, message.attributes)

  def test_request_bisection_once_only(self):
    """Test request bisection for testcases isn't repeated if already
    requested."""
    self.testcase.set_metadata('requested_regressed_bisect', True)
    self.testcase.set_metadata('requested_fixed_bisect', True)
    self.testcase.put()
    bisection.request_bisection(self.testcase)
    self.assertEqual(0, self.mock.publish.call_count)

  def test_request_single_commit_range(self):
    """Request bisection with a single commit (invalid range)."""
    self.mock.get_primary_bucket_path.return_value = 'bucket'
    self.mock.get_revisions_list.return_value = list(range(6))
    self.mock.get_component_range_list.return_value = [
        {
            'link_text': 'one',
        },
    ]
    bisection.request_bisection(self.testcase)
    self._test('address', old_commit='one', new_commit='one')
    self.mock.get_component_range_list.assert_has_calls([
        mock.call(123, 456, 'libfuzzer_asan_proj'),
        mock.call(0, 3, 'libfuzzer_asan_proj'),
        mock.call(123, 456, 'libfuzzer_asan_proj'),
        mock.call(4, 5, 'libfuzzer_asan_proj'),
    ])

# Copyright 2019 Google LLC
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
"""fuzz_task tests."""
# pylint: disable=protected-access

import datetime
import os
import queue
import shutil
import tempfile
import threading
import time
import unittest

import mock
import parameterized
from pyfakefs import fake_filesystem_unittest
import six

from clusterfuzz import stacktraces
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers.libFuzzer import \
    engine as libfuzzer_engine
from clusterfuzz._internal.bot.tasks import fuzz_task
from clusterfuzz._internal.bot.untrusted_runner import file_host
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.chrome import crash_uploader
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz._internal.tests.test_libs import untrusted_runner_helpers
from clusterfuzz.fuzz import engine


class TrackFuzzerRunResultTest(unittest.TestCase):
  """Test _track_fuzzer_run_result."""

  def setUp(self):
    monitor.metrics_store().reset_for_testing()

  def test_fuzzer_run_result(self):
    """Ensure _track_fuzzer_run_result set the right metrics."""
    fuzz_task._track_fuzzer_run_result('name', 10, 100, 2)
    fuzz_task._track_fuzzer_run_result('name', 100, 200, 2)
    fuzz_task._track_fuzzer_run_result('name', 1000, 2000, 2)
    fuzz_task._track_fuzzer_run_result('name', 1000, 500, 0)
    fuzz_task._track_fuzzer_run_result('name', 0, 1000, -1)
    fuzz_task._track_fuzzer_run_result('name', 0, 0, 2)

    self.assertEqual(
        4,
        monitoring_metrics.FUZZER_RETURN_CODE_COUNT.get({
            'fuzzer': 'name',
            'return_code': 2
        }))
    self.assertEqual(
        1,
        monitoring_metrics.FUZZER_RETURN_CODE_COUNT.get({
            'fuzzer': 'name',
            'return_code': 0
        }))
    self.assertEqual(
        1,
        monitoring_metrics.FUZZER_RETURN_CODE_COUNT.get({
            'fuzzer': 'name',
            'return_code': -1
        }))

    testcase_count_ratio = (
        monitoring_metrics.FUZZER_TESTCASE_COUNT_RATIO.get({
            'fuzzer': 'name'
        }))
    self.assertEqual(3.1, testcase_count_ratio.sum)
    self.assertEqual(5, testcase_count_ratio.count)

    expected_buckets = [0 for _ in range(22)]
    expected_buckets[1] = 1
    expected_buckets[3] = 1
    expected_buckets[11] = 2
    expected_buckets[21] = 1
    self.assertListEqual(expected_buckets, testcase_count_ratio.buckets)


class TrackBuildRunResultTest(unittest.TestCase):
  """Test _track_build_run_result."""

  def setUp(self):
    monitor.metrics_store().reset_for_testing()

  def test_build_run_result(self):
    """Ensure _track_build_run_result set the right metrics."""
    fuzz_task._track_build_run_result('name', 10000, True)
    fuzz_task._track_build_run_result('name', 10001, True)
    fuzz_task._track_build_run_result('name', 10002, False)

    self.assertEqual(
        2,
        monitoring_metrics.JOB_BAD_BUILD_COUNT.get({
            'job': 'name',
            'bad_build': True
        }))
    self.assertEqual(
        1,
        monitoring_metrics.JOB_BAD_BUILD_COUNT.get({
            'job': 'name',
            'bad_build': False
        }))


class TrackTestcaseRunResultTest(unittest.TestCase):
  """Test _track_testcase_run_result."""

  def setUp(self):
    monitor.metrics_store().reset_for_testing()

  def test_testcase_run_result(self):
    """Ensure _track_testcase_run_result sets the right metrics."""
    fuzz_task._track_testcase_run_result('fuzzer', 'job', 2, 5)
    fuzz_task._track_testcase_run_result('fuzzer', 'job', 5, 10)

    self.assertEqual(7,
                     monitoring_metrics.JOB_NEW_CRASH_COUNT.get({
                         'job': 'job'
                     }))
    self.assertEqual(
        15, monitoring_metrics.JOB_KNOWN_CRASH_COUNT.get({
            'job': 'job'
        }))
    self.assertEqual(
        7, monitoring_metrics.FUZZER_NEW_CRASH_COUNT.get({
            'fuzzer': 'fuzzer'
        }))
    self.assertEqual(
        15, monitoring_metrics.FUZZER_KNOWN_CRASH_COUNT.get({
            'fuzzer': 'fuzzer'
        }))


class TruncateFuzzerOutputTest(unittest.TestCase):
  """Truncate fuzzer output tests."""

  def test_no_truncation(self):
    """No truncation."""
    self.assertEqual('aaaa', fuzz_task.truncate_fuzzer_output('aaaa', 10))

  def test_truncation(self):
    """Truncate."""
    self.assertEqual(
        '123456\n...truncated...\n54321',
        fuzz_task.truncate_fuzzer_output(
            '123456xxxxxxxxxxxxxxxxxxxxxxxxxxx54321', 28))

  def test_error(self):
    """Error if limit is too low."""
    with self.assertRaises(AssertionError):
      self.assertEqual(
          '', fuzz_task.truncate_fuzzer_output('123456xxxxxx54321', 10))


class TrackFuzzTimeTest(unittest.TestCase):
  """Test _TrackFuzzTime."""

  def setUp(self):
    monitor.metrics_store().reset_for_testing()

  def _test(self, timeout):
    """Test helper."""
    time_module = helpers.MockTime()
    with fuzz_task._TrackFuzzTime('fuzzer', 'job', time_module) as tracker:
      time_module.advance(5)
      tracker.timeout = timeout

    fuzzer_total_time = monitoring_metrics.FUZZER_TOTAL_FUZZ_TIME.get({
        'fuzzer': 'fuzzer',
        'timeout': timeout
    })
    self.assertEqual(5, fuzzer_total_time)

  def test_success(self):
    """Test report metrics."""
    self._test(False)

  def test_timeout(self):
    """Test timeout."""
    self._test(True)


class GetFuzzerMetadataFromOutputTest(unittest.TestCase):
  """Test get_fuzzer_metadata_from_output."""

  def test_no_metadata(self):
    """Tests no metadata in output."""
    data = 'abc\ndef\n123123'
    self.assertDictEqual(fuzz_task.get_fuzzer_metadata_from_output(data), {})

    data = ''
    self.assertDictEqual(fuzz_task.get_fuzzer_metadata_from_output(data), {})

  def test_metadata(self):
    """Tests parsing of metadata."""
    data = ('abc\n'
            'def\n'
            'metadata:invalid: invalid\n'
            'metadat::invalid: invalid\n'
            'metadata::foo: bar\n'
            '123123\n'
            'metadata::blah: 1\n'
            'metadata::test:abcd\n'
            'metadata::test2:   def\n')
    self.assertDictEqual(
        fuzz_task.get_fuzzer_metadata_from_output(data), {
            'blah': '1',
            'test': 'abcd',
            'test2': 'def',
            'foo': 'bar'
        })


class GetRegressionTest(unittest.TestCase):
  """Test get_regression."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.is_custom_binary'
    ])

  def test_one_time_crasher(self):
    """Test when one_time_crasher_flag is True."""
    self.mock.is_custom_binary.return_value = False
    self.assertEqual('NA', fuzz_task.get_regression(True))

  def test_custom_binary(self):
    """Test for custom binary."""
    self.mock.is_custom_binary.return_value = True
    self.assertEqual('NA', fuzz_task.get_regression(False))

  def test_reproducible_non_custom_binary(self):
    """Test for reproducible non-custom binary."""
    self.mock.is_custom_binary.return_value = False
    self.assertEqual('', fuzz_task.get_regression(False))


class GetFixedOrMinimizedKeyTest(unittest.TestCase):
  """Test get_fixed_or_minimized_key."""

  def test_one_time_crasher(self):
    """Test when one_time_crasher_flag is True."""
    self.assertEqual('NA', fuzz_task.get_fixed_or_minimized_key(True))

  def test_reproducible(self):
    """Test for reproducible."""
    self.assertEqual('', fuzz_task.get_fixed_or_minimized_key(False))


class CrashInitTest(fake_filesystem_unittest.TestCase):
  """Test Crash.__init__."""

  def setUp(self):
    """Setup for crash init test."""
    helpers.patch(self, [
        'clusterfuzz._internal.chrome.crash_uploader.FileMetadataInfo',
        'clusterfuzz._internal.bot.tasks.setup.archive_testcase_and_dependencies_in_gcs',
        'clusterfuzz._internal.crash_analysis.stack_parsing.stack_analyzer.get_crash_data',
        'clusterfuzz._internal.bot.testcase_manager.get_additional_command_line_flags',
        'clusterfuzz._internal.bot.testcase_manager.get_command_line_for_application',
        'clusterfuzz._internal.base.utils.get_crash_stacktrace_output',
        'clusterfuzz._internal.crash_analysis.crash_analyzer.ignore_stacktrace',
        'clusterfuzz._internal.crash_analysis.crash_analyzer.is_security_issue',
    ])
    helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)

    self.mock.get_command_line_for_application.return_value = 'cmd'
    dummy_state = stacktraces.CrashInfo()
    dummy_state.crash_type = 'type'
    dummy_state.crash_address = 'address'
    dummy_state.crash_state = 'state'
    dummy_state.crash_stacktrace = 'orig_trace'
    dummy_state.frames = ['frame 1', 'frame 2']
    self.mock.get_crash_data.return_value = dummy_state
    self.mock.get_crash_stacktrace_output.return_value = 'trace'
    self.mock.archive_testcase_and_dependencies_in_gcs.return_value = (
        'fuzzed_key', True, 'absolute_path', 'archive_filename')

    environment.set_value('FILTER_FUNCTIONAL_BUGS', False)

    with open('/stack_file_path', 'w') as f:
      f.write('unsym')

  def test_error(self):
    """Test failing to reading stacktrace file."""
    crash = fuzz_task.Crash.from_testcase_manager_crash(
        testcase_manager.Crash('dir/path-http-name', 123, 11, ['res'], 'ges',
                               '/no_stack_file'))
    self.assertIsNone(crash)

  def _test_crash(self, should_be_ignored, security_flag):
    """Test crash."""
    self.mock.get_command_line_for_application.reset_mock()
    self.mock.get_crash_data.reset_mock()
    self.mock.get_crash_stacktrace_output.reset_mock()
    self.mock.is_security_issue.reset_mock()
    self.mock.ignore_stacktrace.reset_mock()

    self.mock.is_security_issue.return_value = security_flag
    self.mock.ignore_stacktrace.return_value = should_be_ignored

    crash = fuzz_task.Crash.from_testcase_manager_crash(
        testcase_manager.Crash('dir/path-http-name', 123, 11, ['res'], 'ges',
                               '/stack_file_path'))

    self.assertEqual('dir/path-http-name', crash.file_path)
    self.assertEqual(123, crash.crash_time)
    self.assertEqual(11, crash.return_code)
    self.assertListEqual(['res'], crash.resource_list)
    self.assertEqual('ges', crash.gestures)

    self.assertEqual('path-http-name', crash.filename)
    self.assertTrue(crash.http_flag)

    self.assertEqual('cmd', crash.application_command_line)
    self.mock.get_command_line_for_application.assert_called_once_with(
        'dir/path-http-name', needs_http=True)

    self.assertEqual('unsym', crash.unsymbolized_crash_stacktrace)

    self.assertEqual('type', crash.crash_type)
    self.assertEqual('address', crash.crash_address)
    self.assertEqual('state', crash.crash_state)
    self.assertListEqual(['frame 1', 'frame 2'], crash.crash_frames)
    self.mock.get_crash_data.assert_called_once_with('unsym')

    self.assertEqual('trace', crash.crash_stacktrace)
    self.mock.get_crash_stacktrace_output.assert_called_once_with(
        'cmd', 'orig_trace', 'unsym')

    self.assertEqual(security_flag, crash.security_flag)
    self.mock.is_security_issue.assert_called_once_with('unsym', 'type',
                                                        'address')

    self.assertEqual('type,state,%s' % security_flag, crash.key)

    self.assertEqual(should_be_ignored, crash.should_be_ignored)
    self.mock.ignore_stacktrace.assert_called_once_with('orig_trace')

    self.assertFalse(hasattr(crash, 'fuzzed_key'))
    return crash

  def _test_validity_and_get_functional_crash(self):
    """Test validity of different crashes and return functional crash."""
    security_crash = self._test_crash(
        should_be_ignored=False, security_flag=True)
    self.assertIsNone(security_crash.get_error())
    self.assertTrue(security_crash.is_valid())

    ignored_crash = self._test_crash(should_be_ignored=True, security_flag=True)
    self.assertIn('False crash', ignored_crash.get_error())
    self.assertFalse(ignored_crash.is_valid())

    functional_crash = self._test_crash(
        should_be_ignored=False, security_flag=False)
    return functional_crash

  def test_valid_functional_bug(self):
    """Test valid because of functional bug."""
    functional_crash = self._test_validity_and_get_functional_crash()

    self.assertIsNone(functional_crash.get_error())
    self.assertTrue(functional_crash.is_valid())

  def test_invalid_functional_bug(self):
    """Test invalid because of functional bug."""
    environment.set_value('FILTER_FUNCTIONAL_BUGS', True)
    functional_crash = self._test_validity_and_get_functional_crash()

    self.assertIn('Functional crash', functional_crash.get_error())
    self.assertFalse(functional_crash.is_valid())

  def test_hydrate_fuzzed_key(self):
    """Test hydrating fuzzed_key."""
    crash = self._test_crash(should_be_ignored=False, security_flag=True)
    self.assertFalse(crash.is_archived())
    self.assertIsNone(crash.get_error())
    self.assertTrue(crash.is_valid())

    crash.archive_testcase_in_blobstore()
    self.assertTrue(crash.is_archived())
    self.assertIsNone(crash.get_error())
    self.assertTrue(crash.is_valid())

    self.assertEqual('fuzzed_key', crash.fuzzed_key)
    self.assertTrue(crash.archived)
    self.assertEqual('absolute_path', crash.absolute_path)
    self.assertEqual('archive_filename', crash.archive_filename)

  def test_hydrate_fuzzed_key_failure(self):
    """Test fail to hydrate fuzzed_key."""
    self.mock.archive_testcase_and_dependencies_in_gcs.return_value = (None,
                                                                       False,
                                                                       None,
                                                                       None)

    crash = self._test_crash(should_be_ignored=False, security_flag=True)
    self.assertFalse(crash.is_archived())
    self.assertIsNone(crash.get_error())
    self.assertTrue(crash.is_valid())

    crash.archive_testcase_in_blobstore()
    self.assertTrue(crash.is_archived())
    self.assertIn('Unable to store testcase in blobstore', crash.get_error())
    self.assertFalse(crash.is_valid())

    self.assertIsNone(crash.fuzzed_key)
    self.assertFalse(crash.archived)
    self.assertIsNone(crash.absolute_path)
    self.assertIsNone(crash.archive_filename)

  def test_args_from_testcase_manager(self):
    """Test args from testcase_manager.Crash."""
    testcase_manager_crash = testcase_manager.Crash('path', 0, 0, [], [],
                                                    '/stack_file_path')
    self.mock.get_additional_command_line_flags.return_value = 'minimized'
    environment.set_value('APP_ARGS', 'app')

    crash = fuzz_task.Crash.from_testcase_manager_crash(testcase_manager_crash)
    self.assertEqual('app minimized', crash.arguments)


class CrashGroupTest(unittest.TestCase):
  """Test CrashGroup."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.fuzz_task.find_main_crash',
        'clusterfuzz._internal.datastore.data_handler.find_testcase',
        'clusterfuzz._internal.datastore.data_handler.get_project_name',
    ])

    self.mock.get_project_name.return_value = 'some_project'
    self.crashes = [self._make_crash('g1'), self._make_crash('g2')]
    self.context = mock.MagicMock(
        test_timeout=99, fuzzer_name='test', fuzz_target=None)
    self.reproducible_testcase = self._make_testcase(
        project_name='some_project',
        bug_information='',
        one_time_crasher_flag=False)
    self.unreproducible_testcase = self._make_testcase(
        project_name='some_project',
        bug_information='',
        one_time_crasher_flag=True)

  def _make_crash(self, gestures):
    crash = mock.MagicMock(
        crash_type='type',
        crash_state='state',
        security_flag=True,
        file_path='file_path',
        http_flag=True,
        gestures=gestures)
    return crash

  def _make_testcase(self,
                     project_name,
                     bug_information,
                     one_time_crasher_flag,
                     timestamp=datetime.datetime.now()):
    """Make testcase."""
    testcase = data_types.Testcase()
    testcase.timestamp = timestamp
    testcase.one_time_crasher_flag = one_time_crasher_flag
    testcase.bug_information = bug_information
    testcase.project_name = project_name
    return testcase

  def test_no_existing_testcase(self):
    """is_new=True and should_create_testcase=True when there's no existing
        testcase."""
    self.mock.find_testcase.return_value = None
    self.mock.find_main_crash.return_value = self.crashes[0], True

    group = fuzz_task.CrashGroup(self.crashes, self.context)

    self.assertTrue(group.should_create_testcase())
    self.mock.find_main_crash.assert_called_once_with(
        self.crashes, 'test', 'test', self.context.test_timeout)

    self.assertIsNone(group.existing_testcase)
    self.assertEqual(self.crashes[0], group.main_crash)
    self.assertTrue(group.is_new())

  def test_has_existing_reproducible_testcase(self):
    """should_create_testcase=False when there's an existing reproducible
      testcase."""
    self.mock.find_testcase.return_value = self.reproducible_testcase
    self.mock.find_main_crash.return_value = (self.crashes[0], True)

    group = fuzz_task.CrashGroup(self.crashes, self.context)

    self.assertEqual(self.crashes[0].gestures, group.main_crash.gestures)
    self.mock.find_main_crash.assert_called_once_with(
        self.crashes, 'test', 'test', self.context.test_timeout)
    self.assertFalse(group.is_new())
    self.assertFalse(group.should_create_testcase())
    self.assertTrue(group.has_existing_reproducible_testcase())

  def test_reproducible_crash(self):
    """should_create_testcase=True when the group is reproducible."""
    self.mock.find_testcase.return_value = self.unreproducible_testcase
    self.mock.find_main_crash.return_value = (self.crashes[0], False)

    group = fuzz_task.CrashGroup(self.crashes, self.context)

    self.assertEqual(self.crashes[0].gestures, group.main_crash.gestures)
    self.mock.find_main_crash.assert_called_once_with(
        self.crashes, 'test', 'test', self.context.test_timeout)
    self.assertFalse(group.is_new())
    self.assertTrue(group.should_create_testcase())
    self.assertFalse(group.has_existing_reproducible_testcase())
    self.assertFalse(group.one_time_crasher_flag)

  def test_has_existing_unreproducible_testcase(self):
    """should_create_testcase=False when the unreproducible testcase already
    exists."""
    self.mock.find_testcase.return_value = self.unreproducible_testcase
    self.mock.find_main_crash.return_value = (self.crashes[0], True)

    group = fuzz_task.CrashGroup(self.crashes, self.context)

    self.assertFalse(group.should_create_testcase())

    self.assertEqual(self.crashes[0].gestures, group.main_crash.gestures)
    self.mock.find_main_crash.assert_called_once_with(
        self.crashes, 'test', 'test', self.context.test_timeout)
    self.assertFalse(group.is_new())
    self.assertFalse(group.has_existing_reproducible_testcase())
    self.assertTrue(group.one_time_crasher_flag)


class FindMainCrashTest(unittest.TestCase):
  """Test find_main_crash."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.testcase_manager.test_for_reproducibility',
    ])
    self.crashes = [
        self._make_crash('g1'),
        self._make_crash('g2'),
        self._make_crash('g3'),
        self._make_crash('g4')
    ]
    self.reproducible_crashes = []

    # pylint: disable=unused-argument
    def test_for_repro(fuzzer_name,
                       full_fuzzer_name,
                       file_path,
                       state,
                       security_flag,
                       test_timeout,
                       http_flag,
                       gestures,
                       arguments=None):
      """Mock test_for_reproducibility."""
      for c in self.reproducible_crashes:
        if c.gestures == gestures:
          return True
      return False

    self.mock.test_for_reproducibility.side_effect = test_for_repro

  def _make_crash(self, gestures):
    crash = mock.MagicMock(
        file_path='file_path',
        crash_state='state',
        security_flag=True,
        test_timeout=999,
        gestures=gestures)
    return crash

  def test_reproducible_crash(self):
    """Find that the 2nd crash is reproducible."""
    for c in self.crashes:
      c.is_valid.return_value = True
    self.crashes[0].is_valid.return_value = False
    self.reproducible_crashes = [self.crashes[2]]

    self.assertEqual((self.crashes[2], False),
                     fuzz_task.find_main_crash(self.crashes, 'test', 'test',
                                               99))

    self.crashes[0].archive_testcase_in_blobstore.assert_called_once_with()
    self.crashes[1].archive_testcase_in_blobstore.assert_called_once_with()
    self.crashes[2].archive_testcase_in_blobstore.assert_called_once_with()
    self.crashes[3].archive_testcase_in_blobstore.assert_not_called()

    # Calls for self.crashes[1] and self.crashes[2].
    self.assertEqual(2, self.mock.test_for_reproducibility.call_count)

  def test_unreproducible_crash(self):
    """No reproducible crash. Find the first valid one."""
    for c in self.crashes:
      c.is_valid.return_value = True
    self.crashes[0].is_valid.return_value = False
    self.reproducible_crashes = []

    self.assertEqual((self.crashes[1], True),
                     fuzz_task.find_main_crash(self.crashes, 'test', 'test',
                                               99))

    for c in self.crashes:
      c.archive_testcase_in_blobstore.assert_called_once_with()

    # Calls for every crash except self.crashes[0] because it's invalid.
    self.assertEqual(
        len(self.crashes) - 1, self.mock.test_for_reproducibility.call_count)

  def test_no_valid_crash(self):
    """No valid crash."""
    for c in self.crashes:
      c.is_valid.return_value = False
    self.reproducible_crashes = []

    self.assertEqual((None, None),
                     fuzz_task.find_main_crash(self.crashes, 'test', 'test',
                                               99))

    for c in self.crashes:
      c.archive_testcase_in_blobstore.assert_called_once_with()

    self.assertEqual(0, self.mock.test_for_reproducibility.call_count)


@test_utils.with_cloud_emulators('datastore')
class ProcessCrashesTest(fake_filesystem_unittest.TestCase):
  """Test process_crashes."""

  def setUp(self):
    """Setup for process crashes test."""
    helpers.patch(self, [
        'clusterfuzz._internal.chrome.crash_uploader.get_symbolized_stack_bytes',
        'clusterfuzz._internal.bot.tasks.fuzz_task.get_unsymbolized_crash_stacktrace',
        'clusterfuzz._internal.bot.tasks.task_creation.create_tasks',
        'clusterfuzz._internal.bot.tasks.setup.archive_testcase_and_dependencies_in_gcs',
        'clusterfuzz._internal.crash_analysis.stack_parsing.stack_analyzer.get_crash_data',
        'clusterfuzz._internal.build_management.revisions.get_real_revision',
        'clusterfuzz._internal.bot.testcase_manager.get_command_line_for_application',
        'clusterfuzz._internal.bot.testcase_manager.test_for_reproducibility',
        'clusterfuzz._internal.base.utils.get_crash_stacktrace_output',
        'clusterfuzz._internal.crash_analysis.crash_analyzer.ignore_stacktrace',
        'clusterfuzz._internal.crash_analysis.crash_analyzer.is_security_issue',
        'clusterfuzz._internal.datastore.data_handler.get_issue_tracker_name',
        'clusterfuzz._internal.datastore.data_handler.get_project_name',
        'clusterfuzz._internal.google_cloud_utils.big_query.Client.insert',
        'clusterfuzz._internal.google_cloud_utils.big_query.get_api_client',
        'time.sleep', 'time.time'
    ])
    test_utils.set_up_pyfakefs(self)

    self.mock.time.return_value = 987

    self.mock.get_issue_tracker_name.return_value = 'some_issue_tracker'
    self.mock.get_project_name.return_value = 'some_project'
    self.mock.archive_testcase_and_dependencies_in_gcs.return_value = (
        'fuzzed_key', True, 'absolute_path', 'archive_filename')

  def _make_crash(self, trace, state='state'):
    """Make crash."""
    self.mock.get_real_revision.return_value = 'this.is.fake.ver'

    self.mock.get_command_line_for_application.return_value = 'cmd'
    dummy_state = stacktraces.CrashInfo()
    dummy_state.crash_type = 'type'
    dummy_state.crash_address = 'address'
    dummy_state.crash_state = state
    dummy_state.crash_stacktrace = 'orig_trace'
    dummy_state.crash_frames = ['frame 1', 'frame 2']
    self.mock.get_crash_data.return_value = dummy_state
    self.mock.get_symbolized_stack_bytes.return_value = b'f00df00d'
    self.mock.get_crash_stacktrace_output.return_value = trace
    self.mock.get_unsymbolized_crash_stacktrace.return_value = trace
    self.mock.is_security_issue.return_value = True
    self.mock.ignore_stacktrace.return_value = False

    with open('/stack_file_path', 'w') as f:
      f.write('unsym')

    crash = fuzz_task.Crash.from_testcase_manager_crash(
        testcase_manager.Crash('dir/path-http-name', 123, 11, ['res'], ['ges'],
                               '/stack_file_path'))
    return crash

  def test_existing_unreproducible_testcase(self):
    """Test existing unreproducible testcase."""
    crashes = [self._make_crash('c1'), self._make_crash('c2')]
    self.mock.test_for_reproducibility.return_value = False

    existing_testcase = data_types.Testcase()
    existing_testcase.crash_stacktrace = 'existing'
    existing_testcase.crash_type = crashes[0].crash_type
    existing_testcase.crash_state = crashes[0].crash_state
    existing_testcase.security_flag = crashes[0].security_flag
    existing_testcase.one_time_crasher_flag = True
    existing_testcase.job_type = 'existing_job'
    existing_testcase.timestamp = datetime.datetime.now()
    existing_testcase.project_name = 'some_project'
    existing_testcase.put()

    variant = data_types.TestcaseVariant()
    variant.status = data_types.TestcaseVariantStatus.UNREPRODUCIBLE
    variant.job_type = 'job'
    variant.testcase_id = existing_testcase.key.id()
    variant.put()

    new_crash_count, known_crash_count, groups = fuzz_task.process_crashes(
        crashes=crashes,
        context=fuzz_task.Context(
            project_name='some_project',
            bot_name='bot',
            job_type='job',
            fuzz_target=data_types.FuzzTarget(engine='engine', binary='binary'),
            redzone=111,
            disable_ubsan=True,
            platform_id='platform',
            crash_revision=1234,
            fuzzer_name='fuzzer',
            window_argument='win_args',
            fuzzer_metadata={},
            testcases_metadata={},
            timeout_multiplier=1,
            test_timeout=2,
            thread_wait_timeout=3,
            data_directory='/data'))
    self.assertEqual(0, new_crash_count)
    self.assertEqual(2, known_crash_count)

    self.assertEqual(1, len(groups))
    self.assertEqual(2, len(groups[0].crashes))
    self.assertFalse(groups[0].is_new())
    self.assertEqual(crashes[0].crash_type, groups[0].main_crash.crash_type)
    self.assertEqual(crashes[0].crash_state, groups[0].main_crash.crash_state)
    self.assertEqual(crashes[0].security_flag,
                     groups[0].main_crash.security_flag)

    testcases = list(data_types.Testcase.query())
    self.assertEqual(1, len(testcases))
    self.assertEqual('existing', testcases[0].crash_stacktrace)

    variant = data_handler.get_testcase_variant(existing_testcase.key.id(),
                                                'job')
    self.assertEqual(data_types.TestcaseVariantStatus.FLAKY, variant.status)
    self.assertEqual('fuzzed_key', variant.reproducer_key)
    self.assertEqual(1234, variant.revision)
    self.assertEqual('type', variant.crash_type)
    self.assertEqual('state', variant.crash_state)
    self.assertEqual(True, variant.security_flag)
    self.assertEqual(True, variant.is_similar)

  @parameterized.parameterized.expand(['some_project', 'chromium'])
  def test_create_many_groups(self, project_name):
    """Test creating many groups."""
    self.mock.get_project_name.return_value = project_name

    self.mock.insert.return_value = {'insertErrors': [{'index': 0}]}

    # TODO(metzman): Add a separate test for strategies.
    r2_stacktrace = ('r2\ncf::fuzzing_strategies: value_profile\n')

    crashes = [
        self._make_crash('r1', state='reproducible1'),
        self._make_crash(r2_stacktrace, state='reproducible1'),
        self._make_crash('r3', state='reproducible1'),
        self._make_crash('r4', state='reproducible2'),
        self._make_crash('u1', state='unreproducible1'),
        self._make_crash('u2', state='unreproducible2'),
        self._make_crash('u3', state='unreproducible2'),
        self._make_crash('u4', state='unreproducible3')
    ]

    self.mock.test_for_reproducibility.side_effect = [
        False,  # For r1. It returns False. So, r1 is demoted.
        True,  # For r2. It returns True. So, r2 becomes primary for its group.
        True,  # For r4.
        False,  # For u1.
        False,  # For u2.
        False,  # For u3.
        False
    ]  # For u4.

    new_crash_count, known_crash_count, groups = fuzz_task.process_crashes(
        crashes=crashes,
        context=fuzz_task.Context(
            project_name=project_name,
            bot_name='bot',
            job_type='job',
            fuzz_target=data_types.FuzzTarget(engine='engine', binary='binary'),
            redzone=111,
            disable_ubsan=False,
            platform_id='platform',
            crash_revision=1234,
            fuzzer_name='fuzzer',
            window_argument='win_args',
            fuzzer_metadata={},
            testcases_metadata={},
            timeout_multiplier=1,
            test_timeout=2,
            thread_wait_timeout=3,
            data_directory='/data'))
    self.assertEqual(5, new_crash_count)
    self.assertEqual(3, known_crash_count)

    self.assertEqual(5, len(groups))
    self.assertEqual([
        'reproducible1', 'reproducible2', 'unreproducible1', 'unreproducible2',
        'unreproducible3'
    ], [group.main_crash.crash_state for group in groups])
    self.assertEqual([True, True, True, True, True],
                     [group.is_new() for group in groups])
    self.assertEqual([3, 1, 1, 2, 1], [len(group.crashes) for group in groups])

    testcases = list(data_types.Testcase.query())
    self.assertEqual(5, len(testcases))
    self.assertSetEqual(
        set([r2_stacktrace, 'r4', 'u1', 'u2', 'u4']),
        set(t.crash_stacktrace for t in testcases))

    self.assertSetEqual(
        set([
            '{"fuzzing_strategies": ["value_profile"]}', None, None, None, None
        ]), set(t.additional_metadata for t in testcases))

    # r2 is a reproducible crash, so r3 doesn't
    # invoke archive_testcase_in_blobstore. Therefore, the
    # archive_testcase_in_blobstore is called `len(crashes) - 1`.
    self.assertEqual(
        len(crashes) - 1,
        self.mock.archive_testcase_and_dependencies_in_gcs.call_count)

    # Check only the desired testcases were saved.
    actual_crash_infos = [group.main_crash.crash_info for group in groups]
    if project_name != 'chromium':
      expected_crash_infos = [None] * len(actual_crash_infos)
    else:
      expected_saved_crash_info = crash_uploader.CrashReportInfo(
          product='Chrome_' + environment.platform().lower().capitalize(),
          version='this.is.fake.ver',
          serialized_crash_stack_frames=b'f00df00d')
      expected_crash_infos = [
          expected_saved_crash_info,  # r2 is main crash for group r1,r2,r3
          expected_saved_crash_info,  # r4 is main crash for its own group
          None,  # u1 is not reproducible
          None,  # u2, u3 are not reproducible
          None,  # u4 is not reproducible
      ]

    self.assertEqual(len(expected_crash_infos), len(actual_crash_infos))
    for expected, actual in zip(expected_crash_infos, actual_crash_infos):
      if not expected:
        self.assertIsNone(actual)
        continue

      self.assertEqual(expected.product, actual.product)
      self.assertEqual(expected.version, actual.version)
      self.assertEqual(expected.serialized_crash_stack_frames,
                       actual.serialized_crash_stack_frames)

    def _make_big_query_json(crash, reproducible_flag, new_flag, testcase_id):
      return {
          'crash_type': crash.crash_type,
          'crash_state': crash.crash_state,
          'created_at': 987,
          'platform': 'platform',
          'crash_time_in_ms': int(crash.crash_time * 1000),
          'parent_fuzzer_name': 'engine',
          'fuzzer_name': 'engine_binary',
          'job_type': 'job',
          'security_flag': crash.security_flag,
          'reproducible_flag': reproducible_flag,
          'revision': '1234',
          'new_flag': new_flag,
          'project': project_name,
          'testcase_id': testcase_id
      }

    def _get_testcase_id(crash):
      rows = list(
          data_types.Testcase.query(
              data_types.Testcase.crash_type == crash.crash_type,
              data_types.Testcase.crash_state == crash.crash_state,
              data_types.Testcase.security_flag == crash.security_flag))
      if not rows:
        return None
      return str(rows[0].key.id())

    # Calls to write 5 groups of crashes to BigQuery.
    self.assertEqual(5, self.mock.insert.call_count)
    self.mock.insert.assert_has_calls([
        mock.call(mock.ANY, [
            big_query.Insert(
                _make_big_query_json(crashes[0], True, False, None),
                '%s:bot:987:0' % crashes[0].key),
            big_query.Insert(
                _make_big_query_json(crashes[1], True, True,
                                     _get_testcase_id(crashes[1])),
                '%s:bot:987:1' % crashes[0].key),
            big_query.Insert(
                _make_big_query_json(crashes[2], True, False, None),
                '%s:bot:987:2' % crashes[0].key)
        ]),
        mock.call(mock.ANY, [
            big_query.Insert(
                _make_big_query_json(crashes[3], True, True,
                                     _get_testcase_id(crashes[3])),
                '%s:bot:987:0' % crashes[3].key)
        ]),
        mock.call(mock.ANY, [
            big_query.Insert(
                _make_big_query_json(crashes[4], False, True,
                                     _get_testcase_id(crashes[4])),
                '%s:bot:987:0' % crashes[4].key)
        ]),
        mock.call(mock.ANY, [
            big_query.Insert(
                _make_big_query_json(crashes[5], False, True,
                                     _get_testcase_id(crashes[5])),
                '%s:bot:987:0' % crashes[5].key),
            big_query.Insert(
                _make_big_query_json(crashes[6], False, False, None),
                '%s:bot:987:1' % crashes[5].key)
        ]),
        mock.call(mock.ANY, [
            big_query.Insert(
                _make_big_query_json(crashes[7], False, True,
                                     _get_testcase_id(crashes[7])),
                '%s:bot:987:0' % crashes[7].key)
        ]),
    ])


class WriteCrashToBigQueryTest(unittest.TestCase):
  """Test write_crash_to_big_query."""

  def setUp(self):
    self.client = mock.Mock(spec_set=big_query.Client)
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.get_value',
        'clusterfuzz._internal.datastore.data_handler.get_project_name',
        'clusterfuzz._internal.google_cloud_utils.big_query.Client',
        'time.time',
    ])
    monitor.metrics_store().reset_for_testing()

    self.mock.get_project_name.return_value = 'some_project'
    self.mock.get_value.return_value = 'bot'
    self.mock.Client.return_value = self.client
    self.mock.time.return_value = 99
    self.crashes = [
        self._make_crash('c1'),
        self._make_crash('c2'),
        self._make_crash('c3')
    ]

    newly_created_testcase = mock.MagicMock()
    newly_created_testcase.key.id.return_value = 't'
    self.group = mock.MagicMock(
        crashes=self.crashes,
        main_crash=self.crashes[0],
        one_time_crasher_flag=False,
        newly_created_testcase=newly_created_testcase)
    self.group.is_new.return_value = True

  def _create_context(self, job_type, platform_id):
    return fuzz_task.Context(
        project_name='some_project',
        bot_name='bot',
        job_type=job_type,
        fuzz_target=data_types.FuzzTarget(engine='engine', binary='binary'),
        redzone=32,
        disable_ubsan=False,
        platform_id=platform_id,
        crash_revision=1234,
        fuzzer_name='engine',
        window_argument='windows_args',
        fuzzer_metadata={},
        testcases_metadata={},
        timeout_multiplier=1.0,
        test_timeout=5,
        thread_wait_timeout=6,
        data_directory='data')

  def _make_crash(self, state):
    crash = mock.Mock(
        crash_type='type',
        crash_state=state,
        crash_time=111,
        security_flag=True,
        key='key')
    return crash

  def _json(self, job, platform, state, new_flag, testcase_id):
    return {
        'crash_type': 'type',
        'crash_state': state,
        'created_at': 99,
        'platform': platform,
        'crash_time_in_ms': 111000,
        'parent_fuzzer_name': 'engine',
        'fuzzer_name': 'engine_binary',
        'job_type': job,
        'security_flag': True,
        'reproducible_flag': True,
        'revision': '1234',
        'new_flag': new_flag,
        'project': 'some_project',
        'testcase_id': testcase_id
    }

  def test_all_succeed(self):
    """Test writing succeeds."""
    self.client.insert.return_value = {}
    context = self._create_context('job', 'linux')
    fuzz_task.write_crashes_to_big_query(self.group, context)

    success_count = monitoring_metrics.BIG_QUERY_WRITE_COUNT.get({
        'success': True
    })
    failure_count = monitoring_metrics.BIG_QUERY_WRITE_COUNT.get({
        'success': False
    })

    self.assertEqual(3, success_count)
    self.assertEqual(0, failure_count)

    self.mock.Client.assert_called_once_with(
        dataset_id='main', table_id='crashes$19700101')
    self.client.insert.assert_called_once_with([
        big_query.Insert(
            self._json('job', 'linux', 'c1', True, 't'), 'key:bot:99:0'),
        big_query.Insert(
            self._json('job', 'linux', 'c2', False, None), 'key:bot:99:1'),
        big_query.Insert(
            self._json('job', 'linux', 'c3', False, None), 'key:bot:99:2')
    ])

  def test_succeed(self):
    """Test writing succeeds."""
    self.client.insert.return_value = {'insertErrors': [{'index': 1}]}
    context = self._create_context('job', 'linux')
    fuzz_task.write_crashes_to_big_query(self.group, context)

    success_count = monitoring_metrics.BIG_QUERY_WRITE_COUNT.get({
        'success': True
    })
    failure_count = monitoring_metrics.BIG_QUERY_WRITE_COUNT.get({
        'success': False
    })

    self.assertEqual(2, success_count)
    self.assertEqual(1, failure_count)

    self.mock.Client.assert_called_once_with(
        dataset_id='main', table_id='crashes$19700101')
    self.client.insert.assert_called_once_with([
        big_query.Insert(
            self._json('job', 'linux', 'c1', True, 't'), 'key:bot:99:0'),
        big_query.Insert(
            self._json('job', 'linux', 'c2', False, None), 'key:bot:99:1'),
        big_query.Insert(
            self._json('job', 'linux', 'c3', False, None), 'key:bot:99:2')
    ])

  def test_chromeos_platform(self):
    """Test ChromeOS platform is written in stats."""
    self.client.insert.return_value = {'insertErrors': [{'index': 1}]}
    context = self._create_context('job_chromeos', 'linux')
    fuzz_task.write_crashes_to_big_query(self.group, context)

    success_count = monitoring_metrics.BIG_QUERY_WRITE_COUNT.get({
        'success': True
    })
    failure_count = monitoring_metrics.BIG_QUERY_WRITE_COUNT.get({
        'success': False
    })

    self.assertEqual(2, success_count)
    self.assertEqual(1, failure_count)

    self.mock.Client.assert_called_once_with(
        dataset_id='main', table_id='crashes$19700101')
    self.client.insert.assert_called_once_with([
        big_query.Insert(
            self._json('job_chromeos', 'chrome', 'c1', True, 't'),
            'key:bot:99:0'),
        big_query.Insert(
            self._json('job_chromeos', 'chrome', 'c2', False, None),
            'key:bot:99:1'),
        big_query.Insert(
            self._json('job_chromeos', 'chrome', 'c3', False, None),
            'key:bot:99:2')
    ])

  def test_exception(self):
    """Test writing raising an exception."""
    self.client.insert.side_effect = Exception('error')
    context = self._create_context('job', 'linux')
    fuzz_task.write_crashes_to_big_query(self.group, context)

    success_count = monitoring_metrics.BIG_QUERY_WRITE_COUNT.get({
        'success': True
    })
    failure_count = monitoring_metrics.BIG_QUERY_WRITE_COUNT.get({
        'success': False
    })

    self.assertEqual(0, success_count)
    self.assertEqual(3, failure_count)


class ConvertGroupsToCrashesTest(object):
  """Test convert_groups_to_crashes."""

  def test_convert(self):
    """Test converting."""
    groups = [
        mock.Mock(
            crashes=[mock.Mock(), mock.Mock()],
            main_crash=mock.Mock(
                crash_type='t1', crash_state='s1', security_flag=True)),
        mock.Mock(
            crashes=[mock.Mock()],
            main_crash=mock.Mock(
                crash_type='t2', crash_state='s2', security_flag=False)),
    ]
    groups[0].is_new.return_value = False
    groups[1].is_new.return_value = True

    self.assertEqual([
        {
            'is_new': False,
            'count': 2,
            'crash_type': 't1',
            'crash_state': 's1',
            'security_flag': True
        },
        {
            'is_new': True,
            'count': 1,
            'crash_type': 't2',
            'crash_state': 's2',
            'security_flag': False
        },
    ], fuzz_task.convert_groups_to_crashes(groups))


class TestCorpusSync(fake_filesystem_unittest.TestCase):
  """Test corpus sync."""

  def setUp(self):
    """Setup for test corpus sync."""
    helpers.patch(self, [
        'clusterfuzz._internal.fuzzing.corpus_manager.FuzzTargetCorpus.rsync_to_disk',
        'clusterfuzz._internal.fuzzing.corpus_manager.FuzzTargetCorpus.upload_files',
        'clusterfuzz._internal.google_cloud_utils.storage.last_updated',
    ])

    helpers.patch_environ(self)

    os.environ['FAIL_RETRIES'] = '1'
    os.environ['CORPUS_BUCKET'] = 'bucket'

    self.mock.rsync_to_disk.return_value = True
    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir('/dir')
    self.fs.create_dir('/dir1')

  def _write_corpus_files(self, *args, **kwargs):  # pylint: disable=unused-argument
    self.fs.create_file('/dir/a')
    self.fs.create_file('/dir/b')
    return True

  def test_sync(self):
    """Test corpus sync."""
    corpus = fuzz_task.GcsCorpus('parent', 'child', '/dir', '/dir1')

    self.mock.rsync_to_disk.side_effect = self._write_corpus_files
    self.assertTrue(corpus.sync_from_gcs())
    self.assertTrue(os.path.exists('/dir1/.child_sync'))
    self.assertEqual(('/dir',), self.mock.rsync_to_disk.call_args[0][1:])
    self.fs.create_file('/dir/c')
    self.assertListEqual(['/dir/c'], corpus.get_new_files())

    corpus.upload_files(corpus.get_new_files())
    self.assertEqual((['/dir/c'],), self.mock.upload_files.call_args[0][1:])

    self.assertListEqual([], corpus.get_new_files())

  def test_no_sync(self):
    """Test no corpus sync when bundle is not updated since last sync."""
    corpus = fuzz_task.GcsCorpus('parent', 'child', '/dir', '/dir1')

    utils.write_data_to_file(time.time(), '/dir1/.child_sync')
    self.mock.last_updated.return_value = (
        datetime.datetime.utcnow() - datetime.timedelta(days=1))
    self.assertTrue(corpus.sync_from_gcs())
    self.assertEqual(0, self.mock.rsync_to_disk.call_count)

  def test_sync_with_failed_last_update(self):
    """Test corpus sync when failed to get last update info from gcs."""
    corpus = fuzz_task.GcsCorpus('parent', 'child', '/dir', '/dir1')

    utils.write_data_to_file(time.time(), '/dir1/.child_sync')
    self.mock.last_updated.return_value = None
    self.assertTrue(corpus.sync_from_gcs())
    self.assertEqual(1, self.mock.rsync_to_disk.call_count)


@test_utils.with_cloud_emulators('datastore')
class DoBlackboxFuzzingTest(fake_filesystem_unittest.TestCase):
  """do_blackbox_fuzzing tests."""

  def setUp(self):
    """Setup for blackbox fuzzing test."""
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.random_element_from_list',
        'clusterfuzz._internal.base.utils.random_number',
        'clusterfuzz._internal.bot.fuzzers.engine_common.current_timestamp',
        'clusterfuzz._internal.bot.tasks.fuzz_task.pick_gestures',
        'clusterfuzz._internal.bot.testcase_manager.upload_log',
        'clusterfuzz._internal.bot.testcase_manager.upload_testcase',
        'clusterfuzz._internal.build_management.revisions.get_component_list',
        'clusterfuzz._internal.crash_analysis.crash_analyzer.is_crash',
        'clusterfuzz._internal.crash_analysis.stack_parsing.stack_analyzer.get_crash_data',
        'clusterfuzz._internal.datastore.ndb_init.context',
        'clusterfuzz._internal.metrics.fuzzer_stats.upload_stats',
        'random.random',
        'clusterfuzz._internal.system.process_handler.close_queue',
        'clusterfuzz._internal.system.process_handler.get_process',
        'clusterfuzz._internal.system.process_handler.get_queue',
        'clusterfuzz._internal.system.process_handler.run_process',
        'clusterfuzz._internal.system.process_handler.terminate_hung_threads',
        'clusterfuzz._internal.system.process_handler.'
        'terminate_stale_application_instances',
    ])

    os.environ['APP_ARGS'] = '-x'
    os.environ['APP_ARGS_APPEND_TESTCASE'] = 'True'
    os.environ['APP_DIR'] = '/app'
    os.environ['APP_NAME'] = 'app_1'
    os.environ['APP_PATH'] = '/app/app_1'
    os.environ['BOT_TMPDIR'] = '/tmp'
    os.environ['CRASH_STACKTRACES_DIR'] = '/crash'
    os.environ['ENABLE_GESTURES'] = 'False'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['FUZZER_DIR'] = '/fuzzer'
    os.environ['INPUT_DIR'] = '/input'
    os.environ['JOB_NAME'] = 'asan_test'
    os.environ['MAX_FUZZ_THREADS'] = '1'
    os.environ['MAX_TESTCASES'] = '3'
    os.environ['RANDOM_SEED'] = '-r'
    os.environ['ROOT_DIR'] = '/root'
    os.environ['THREAD_ALIVE_CHECK_INTERVAL'] = '0.001'
    os.environ['THREAD_DELAY'] = '0.001'
    os.environ['USER_PROFILE_IN_MEMORY'] = 'True'

    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir('/crash')
    self.fs.create_dir('/root/bot/logs')

    # Value picked as timeout multiplier.
    self.mock.random_element_from_list.return_value = 2.0
    # Choose window_arg, timeout multiplier, random seed.
    self.mock.random_number.side_effect = [0, 0, 3]
    # One trial profile for the session.
    self.mock.random.side_effect = [0.3, 0.3]
    self.mock.pick_gestures.return_value = []
    self.mock.get_component_list.return_value = [{
        'component': 'component',
        'link_text': 'rev',
    }]
    self.mock.current_timestamp.return_value = 0.0

    # Dummy output when running tests. E.g. exit code 0 and no output.
    self.mock.run_process.return_value = (0, 0, '')

    # Treat first and third run as crashed.
    self.mock.is_crash.side_effect = [True, False, True]

    self.mock.get_queue.return_value = queue.Queue()
    self.mock.get_process.return_value = threading.Thread

  def test_trials(self):
    """Test fuzzing session with trials."""
    data_types.Trial(app_name='app_1', probability=0.5, app_args='-y').put()
    data_types.Trial(app_name='app_1', probability=0.2, app_args='-z').put()

    session = fuzz_task.FuzzingSession('fantasy_fuzz', 'asan_test', 10)
    self.assertEqual(20, session.test_timeout)

    # Mock out actual test-case generation for 3 tests.
    session.generate_blackbox_testcases = mock.MagicMock()
    expected_testcase_file_paths = ['/tests/0', '/tests/1', '/tests/2']
    session.generate_blackbox_testcases.return_value = (
        False, expected_testcase_file_paths, None, {
            'fuzzer_binary_name': 'fantasy_fuzz'
        })

    fuzzer = data_types.Fuzzer()
    fuzzer.name = 'fantasy_fuzz'

    fuzzer_metadata, testcase_file_paths, testcases_metadata, crashes = (
        session.do_blackbox_fuzzing(fuzzer, '/fake-fuzz-dir', 'asan_test'))

    self.assertEqual({'fuzzer_binary_name': 'fantasy_fuzz'}, fuzzer_metadata)
    self.assertEqual(expected_testcase_file_paths, testcase_file_paths)
    self.assertEqual(
        dict((t, {
            'gestures': []
        }) for t in expected_testcase_file_paths), testcases_metadata)

    self.assertEqual(3, len(self.mock.is_crash.call_args_list))

    # Verify the three test runs are called with the correct arguments.
    calls = self.mock.run_process.call_args_list
    self.assertEqual(3, len(calls))
    self.assertEqual('/app/app_1 -r=3 -x -y /tests/0', calls[0][0][0])
    self.assertEqual('/app/app_1 -r=3 -x -y /tests/1', calls[1][0][0])
    self.assertEqual('/app/app_1 -r=3 -x -y /tests/2', calls[2][0][0])

    # Verify the two crashes store the correct arguments.
    self.assertEqual(2, len(crashes))
    self.assertEqual('/app/app_1 -r=3 -x -y /tests/0',
                     crashes[0].application_command_line)
    self.assertEqual('/app/app_1 -r=3 -x -y /tests/2',
                     crashes[1].application_command_line)


@test_utils.with_cloud_emulators('datastore')
class DoEngineFuzzingTest(fake_filesystem_unittest.TestCase):
  """do_engine_fuzzing tests."""

  def setUp(self):
    """Setup for do engine fuzzing test."""
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.engine_common.current_timestamp',
        'clusterfuzz._internal.bot.tasks.fuzz_task.GcsCorpus.sync_from_gcs',
        'clusterfuzz._internal.bot.tasks.fuzz_task.GcsCorpus.upload_files',
        'clusterfuzz._internal.build_management.revisions.get_component_list',
        'clusterfuzz._internal.bot.testcase_manager.upload_log',
        'clusterfuzz._internal.bot.testcase_manager.upload_testcase',
        'clusterfuzz._internal.metrics.fuzzer_stats.upload_stats',
    ])
    test_utils.set_up_pyfakefs(self)

    os.environ['JOB_NAME'] = 'libfuzzer_asan_test'
    os.environ['FUZZ_INPUTS'] = '/fuzz-inputs'
    os.environ['FUZZ_INPUTS_DISK'] = '/fuzz-inputs-disk'
    os.environ['BUILD_DIR'] = '/build_dir'
    os.environ['MAX_TESTCASES'] = '2'
    os.environ['AUTOMATIC_LABELS'] = 'auto_label,auto_label1'
    os.environ['AUTOMATIC_COMPONENTS'] = 'auto_component,auto_component1'

    self.fs.create_file('/build_dir/test_target')
    self.fs.create_file(
        '/build_dir/test_target.labels', contents='label1\nlabel2')
    self.fs.create_file(
        '/build_dir/test_target.owners', contents='owner1@email.com')
    self.fs.create_file(
        '/build_dir/test_target.components', contents='component1\ncomponent2')
    self.fs.create_file('/input')

    self.mock.sync_from_gcs.return_value = True
    self.mock.upload_files.return_value = True
    self.mock.get_component_list.return_value = [{
        'component': 'component',
        'link_text': 'rev',
    }]
    self.mock.current_timestamp.return_value = 0.0

  def test_basic(self):
    """Test basic fuzzing session."""
    session = fuzz_task.FuzzingSession('libFuzzer', 'libfuzzer_asan_test', 60)
    session.testcase_directory = os.environ['FUZZ_INPUTS']
    session.data_directory = '/data_dir'

    os.environ['FUZZ_TARGET'] = 'test_target'
    os.environ['APP_REVISION'] = '1'
    os.environ['FUZZ_TEST_TIMEOUT'] = '2000'
    os.environ['BOT_NAME'] = 'hostname.company.com'

    expected_crashes = [engine.Crash('/input', 'stack', ['args'], 1.0)]

    engine_impl = mock.Mock()
    engine_impl.name = 'libFuzzer'
    engine_impl.prepare.return_value = engine.FuzzOptions(
        '/corpus', ['arg'], {
            'strategy_1': 1,
            'strategy_2': 50,
        })
    engine_impl.fuzz.side_effect = lambda *_: engine.FuzzResult(
        'logs', ['cmd'], expected_crashes, {'stat': 1}, 42.0)
    engine_impl.fuzz_additional_processing_timeout.return_value = 1337

    crashes, fuzzer_metadata = session.do_engine_fuzzing(engine_impl)

    engine_impl.fuzz.assert_called_with('/build_dir/test_target',
                                        engine_impl.prepare.return_value,
                                        '/fuzz-inputs', 663)
    self.assertDictEqual({
        'fuzzer_binary_name':
            'test_target',
        'issue_components':
            'component1,component2,auto_component,auto_component1',
        'issue_labels':
            'label1,label2,auto_label,auto_label1',
        'issue_owners':
            'owner1@email.com',
    }, fuzzer_metadata)

    log_time = datetime.datetime(1970, 1, 1, 0, 0)
    log_call = mock.call(
        b'Component revisions (build r1):\n'
        b'component: rev\n\nBot name: hostname.company.com\n'
        b'Return code: 1\n\n'
        b'Command: cmd\nTime ran: 42.0\n\n'
        b'logs\n'
        b'cf::fuzzing_strategies: strategy_1:1,strategy_2:50', log_time)
    self.mock.upload_log.assert_has_calls([log_call, log_call])
    self.mock.upload_testcase.assert_has_calls([
        mock.call('/input', log_time),
        mock.call('/input', log_time),
    ])

    self.assertEqual(2, len(crashes))
    for i in range(2):
      self.assertEqual('/input', crashes[i].file_path)
      self.assertEqual(1, crashes[i].return_code)
      self.assertEqual('stack', crashes[i].unsymbolized_crash_stacktrace)
      self.assertEqual(1.0, crashes[i].crash_time)
      self.assertEqual('args', crashes[i].arguments)

    for i in range(2):
      upload_args = self.mock.upload_stats.call_args_list[i][0][0]
      testcase_run = upload_args[0]
      self.assertDictEqual({
          'build_revision': 1,
          'command': ['cmd'],
          'fuzzer': u'libFuzzer_test_target',
          'job': 'libfuzzer_asan_test',
          'kind': 'TestcaseRun',
          'stat': 1,
          'strategy_strategy_1': 1,
          'strategy_strategy_2': 50,
          'timestamp': 0.0,
      }, testcase_run.data)


class UntrustedRunEngineFuzzerTest(
    untrusted_runner_helpers.UntrustedRunnerIntegrationTest):
  """Engine fuzzing tests for untrusted."""

  def setUp(self):
    """Set up."""
    super().setUp()
    environment.set_value('JOB_NAME', 'libfuzzer_asan_job')

    job = data_types.Job(
        name='libfuzzer_asan_job',
        environment_string=(
            'RELEASE_BUILD_BUCKET_PATH = '
            'gs://clusterfuzz-test-data/test_libfuzzer_builds/'
            'test-libfuzzer-build-([0-9]+).zip\n'
            'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
            'clusterfuzz-test-data/test_libfuzzer_builds/'
            'test-libfuzzer-build-%s.srcmap.json\n'))
    job.put()

    self.temp_dir = tempfile.mkdtemp(dir=environment.get_value('FUZZ_INPUTS'))
    environment.set_value('USE_MINIJAIL', False)

  def tearDown(self):
    super().tearDown()
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_run_engine_fuzzer(self):
    """Test running engine fuzzer."""
    self._setup_env(job_type='libfuzzer_asan_job')
    environment.set_value('FUZZ_TEST_TIMEOUT', 3600)
    environment.set_value('STRATEGY_SELECTION_METHOD', 'multi_armed_bandit')
    environment.set_value(
        'STRATEGY_SELECTION_DISTRIBUTION',
        '[{"strategy_name": "value_profile", '
        '"probability": 1.0, "engine": "libFuzzer"}]')

    build_manager.setup_build()
    corpus_directory = os.path.join(self.temp_dir, 'corpus')
    testcase_directory = os.path.join(self.temp_dir, 'artifacts')
    os.makedirs(file_host.rebase_to_worker_root(corpus_directory))
    os.makedirs(file_host.rebase_to_worker_root(testcase_directory))

    result, fuzzer_metadata, strategies = fuzz_task.run_engine_fuzzer(
        libfuzzer_engine.LibFuzzerEngine(), 'test_fuzzer', corpus_directory,
        testcase_directory)
    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000',
        result.logs)
    self.assertEqual(1, len(result.crashes))
    self.assertTrue(result.crashes[0].input_path.startswith(
        os.environ['ROOT_DIR']))
    self.assertTrue(os.path.exists(result.crashes[0].input_path))
    self.assertIsInstance(
        result.stats.get('number_of_executed_units'), six.integer_types)
    self.assertIsInstance(result.stats.get('oom_count'), six.integer_types)
    self.assertIsInstance(
        result.stats.get('strategy_selection_method'), six.string_types)

    self.assertDictEqual({'fuzzer_binary_name': 'test_fuzzer'}, fuzzer_metadata)
    self.assertDictEqual({'value_profile': 1}, strategies)


class AddIssueMetadataFromEnvironmentTest(unittest.TestCase):
  """Tests for _add_issue_metadata_from_environment."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_add_no_existing(self):
    """Test adding issue metadata when there are none existing."""
    os.environ['AUTOMATIC_LABELS'] = 'auto_label'
    os.environ['AUTOMATIC_LABELS_1'] = 'auto_label1'
    os.environ['AUTOMATIC_COMPONENTS'] = 'auto_component'
    os.environ['AUTOMATIC_COMPONENTS_1'] = 'auto_component1'

    metadata = {}
    fuzz_task._add_issue_metadata_from_environment(metadata)
    self.assertDictEqual({
        'issue_components': 'auto_component,auto_component1',
        'issue_labels': 'auto_label,auto_label1',
    }, metadata)

  def test_add_append(self):
    """Test adding issue metadata when there are already existing metadata."""
    os.environ['AUTOMATIC_LABELS'] = 'auto_label'
    os.environ['AUTOMATIC_LABELS_1'] = 'auto_label1'
    os.environ['AUTOMATIC_COMPONENTS'] = 'auto_component'
    os.environ['AUTOMATIC_COMPONENTS_1'] = 'auto_component1'

    metadata = {
        'issue_components': 'existing_component',
        'issue_labels': 'existing_label'
    }
    fuzz_task._add_issue_metadata_from_environment(metadata)
    self.assertDictEqual({
        'issue_components':
            'existing_component,auto_component,auto_component1',
        'issue_labels':
            'existing_label,auto_label,auto_label1',
    }, metadata)

  def test_add_numeric(self):
    """Tests adding a numeric label."""
    os.environ['AUTOMATIC_LABELS'] = '123,456'

    metadata = {}
    fuzz_task._add_issue_metadata_from_environment(metadata)
    self.assertDictEqual({
        'issue_labels': '123,456',
    }, metadata)

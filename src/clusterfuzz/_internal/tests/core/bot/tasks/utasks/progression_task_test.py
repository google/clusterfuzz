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
"""Tests for regression_task."""

import json
import os
import unittest

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.bot.tasks.utasks import progression_task
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class WriteToBigqueryTest(unittest.TestCase):
  """Test _write_to_big_query."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.big_query.write_range',
    ])

    self.testcase = data_types.Testcase(
        crash_type='type',
        crash_state='state',
        security_flag=True,
        fuzzer_name='libfuzzer',
        overridden_fuzzer_name='libfuzzer_pdf',
        job_type='some_job')

  def test_write(self):
    """Tests write."""
    progression_task._write_to_bigquery(self.testcase, 456, 789)  # pylint: disable=protected-access
    self.mock.write_range.assert_called_once_with(
        table_id='fixeds',
        testcase=self.testcase,
        range_name='fixed',
        start=456,
        end=789)


class TestcaseReproducesInRevisionTest(unittest.TestCase):
  """Test _testcase_reproduces_in_revision."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.setup_build',
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
        'clusterfuzz._internal.bot.testcase_manager.update_build_metadata',
        'clusterfuzz._internal.bot.testcase_manager.check_for_bad_build',
        'clusterfuzz._internal.build_management.build_manager.check_app_path'
    ])
    helpers.patch_environ(self)
    os.environ['APP_NAME'] = 'app_name'

  def test_error_on_failed_setup(self):
    """Ensure that we throw an exception if we fail to set up a build."""
    self.mock.check_app_path.return_value = False
    # No need to implement a fake setup_regular_build. Since it's doing nothing,
    # we won't have the build directory properly set.
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        None, '/tmp/blah', 'job_type', 1)
    self.assertIsNone(result)
    self.assertIs(worker_output.error,
                  uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP_ERROR,
                  "build setup is expected to fail")

  def test_bad_build_error(self):
    """Tests _testcase_reproduces_in_revision behaviour on bad builds."""
    self.mock.check_app_path.return_value = True
    self.mock.check_for_bad_build.return_value = True, False, None
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        None, '/tmp/blah', 'job_type', 1)
    self.assertIsNone(result)
    self.assertEqual(worker_output.error,
                     uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD)
    self.assertEqual(worker_output.error_message, 'Bad build at r1. Skipping')

  def test_no_crash(self):
    """Tests _testcase_reproduces_in_revision behaviour with no crash or error."""
    self.mock.check_app_path.return_value = True
    self.mock.check_for_bad_build.return_value = False, False, None
    testcase = data_types.Testcase()
    testcase = uworker_io.UworkerEntityWrapper(testcase)
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        testcase, '/tmp/blah', 'job_type', 1)
    self.assertIsNone(worker_output)
    self.assertIsNotNone(result)


@test_utils.with_cloud_emulators('datastore')
class UtaskPreprocessTest(unittest.TestCase):
  """Tests progression_task.utask_preprocess."""

  def setUp(self):
    helpers.patch_environ(self)
    os.environ['JOB_NAME'] = 'progression'
    # Add a bad build.
    data_handler.add_build_metadata(
        job_type='progression',
        is_bad_build=True,
        crash_revision=9999,
        console_output='console')
    helpers.patch(
        self,
        ['clusterfuzz._internal.bot.tasks.setup.preprocess_setup_testcase'])
    self.mock.preprocess_setup_testcase.return_value = uworker_io.SetupInput()

  def test_inexistant_testcase(self):
    """Verifies that an InvalidTestcaseError is raised when we try to
    fetch an inexistant testcase."""
    testcase_id = 11
    with self.assertRaises(errors.InvalidTestcaseError):
      progression_task.utask_preprocess(testcase_id, None, None)

  def test_on_fixed_testcase(self):
    """Ensure that nothing is done for already fixed testcases."""
    testcase = test_utils.create_generic_testcase()
    testcase.fixed = 'Yes'
    testcase.put()
    result = progression_task.utask_preprocess(testcase.key.id(), None, None)
    self.assertIsNone(result)

  def test_preprocess_uworker_output(self):
    """Tests the preprocess behaviour for non custom binaries."""
    testcase = test_utils.create_generic_testcase()
    result = progression_task.utask_preprocess(
        str(testcase.key.id()), 'job_type', None)
    self.assertFalse(result.progression_task_input.custom_binary)
    self.assertEqual('job_type', result.job_type)
    returned_testcase = result.testcase
    self.assertTrue(returned_testcase.get_metadata('progression_pending'))
    bad_builds = result.progression_task_input.bad_builds
    self.assertEqual(len(bad_builds), 1)
    self.assertTrue(bad_builds[0].bad_build)
    self.assertEqual(bad_builds[0].revision, 9999)

  def test_preprocess_uworker_output_custom_binary(self):
    """Tests the preprocess behaviour for custom binaries."""
    helpers.patch_environ(self)
    os.environ['CUSTOM_BINARY'] = 'some_value'
    testcase = test_utils.create_generic_testcase()
    result = progression_task.utask_preprocess(
        str(testcase.key.id()), 'job_type', None)
    self.assertTrue(result.progression_task_input.custom_binary)
    self.assertEqual('job_type', result.job_type)
    returned_testcase = result.testcase
    self.assertTrue(returned_testcase.get_metadata('progression_pending'))
    bad_builds = result.progression_task_input.bad_builds
    self.assertEqual(len(bad_builds), 1)
    self.assertTrue(bad_builds[0].bad_build)
    self.assertEqual(bad_builds[0].revision, 9999)


@test_utils.with_cloud_emulators('datastore')
class UTaskPostprocessTest(unittest.TestCase):
  """Tests for progression_task.utask_postprocess."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.uworker_handle_errors.handle',
        'clusterfuzz._internal.bot.tasks.utasks.progression_task.crash_on_latest',
        'clusterfuzz._internal.datastore.data_handler.is_first_retry_for_task',
        'clusterfuzz._internal.base.bisection.request_bisection'
    ])

  def _get_generic_input(self):
    testcase = data_types.Testcase()
    uworker_input = uworker_io.UworkerInput(
        job_type='job_type', testcase_id='testcase_id', testcase=testcase)
    uworker_input = uworker_io.serialize_uworker_input(uworker_input)
    uworker_input = uworker_io.deserialize_uworker_input(uworker_input)
    return uworker_input

  def _create_output(self, uworker_input=None, **kwargs):
    uworker_output = uworker_io.UworkerOutput(**kwargs)
    uworker_output = uworker_io.serialize_uworker_output(uworker_output)
    uworker_output = uworker_io.deserialize_uworker_output(uworker_output)
    if uworker_input:
      uworker_output.uworker_input = uworker_input
    return uworker_output

  def test_error_handling_called_on_error(self):
    """Checks that an output with an error is handled properly."""
    testcase = test_utils.create_generic_testcase()
    uworker_input = uworker_io.UworkerInput(testcase_id=str(testcase.key.id()))
    uworker_output = self._create_output(
        uworker_input=uworker_input, error=uworker_msg_pb2.ErrorType.UNHANDLED)
    progression_task.utask_postprocess(uworker_output)
    self.assertTrue(self.mock.handle.called)

  def test_handle_crash_on_latest_revision(self):
    """Tests utask_postprocess behaviour when there is a crash on latest revision."""
    testcase = test_utils.create_generic_testcase()
    uworker_input = uworker_io.UworkerInput(testcase_id=str(testcase.key.id()))
    progression_task_output = uworker_io.ProgressionTaskOutput(
        crash_on_latest=True)
    uworker_output = self._create_output(
        uworker_input=uworker_input,
        progression_task_output=progression_task_output)
    progression_task.utask_postprocess(uworker_output)
    self.assertFalse(self.mock.handle.called)
    self.assertTrue(self.mock.crash_on_latest.called)

  def test_handle_custom_binary_postprocess(self):
    """Tests utask_postprocess behaviour for custom binaries in the absence of errors."""
    progression_task_input = uworker_io.ProgressionTaskInput(custom_binary=True)
    testcase = test_utils.create_generic_testcase()
    uworker_input = uworker_io.UworkerInput(
        testcase_id=str(testcase.key.id()),
        progression_task_input=progression_task_input)
    self.assertEqual(testcase.fixed, '')
    self.assertTrue(testcase.open)
    # TODO(alhijazi): Should we wrap the testcase entities passed to utask_main
    # before returning them through the uworker_output?
    testcase = uworker_io.UworkerEntityWrapper(testcase)
    uworker_output = self._create_output(
        uworker_input=uworker_input, testcase=testcase)
    self.assertTrue(testcase.open)
    self.mock.is_first_retry_for_task.return_value = False
    progression_task.utask_postprocess(uworker_output)
    self.assertFalse(self.mock.handle.called)
    self.assertFalse(self.mock.crash_on_latest.called)
    self.assertTrue(self.mock.is_first_retry_for_task.called)
    updated_testcase = data_handler.get_testcase_by_id(testcase.key.id())
    self.assertEqual(updated_testcase.fixed, 'Yes')
    self.assertFalse(updated_testcase.open)

  def test_handle_non_custom_binary_postprocess(self):
    """Tests utask_postprocess behaviour for non_custom binaries in the absence of errors."""
    testcase = test_utils.create_generic_testcase()
    uworker_input = uworker_io.UworkerInput(testcase_id=str(testcase.key.id()))
    progression_task_output = uworker_io.ProgressionTaskOutput()
    uworker_output = self._create_output(
        uworker_input=uworker_input,
        progression_task_output=progression_task_output)

    progression_task.utask_postprocess(uworker_output)
    self.assertFalse(self.mock.handle.called)
    self.assertFalse(self.mock.crash_on_latest.called)
    self.assertFalse(self.mock.is_first_retry_for_task.called)
    self.assertTrue(self.mock.request_bisection.called)


@test_utils.with_cloud_emulators('datastore')
class CheckFixedForCustomBinaryTest(unittest.TestCase):
  """Tests for progression_task._check_fixed_for_custom_binary behaviour."""

  def setUp(self):
    helpers.patch_environ(self, None)
    os.environ.clear()
    os.environ['CUSTOM_BINARY'] = 'some_value'
    os.environ['APP_REVISION'] = '1234'
    helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.setup_build',
        'clusterfuzz._internal.build_management.build_manager.check_app_path',
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
        'clusterfuzz._internal.crash_analysis.crash_result.CrashResult.get_stacktrace',
        'clusterfuzz._internal.crash_analysis.crash_result.CrashResult.get_symbolized_data',
        'clusterfuzz._internal.crash_analysis.crash_result.CrashResult.is_crash',
        'clusterfuzz._internal.datastore.data_handler.filter_stacktrace',
    ])
    self.maxDiff = None

  def test_build_setup_error(self):
    """Tests _check_fixed_for_custom_binary behaviour on build setup errors."""
    self.mock.check_app_path.return_value = None
    testcase_file_path = '/a/b/c'
    testcase = test_utils.create_generic_testcase()
    testcase = uworker_io.UworkerEntityWrapper(testcase)
    result = progression_task._check_fixed_for_custom_binary(  # pylint: disable=protected-access
        testcase, testcase_file_path)
    self.assertEqual(result.error_message,
                     'Build setup failed for custom binary')
    self.assertEqual(result.error,
                     uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP_ERROR)

  def test_crash_on_latest(self):
    """Tests _check_fixed_for_custom_binary behaviour when the testcase crashes on the latest custom binary."""
    self.mock.check_app_path.return_value = True
    from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
    stacktrace = (
        '==14970==ERROR: AddressSanitizer: heap-buffer-overflow on address '
        '0x61b00001f7d0 at pc 0x00000064801b bp 0x7ffce478dbd0 sp '
        '0x7ffce478dbc8 READ of size 4 at 0x61b00001f7d0 thread T0\n'
        '#0 0x64801a in frame0() src/test.cpp:1819:15\n'
        '#1 0x647ac5 in frame1() src/test.cpp:1954:25\n'
        '#2 0xb1dee7 in frame2() src/test.cpp:160:9\n'
        '#3 0xb1ddd8 in frame3() src/test.cpp:148:34\n')
    crash_result = CrashResult(1, 1.1, stacktrace)
    self.mock.test_for_crash_with_retries.return_value = crash_result
    self.mock.is_crash.return_value = True
    self.mock.get_stacktrace.return_value = None  # This return value does not matter
    self.mock.get_symbolized_data.return_value = None
    self.mock.filter_stacktrace.return_value = stacktrace
    testcase_file_path = '/a/b/c'
    testcase = test_utils.create_generic_testcase()
    testcase = uworker_io.UworkerEntityWrapper(testcase)

    result = progression_task._check_fixed_for_custom_binary(  # pylint: disable=protected-access
        testcase, testcase_file_path)
    self.assertTrue(result.progression_task_output.crash_on_latest)
    self.assertEqual(result.progression_task_output.crash_revision, 1234)
    self.assertEqual(result.progression_task_output.crash_on_latest_message,
                     'Still crashes on latest custom build.')

    self.assertEqual(
        result.progression_task_output.last_tested_crash_stacktrace, stacktrace)

  def test_no_crash(self):
    """Tests _check_fixed_for_custom_binary behaviour when testcase does not crash."""
    self.mock.check_app_path.return_value = True
    from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
    crash_result = CrashResult(0, 0, '')
    self.mock.test_for_crash_with_retries.return_value = crash_result
    self.mock.filter_stacktrace.return_value = ''
    self.mock.is_crash.return_value = False
    testcase_file_path = '/a/b/c'
    testcase = test_utils.create_generic_testcase()
    testcase = uworker_io.UworkerEntityWrapper(testcase)

    result = progression_task._check_fixed_for_custom_binary(  # pylint: disable=protected-access
        testcase, testcase_file_path)
    self.assertFalse(result.progression_task_output.crash_on_latest)
    self.assertEqual(result.progression_task_output.crash_revision, 1234)
    self.assertEqual(result.progression_task_output.crash_on_latest_message, '')


@test_utils.with_cloud_emulators('datastore')
class UpdateIssueMetadataTest(unittest.TestCase):
  """Test _update_issue_metadata."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.engine_common.find_fuzzer_path',
        'clusterfuzz._internal.bot.fuzzers.engine_common.get_all_issue_metadata',
    ])

    data_types.FuzzTarget(engine='libFuzzer', binary='fuzzer').put()
    self.mock.get_all_issue_metadata.return_value = {
        'issue_labels': 'label1',
        'issue_components': 'component1',
    }

    self.testcase = data_types.Testcase(
        overridden_fuzzer_name='libFuzzer_fuzzer')
    self.testcase.put()

  def test_update_issue_metadata_non_existent(self):
    """Test update issue metadata a testcase with no metadata."""
    progression_task._update_issue_metadata(self.testcase)  # pylint: disable=protected-access

    testcase = self.testcase.key.get()
    self.assertDictEqual({
        'issue_labels': 'label1',
        'issue_components': 'component1',
    }, json.loads(testcase.additional_metadata))

  def test_update_issue_metadata_replace(self):
    """Test update issue metadata a testcase with different metadata."""
    self.testcase.additional_metadata = json.dumps({
        'issue_labels': 'label1',
        'issue_components': 'component2',
    })
    progression_task._update_issue_metadata(self.testcase)  # pylint: disable=protected-access

    testcase = self.testcase.key.get()
    self.assertDictEqual({
        'issue_labels': 'label1',
        'issue_components': 'component1',
    }, json.loads(testcase.additional_metadata))

  def test_update_issue_metadata_same(self):
    """Test update issue metadata a testcase with the same metadata."""
    self.testcase.additional_metadata = json.dumps({
        'issue_labels': 'label1',
        'issue_components': 'component1',
    })
    self.testcase.put()

    self.testcase.crash_type = 'test'  # Should not be written.
    progression_task._update_issue_metadata(self.testcase)  # pylint: disable=protected-access

    testcase = self.testcase.key.get()
    self.assertDictEqual({
        'issue_labels': 'label1',
        'issue_components': 'component1',
    }, json.loads(testcase.additional_metadata))
    self.assertIsNone(testcase.crash_type)


@test_utils.with_cloud_emulators('datastore')
class StoreTestcaseForRegressionTesting(fake_filesystem_unittest.TestCase):
  """Test _store_testcase_for_regression_testing."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.copy_file_to',
    ])

    os.environ['CORPUS_BUCKET'] = 'corpus'

    fuzz_target = data_types.FuzzTarget(id='libFuzzer_test_project_test_fuzzer')
    fuzz_target.binary = 'test_fuzzer'
    fuzz_target.project = 'test_project'
    fuzz_target.engine = 'libFuzzer'
    fuzz_target.put()

    self.testcase = data_types.Testcase()
    self.testcase.fuzzer_name = 'libFuzzer'
    self.testcase.overridden_fuzzer_name = 'libFuzzer_test_project_test_fuzzer'
    self.testcase.job_type = 'job'
    self.testcase.bug_information = '123'
    self.testcase.open = False
    self.testcase.put()

    self.testcase_file_path = '/testcase'
    self.fs.create_file(self.testcase_file_path, contents='A')

  def test_open_testcase(self):
    """Test that an open testcase is not stored for regression testing."""
    self.testcase.open = True
    self.testcase.put()

    progression_task._store_testcase_for_regression_testing(  # pylint: disable=protected-access
        self.testcase, self.testcase_file_path)
    self.assertEqual(0, self.mock.copy_file_to.call_count)

  def test_testcase_with_no_issue(self):
    """Test that a testcase with no associated issue is not stored for
    regression testing."""
    self.testcase.bug_information = ''
    self.testcase.put()

    progression_task._store_testcase_for_regression_testing(  # pylint: disable=protected-access
        self.testcase, self.testcase_file_path)
    self.assertEqual(0, self.mock.copy_file_to.call_count)

  def test_testcase_with_no_fuzz_target(self):
    """Test that a testcase with no associated fuzz target is not stored for
    regression testing."""
    self.testcase.overridden_fuzzer_name = 'libFuzzer_not_exist'
    self.testcase.put()

    progression_task._store_testcase_for_regression_testing(  # pylint: disable=protected-access
        self.testcase, self.testcase_file_path)
    self.assertEqual(0, self.mock.copy_file_to.call_count)

  def test_testcase_stored(self):
    """Test that a testcase is stored for regression testing."""
    progression_task._store_testcase_for_regression_testing(  # pylint: disable=protected-access
        self.testcase, self.testcase_file_path)
    self.mock.copy_file_to.assert_called_with(
        '/testcase',
        'gs://corpus/libFuzzer/test_project_test_fuzzer_regressions/'
        '6dcd4ce23d88e2ee9568ba546c007c63d9131c1b')

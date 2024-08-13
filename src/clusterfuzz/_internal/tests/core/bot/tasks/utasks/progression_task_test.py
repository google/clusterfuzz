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
from unittest import mock

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
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        None, '/tmp/blah', 'job_type', 1, None, progression_task_output)
    self.assertIsNone(result)
    self.assertIs(worker_output.error_type,
                  uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP_ERROR,
                  "build setup is expected to fail")

  def test_bad_build_error(self):
    """Tests _testcase_reproduces_in_revision behaviour on bad builds."""
    self.mock.check_app_path.return_value = True
    build_data = uworker_msg_pb2.BuildData(
        revision=1,
        is_bad_build=True,
        should_ignore_crash_result=False,
        build_run_console_output='')
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
    self.mock.check_for_bad_build.return_value = build_data
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        None, '/tmp/blah', 'job_type', 1, None, progression_task_output)
    self.assertIsNone(result)
    self.assertEqual(worker_output.error_type,
                     uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD)
    self.assertEqual(worker_output.error_message, 'Bad build at r1. Skipping')
    self.assertEqual(len(progression_task_output.build_data_list), 1)
    self.assertEqual(progression_task_output.build_data_list[0], build_data)

  def test_no_crash(self):
    """Tests _testcase_reproduces_in_revision behaviour with no crash or error."""
    self.mock.check_app_path.return_value = True
    build_data = uworker_msg_pb2.BuildData(
        revision=1,
        is_bad_build=False,
        should_ignore_crash_result=False,
        build_run_console_output='')
    self.mock.check_for_bad_build.return_value = build_data
    testcase = data_types.Testcase()
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        testcase, '/tmp/blah', 'job_type', 1, None, progression_task_output)
    self.assertIsNone(worker_output)
    self.assertIsNotNone(result)
    self.assertEqual(len(progression_task_output.build_data_list), 1)
    self.assertEqual(progression_task_output.build_data_list[0], build_data)


@test_utils.with_cloud_emulators('datastore')
class UtaskPreprocessTest(unittest.TestCase):
  """Tests progression_task.utask_preprocess."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.setup.preprocess_setup_testcase',
        'clusterfuzz._internal.google_cloud_utils.blobs.get_blob_signed_upload_url'
    ])
    setup_input = uworker_msg_pb2.SetupInput(fuzzer_name='fuzzer_name')
    self.mock.preprocess_setup_testcase.return_value = setup_input
    self.mock.get_blob_signed_upload_url.return_value = (
        'blob_name', 'https://blob_upload_url')
    os.environ['JOB_NAME'] = 'progression'
    # Add a bad build.
    data_handler.add_build_metadata(
        job_type='progression',
        is_bad_build=True,
        crash_revision=8888,
        console_output='console')
    # Add a bad build.
    data_handler.add_build_metadata(
        job_type='progression',
        is_bad_build=True,
        crash_revision=9999,
        console_output='console')

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
    returned_testcase = uworker_io.entity_from_protobuf(result.testcase,
                                                        data_types.Testcase)
    self.assertTrue(returned_testcase.get_metadata('progression_pending'))
    self.assertEqual(result.progression_task_input.bad_revisions, [8888, 9999])
    self.assertEqual(result.progression_task_input.blob_name, 'blob_name')
    self.assertEqual(result.progression_task_input.stacktrace_upload_url,
                     'https://blob_upload_url')
    self.assertEqual('fuzzer_name', result.setup_input.fuzzer_name)

  def test_preprocess_uworker_output_custom_binary(self):
    """Tests the preprocess behaviour for custom binaries."""
    helpers.patch_environ(self)
    os.environ['CUSTOM_BINARY'] = 'some_value'
    testcase = test_utils.create_generic_testcase()
    result = progression_task.utask_preprocess(
        str(testcase.key.id()), 'job_type', None)
    self.assertTrue(result.progression_task_input.custom_binary)
    self.assertEqual('job_type', result.job_type)
    returned_testcase = uworker_io.entity_from_protobuf(result.testcase,
                                                        data_types.Testcase)
    self.assertTrue(returned_testcase.get_metadata('progression_pending'))
    self.assertEqual(result.progression_task_input.bad_revisions, [8888, 9999])
    self.assertEqual(result.progression_task_input.blob_name, 'blob_name')
    self.assertEqual(result.progression_task_input.stacktrace_upload_url,
                     'https://blob_upload_url')
    self.assertEqual('fuzzer_name', result.setup_input.fuzzer_name)


@test_utils.with_cloud_emulators('datastore')
class UTaskPostprocessTest(unittest.TestCase):
  """Tests for progression_task.utask_postprocess."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.progression_task._ERROR_HANDLER.handle',
        'clusterfuzz._internal.bot.tasks.utasks.progression_task.crash_on_latest',
        'clusterfuzz._internal.datastore.data_handler.is_first_attempt_for_task',
        'clusterfuzz._internal.base.bisection.request_bisection',
        'clusterfuzz._internal.google_cloud_utils.blobs.delete_blob'
    ])
    self.testcase = test_utils.create_generic_testcase()
    self.progression_task_input = uworker_msg_pb2.ProgressionTaskInput(
        blob_name='blob_name',
        stacktrace_upload_url='https://signed_upload_url')
    self.uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(self.testcase.key.id()),
        progression_task_input=self.progression_task_input)

  def test_error_handling_called_on_error(self):
    """Checks that an output with an error is handled properly."""
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        error_type=uworker_msg_pb2.ErrorType.UNHANDLED)
    progression_task.utask_postprocess(uworker_output)
    self.mock.delete_blob.assert_called_with('blob_name')
    self.assertTrue(self.mock.handle.called)

  def test_handle_crash_on_latest_revision(self):
    """Tests utask_postprocess behaviour when there is a crash on latest revision."""
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput(
        crash_on_latest=True)
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        progression_task_output=progression_task_output)
    progression_task.utask_postprocess(uworker_output)
    self.mock.delete_blob.assert_called_with('blob_name')
    self.assertFalse(self.mock.handle.called)
    self.assertTrue(self.mock.crash_on_latest.called)

  def test_handle_custom_binary_postprocess(self):
    """Tests utask_postprocess behaviour for custom binaries in the absence of errors."""
    self.uworker_input.progression_task_input.custom_binary = True
    self.assertEqual(self.testcase.fixed, '')
    self.assertTrue(self.testcase.open)
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput(
        crash_revision=1)
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        progression_task_output=progression_task_output)
    self.mock.is_first_attempt_for_task.return_value = False
    progression_task.utask_postprocess(uworker_output)
    self.mock.delete_blob.assert_called_with('blob_name')
    self.assertFalse(self.mock.handle.called)
    self.assertFalse(self.mock.crash_on_latest.called)
    self.assertTrue(self.mock.is_first_attempt_for_task.called)
    updated_testcase = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertEqual(updated_testcase.fixed, 'Yes')
    self.assertFalse(updated_testcase.open)

  def test_handle_non_custom_binary_postprocess(self):
    """Tests utask_postprocess behaviour for non_custom binaries in the absence of errors."""
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        progression_task_output=progression_task_output)

    progression_task.utask_postprocess(uworker_output)
    self.mock.delete_blob.assert_called_with('blob_name')
    self.assertFalse(self.mock.handle.called)
    self.assertFalse(self.mock.crash_on_latest.called)
    self.assertFalse(self.mock.is_first_attempt_for_task.called)
    self.assertTrue(self.mock.request_bisection.called)

  def test_handle_non_custom_binary_postprocess_with_stacktrace_uploaded_via_url(
      self):
    """Tests utask_postprocess behaviour for non_custom binaries in the absence of
    errors and when the stacktrace is uploaded to blob storage."""
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput(
        last_tested_crash_stacktrace='BLOB_KEY=blob_name')
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        progression_task_output=progression_task_output)

    progression_task.utask_postprocess(uworker_output)
    # We should not delete the blob if the filtered stack traced is stored in it.
    self.assertFalse(self.mock.delete_blob.called)
    self.assertFalse(self.mock.handle.called)
    self.assertFalse(self.mock.crash_on_latest.called)
    self.assertFalse(self.mock.is_first_attempt_for_task.called)
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
    uworker_input = uworker_msg_pb2.Input()
    result = progression_task._check_fixed_for_custom_binary(  # pylint: disable=protected-access
        testcase, testcase_file_path, uworker_input)
    self.assertEqual(result.error_message,
                     'Build setup failed for custom binary')
    self.assertEqual(result.error_type,
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

    uworker_input = uworker_msg_pb2.Input()
    result = progression_task._check_fixed_for_custom_binary(  # pylint: disable=protected-access
        testcase, testcase_file_path, uworker_input)
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

    uworker_input = uworker_msg_pb2.Input()
    result = progression_task._check_fixed_for_custom_binary(  # pylint: disable=protected-access
        testcase, testcase_file_path, uworker_input)
    self.assertFalse(result.progression_task_output.crash_on_latest)
    self.assertEqual(result.progression_task_output.crash_revision, 1234)
    self.assertEqual(result.progression_task_output.crash_on_latest_message, '')


@test_utils.with_cloud_emulators('datastore')
class UpdateIssueMetadataTest(unittest.TestCase):
  """Test _update_issue_metadata."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.engine_common.find_fuzzer_path',
    ])

    data_types.FuzzTarget(engine='libFuzzer', binary='fuzzer').put()
    self.issue_metadata = {
        'issue_labels': 'label1',
        'issue_components': 'component1',
        'issue_metadata': {
            "assignee": "dev1@example.com",
            "additional_fields": {
                'Acknowledgements': 'dev4@example4.com'
            }
        },
    }

    self.testcase = data_types.Testcase(
        overridden_fuzzer_name='libFuzzer_fuzzer')
    self.testcase.put()
    progression_task._update_issue_metadata(self.testcase, self.issue_metadata)  # pylint: disable=protected-access

  def test_update_issue_metadata_non_existent(self):
    """Test update issue metadata a testcase with no metadata."""
    testcase = self.testcase.key.get()
    self.assertDictEqual({
        'issue_labels':
            'label1',
        'issue_components':
            'component1',
        'issue_metadata':
            json.dumps({
                "assignee": "dev1@example.com",
                "additional_fields": {
                    'Acknowledgements': 'dev4@example4.com'
                }
            }),
    }, json.loads(testcase.additional_metadata))

  def test_update_issue_metadata_replace(self):
    """Test update issue metadata a testcase with different metadata."""
    self.testcase.additional_metadata = json.dumps({
        'issue_labels':
            'label1',
        'issue_components':
            'component2',
        'issue_metadata':
            json.dumps({
                "assignee": "dev1@example.com",
                "additional_fields": {
                    'Acknowledgements': 'dev4@example4.com'
                }
            }),
    })

    testcase = self.testcase.key.get()
    self.assertDictEqual({
        'issue_labels':
            'label1',
        'issue_components':
            'component1',
        'issue_metadata':
            json.dumps({
                "assignee": "dev1@example.com",
                "additional_fields": {
                    'Acknowledgements': 'dev4@example4.com'
                }
            }),
    }, json.loads(testcase.additional_metadata))

  def test_update_issue_metadata_same(self):
    """Test update issue metadata a testcase with the same metadata."""
    self.testcase.additional_metadata = json.dumps({
        'issue_labels':
            'label1',
        'issue_components':
            'component1',
        'issue_metadata':
            json.dumps({
                "assignee": "dev1@example.com",
                "additional_fields": {
                    'Acknowledgements': 'dev4@example4.com'
                }
            }),
    })
    self.testcase.put()

    self.testcase.crash_type = 'test'  # Should not be written.

    testcase = self.testcase.key.get()
    self.assertDictEqual({
        'issue_labels':
            'label1',
        'issue_components':
            'component1',
        'issue_metadata':
            json.dumps({
                "assignee": "dev1@example.com",
                "additional_fields": {
                    'Acknowledgements': 'dev4@example4.com'
                }
            }),
    }, json.loads(testcase.additional_metadata))
    self.assertIsNone(testcase.crash_type)


@test_utils.with_cloud_emulators('datastore')
class StoreTestcaseForRegressionTesting(fake_filesystem_unittest.TestCase):
  """Test _store_testcase_for_regression_testing."""
  SIGNED_URL = 'https://signed'

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.upload_signed_url',
        'clusterfuzz._internal.google_cloud_utils.storage.get',
        'clusterfuzz._internal.google_cloud_utils.storage.list_blobs',
        'clusterfuzz._internal.google_cloud_utils.storage.get_arbitrary_signed_upload_urls',
        'clusterfuzz._internal.google_cloud_utils.storage.last_updated',
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
    self.mock.list_blobs.return_value = []
    self.mock.get_arbitrary_signed_upload_urls.return_value = (
        ['https://upload'] * 10000)
    self.mock.last_updated.return_value = None

  def test_open_testcase(self):
    """Test that an open testcase is not stored for regression testing."""
    self.testcase.open = True
    self.testcase.put()
    progression_task_input = uworker_msg_pb2.ProgressionTaskInput()
    progression_task._store_testcase_for_regression_testing(  # pylint: disable=protected-access
        self.testcase, self.testcase_file_path, progression_task_input)
    self.assertEqual(0, self.mock.upload_signed_url.call_count)

  def test_testcase_with_no_issue(self):
    """Test that a testcase with no associated issue is not stored for
    regression testing."""
    self.testcase.bug_information = ''
    self.testcase.put()
    progression_task_input = uworker_msg_pb2.ProgressionTaskInput()

    progression_task._store_testcase_for_regression_testing(  # pylint: disable=protected-access
        self.testcase, self.testcase_file_path, progression_task_input)
    self.assertEqual(0, self.mock.upload_signed_url.call_count)

  def test_testcase_with_no_fuzz_target(self):
    """Test that a testcase with no associated fuzz target is not stored for
    regression testing."""
    self.testcase.overridden_fuzzer_name = 'libFuzzer_not_exist'
    self.testcase.put()
    progression_task_input = uworker_msg_pb2.ProgressionTaskInput()
    progression_task._set_regression_testcase_upload_url(  # pylint: disable=protected-access
        progression_task_input, self.testcase)

    progression_task._store_testcase_for_regression_testing(  # pylint: disable=protected-access
        self.testcase, self.testcase_file_path, progression_task_input)
    self.assertEqual(0, self.mock.upload_signed_url.call_count)

  def test_testcase_stored(self):
    """Test that a testcase is stored for regression testing."""
    self.mock.get.return_value = False
    progression_task_input = uworker_msg_pb2.ProgressionTaskInput()
    progression_task._set_regression_testcase_upload_url(  # pylint: disable=protected-access
        progression_task_input, self.testcase)
    progression_task_input.regression_testcase_url = 'https://upload-regression'
    progression_task._store_testcase_for_regression_testing(  # pylint: disable=protected-access
        self.testcase, self.testcase_file_path, progression_task_input)
    self.mock.upload_signed_url.assert_called_with(
        b'A', progression_task_input.regression_testcase_url)

  def test_untrusted_testcase(self):
    """Tests that a user-uploaded testcase is not stored for regression
    testing."""
    self.mock.get.return_value = False
    progression_task_input = uworker_msg_pb2.ProgressionTaskInput()
    with mock.patch(
        'clusterfuzz._internal.datastore.data_handler.get_fuzz_target',
        return_value=mock.Mock()):
      progression_task._set_regression_testcase_upload_url(  # pylint: disable=protected-access
          progression_task_input, self.testcase)
    self.assertFalse(bool(progression_task_input.regression_testcase_url))

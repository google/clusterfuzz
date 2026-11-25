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

import datetime
import json
import os
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.bot.tasks.utasks import progression_task
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.crash_analysis import \
    crash_result as crash_result_lib
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import events
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
    ])
    helpers.patch_environ(self)
    os.environ['APP_NAME'] = 'app_name'
    os.environ['CONFIG_DIR_OVERRIDE'] = './configs/test'

  def test_error_on_failed_setup(self):
    """Ensure that we throw an exception if we fail to set up a build."""
    self.mock.setup_build.return_value = False
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
    from clusterfuzz._internal.crash_analysis.crash_result import \
        CrashResult  # pylint: disable=import-outside-toplevel
    build_data = uworker_msg_pb2.BuildData(
        revision=1,
        is_bad_build=False,
        should_ignore_crash_result=False,
        build_run_console_output='')
    self.mock.check_for_bad_build.return_value = build_data
    self.mock.test_for_crash_with_retries.return_value = CrashResult(0, 0, '')
    testcase = data_types.Testcase()
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        testcase, '/tmp/blah', 'job_type', 1, None, progression_task_output)
    self.assertIsNone(worker_output)
    self.assertIsNotNone(result)
    self.assertEqual(len(progression_task_output.build_data_list), 1)
    self.assertEqual(progression_task_output.build_data_list[0], build_data)

  def test_exit_127_missing_shared_library_treated_as_bad_build(self):
    """Ensures exit 126/127 or missing .so aborts as PROGRESSION_BAD_BUILD."""
    from clusterfuzz._internal.crash_analysis.crash_result import \
        CrashResult  # pylint: disable=import-outside-toplevel
    build_data = uworker_msg_pb2.BuildData(
        revision=42,
        is_bad_build=False,
        should_ignore_crash_result=False,
        build_run_console_output='')
    self.mock.check_for_bad_build.return_value = build_data
    self.mock.test_for_crash_with_retries.return_value = CrashResult(
        127, 0.1,
        '/out/fuzzer: error while loading shared libraries: libssl.so.1.1: '
        'cannot open shared object file: No such file or directory')
    testcase = data_types.Testcase()
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
    with mock.patch(
        'clusterfuzz._internal.metrics.logs.warning') as mock_warn, mock.patch(
            'clusterfuzz._internal.metrics.logs.error') as mock_err:
      result, worker_output = (
          progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
              testcase, '/tmp/blah', 'job_type', 42, None,
              progression_task_output))
    mock_warn.assert_called_once()
    mock_err.assert_not_called()
    self.assertIsNone(result)
    self.assertIsNotNone(worker_output)
    self.assertEqual(worker_output.error_type,
                     uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD)
    self.assertFalse(progression_task_output.build_data_list[0].is_bad_build)
    self.assertTrue(
        progression_task_output.build_data_list[0].should_ignore_crash_result)

  def test_glibc_symbol_mismatch_with_zero_return_code_treated_as_bad_build(
      self):
    """Ensures ABI errors abort even after reproduce_with_retries sets 0."""
    from clusterfuzz._internal.crash_analysis.crash_result import \
        CrashResult  # pylint: disable=import-outside-toplevel
    build_data = uworker_msg_pb2.BuildData(
        revision=43,
        is_bad_build=False,
        should_ignore_crash_result=False,
        build_run_console_output='')
    self.mock.check_for_bad_build.return_value = build_data
    self.mock.test_for_crash_with_retries.return_value = CrashResult(
        0,
        0,
        '/out/fuzzer: /lib/x86_64-linux-gnu/libc.so.6: '
        "version `GLIBC_2.38' not found (required by /out/fuzzer)",
        raw_return_code=1)
    testcase = data_types.Testcase()
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        testcase, '/tmp/blah', 'job_type', 43, None, progression_task_output)
    self.assertIsNone(result)
    self.assertEqual(worker_output.error_type,
                     uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD)
    self.assertIn('code=1', worker_output.error_message)

  def test_engine_fuzz_target_loader_error_does_not_mark_job_build_bad(self):
    """Ensures single-target .so errors do not poison job-wide BuildMetadata."""
    from clusterfuzz._internal.crash_analysis.crash_result import \
        CrashResult  # pylint: disable=import-outside-toplevel
    build_data = uworker_msg_pb2.BuildData(
        revision=44,
        is_bad_build=False,
        should_ignore_crash_result=False,
        build_run_console_output='')
    self.mock.check_for_bad_build.return_value = build_data
    self.mock.test_for_crash_with_retries.return_value = CrashResult(
        0,
        0,
        '/out/target_a: error while loading shared libraries: libfoo.so: '
        'cannot open shared object file: No such file or directory',
        raw_return_code=127)
    testcase = data_types.Testcase()
    fuzz_target = data_types.FuzzTarget(
        engine='libFuzzer', project='proj', binary='target_a')
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        testcase, '/tmp/blah', 'job_type', 44, fuzz_target,
        progression_task_output)
    self.assertIsNone(result)
    self.assertEqual(worker_output.error_type,
                     uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD)
    self.assertIn('code=127', worker_output.error_message)
    self.assertFalse(progression_task_output.build_data_list[0].is_bad_build)
    self.assertTrue(
        progression_task_output.build_data_list[0].should_ignore_crash_result)

  def test_non_glibc_version_and_undefined_symbol_treated_as_bad_build(self):
    """Ensures OPENSSL version tags and undefined symbols abort safely."""
    from clusterfuzz._internal.crash_analysis.crash_result import \
        CrashResult  # pylint: disable=import-outside-toplevel
    for raw_code, stderr_line in (
        (1, "/out/fuzzer: /lib/libcrypto.so.3: version `OPENSSL_3.2.0' "
         'not found (required by /out/fuzzer)'),
        (127,
         '/out/fuzzer: symbol lookup error: /out/fuzzer: undefined symbol: '
         'foo_v2'),
        (126, 'unshare: failed to execute /out/fuzzer: Permission denied'),
        (127, 'No output!'),
    ):
      build_data = uworker_msg_pb2.BuildData(
          revision=45, is_bad_build=False, should_ignore_crash_result=True)
      self.mock.check_for_bad_build.return_value = build_data
      self.mock.test_for_crash_with_retries.return_value = CrashResult(
          0, 0, stderr_line, raw_return_code=raw_code)
      progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
      result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
          data_types.Testcase(), '/tmp/blah', 'job_type', 45, None,
          progression_task_output)
      self.assertIsNone(result)
      self.assertEqual(worker_output.error_type,
                       uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD)

  def test_benign_not_found_and_gui_none_return_code_not_false_positive(self):
    """Ensures benign 'not found' logs, exit 0 runs, or None exit pass."""
    from clusterfuzz._internal.crash_analysis.crash_result import \
        CrashResult  # pylint: disable=import-outside-toplevel
    for crash_result in (
        CrashResult(
            0,
            0.1,
            "requested version '2.0' not found\n"
            'dlopen warning: cannot open shared object file',
            raw_return_code=1),
        CrashResult(
            0,
            0.1,
            '/out/helper: error while loading shared libraries: libopt.so: '
            'cannot open shared object file',
            raw_return_code=0),
        CrashResult(
            None, 0,
            '/out/helper: error while loading shared libraries: libopt.so: '
            'cannot open shared object file'),
    ):
      build_data = uworker_msg_pb2.BuildData(
          revision=46, is_bad_build=False, should_ignore_crash_result=True)
      self.mock.check_for_bad_build.return_value = build_data
      self.mock.test_for_crash_with_retries.return_value = crash_result
      progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
      result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
          data_types.Testcase(), '/tmp/blah', 'job_type', 46, None,
          progression_task_output)
      self.assertIsNone(worker_output)
      self.assertIs(result, crash_result)

  def test_reproducing_crash_with_optional_dlopen_log_not_bad_build(self):
    """Ensures reproducing crashes are preserved even with loader errors."""
    from clusterfuzz._internal.crash_analysis.crash_result import \
        CrashResult  # pylint: disable=import-outside-toplevel
    stacktrace = (
        '/out/helper: error while loading shared libraries: libopt.so: '
        'cannot open shared object file: No such file or directory\n'
        '==12==ERROR: AddressSanitizer: heap-buffer-overflow on address '
        '0x602000000014 at pc 0x55a1234 bp 0x7ffd00 sp 0x7ffd08\n'
        'READ of size 4 at 0x602000000014 thread T0\n'
        '    #0 0x55a1233 in parse_frame /src/parser.c:42:9\n'
        'SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:42:9\n')
    crash_result = CrashResult(1, 0.2, stacktrace)
    build_data = uworker_msg_pb2.BuildData(
        revision=47, is_bad_build=False, should_ignore_crash_result=False)
    self.mock.check_for_bad_build.return_value = build_data
    self.mock.test_for_crash_with_retries.return_value = crash_result
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput()
    result, worker_output = progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        data_types.Testcase(), '/tmp/blah', 'job_type', 47, None,
        progression_task_output)
    self.assertIsNone(worker_output)
    self.assertIs(result, crash_result)
    self.assertTrue(result.is_crash())


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
      progression_task.utask_preprocess(testcase_id, None, {})

  def test_on_fixed_testcase(self):
    """Ensure that nothing is done for already fixed testcases."""
    testcase = test_utils.create_generic_testcase()
    testcase.fixed = 'Yes'
    testcase.put()
    result = progression_task.utask_preprocess(testcase.key.id(), None, {})
    self.assertIsNone(result)

  def test_preprocess_uworker_output(self):
    """Tests the preprocess behaviour for non custom binaries."""
    testcase = test_utils.create_generic_testcase()
    result = progression_task.utask_preprocess(
        str(testcase.key.id()), 'job_type', {})
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
        str(testcase.key.id()), 'job_type', {})
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
        'clusterfuzz._internal.bot.tasks.utasks.progression_task._write_to_bigquery',
        'clusterfuzz._internal.datastore.data_handler.is_first_attempt_for_task',
        'clusterfuzz._internal.base.bisection.request_bisection',
        'clusterfuzz._internal.google_cloud_utils.blobs.delete_blob',
        'clusterfuzz._internal.metrics.events.emit',
        'clusterfuzz._internal.metrics.events._get_datetime_now',
    ])
    self.mock._get_datetime_now.return_value = datetime.datetime(2025, 1, 1)  # pylint: disable=protected-access
    self.testcase = test_utils.create_generic_testcase()
    self.progression_task_input = uworker_msg_pb2.ProgressionTaskInput(
        blob_name='blob_name',
        stacktrace_upload_url='https://signed_upload_url')
    self.uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(self.testcase.key.id()),
        progression_task_input=self.progression_task_input)

  def _error_handling_if_needed(self, output):
    """Workaround for un-mocking specific error handling when needed."""
    if output.error_type == uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_NOT_FOUND:
      return progression_task.handle_progression_build_not_found(output)
    if output.error_type == uworker_msg_pb2.ErrorType.PROGRESSION_BAD_STATE_MIN_MAX:
      return progression_task.handle_progression_bad_state_min_max(output)
    if output.error_type == uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD:
      return progression_task.handle_progression_bad_build(output)
    return None

  def test_handling_bad_build_keeps_testcase_open_and_clears_pending(self):
    """Tests PROGRESSION_BAD_BUILD keeps testcase open and clears pending."""
    self.mock.handle.side_effect = self._error_handling_if_needed
    self.testcase.set_metadata('progression_pending', True)
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        progression_task_output=uworker_msg_pb2.ProgressionTaskOutput(),
        error_message=(
            'Target execution failed with loader error (code=127) at r200. '
            'Skipping'),
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD)
    progression_task.utask_postprocess(uworker_output)
    updated_testcase = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertTrue(updated_testcase.open)
    self.assertEqual(updated_testcase.fixed, '')
    self.assertFalse(bool(updated_testcase.get_metadata('progression_pending')))
    self.mock.emit.assert_not_called()
    self.assertIn('Unable to recover from bad build: Target execution failed',
                  updated_testcase.comments)

  def test_error_handling_called_on_error(self):
    """Checks that an output with an error is handled properly."""
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        error_type=uworker_msg_pb2.ErrorType.UNHANDLED)
    progression_task.utask_postprocess(uworker_output)
    self.mock.delete_blob.assert_called_with('blob_name')
    self.assertTrue(self.mock.handle.called)

  def test_handling_build_not_found(self):
    """Tests that an output with a build not found error is handled properly."""
    self.mock.handle.side_effect = self._error_handling_if_needed
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_NOT_FOUND)
    progression_task.utask_postprocess(uworker_output)
    updated_testcase = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertEqual(updated_testcase.fixed, 'NA')
    self.assertFalse(updated_testcase.open)
    self.mock.emit.assert_called_once_with(
        events.TestcaseRejectionEvent(
            testcase=updated_testcase,
            rejection_reason=events.RejectionReason.PROGRESSION_BUILD_NOT_FOUND)
    )

  def test_handling_bad_state_min_max(self):
    """Tests handling an output with bad state for min-max revisions."""
    self.mock.handle.side_effect = self._error_handling_if_needed
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BAD_STATE_MIN_MAX)
    progression_task.utask_postprocess(uworker_output)
    updated_testcase = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertEqual(updated_testcase.fixed, 'NA')
    self.assertFalse(updated_testcase.open)
    self.mock.emit.assert_called_once_with(
        events.TestcaseRejectionEvent(
            testcase=updated_testcase,
            rejection_reason=events.RejectionReason.
            PROGRESSION_BAD_STATE_MIN_MAX))

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
    self.mock.emit.assert_called_once_with(
        events.TestcaseFixedEvent(
            testcase=updated_testcase, fixed_revision='custom_build:1'))

  def test_handle_non_custom_binary_postprocess(self):
    """Tests utask_postprocess behaviour for non_custom binaries in the absence of errors."""
    progression_task_output = uworker_msg_pb2.ProgressionTaskOutput(
        min_revision=1, max_revision=2)
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        progression_task_output=progression_task_output)

    progression_task.utask_postprocess(uworker_output)
    self.mock.delete_blob.assert_called_with('blob_name')
    self.assertFalse(self.mock.handle.called)
    self.assertFalse(self.mock.crash_on_latest.called)
    self.assertFalse(self.mock.is_first_attempt_for_task.called)
    self.assertTrue(self.mock.request_bisection.called)
    updated_testcase = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertEqual(updated_testcase.fixed, '1:2')
    self.assertFalse(updated_testcase.open)
    self.mock.emit.assert_called_once_with(
        events.TestcaseFixedEvent(
            testcase=updated_testcase, fixed_revision='1:2'))

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
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
        'clusterfuzz._internal.crash_analysis.crash_result.CrashResult.get_stacktrace',
        'clusterfuzz._internal.crash_analysis.crash_result.CrashResult.get_symbolized_data',
        'clusterfuzz._internal.crash_analysis.crash_result.CrashResult.is_crash',
        'clusterfuzz._internal.datastore.data_handler.filter_stacktrace',
    ])
    self.maxDiff = None

  def test_build_setup_error(self):
    """Tests _check_fixed_for_custom_binary behaviour on build setup errors."""
    self.mock.setup_build.return_value = False
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

  def test_loader_failure_returns_bad_build(self):
    """Tests _check_fixed_for_custom_binary aborts on loader failure."""
    from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
    crash_result = CrashResult(
        0,
        0,
        '/out/custom: error while loading shared libraries: libfoo.so: '
        'cannot open shared object file',
        raw_return_code=127)
    self.mock.test_for_crash_with_retries.return_value = crash_result
    self.mock.is_crash.return_value = False
    self.mock.get_stacktrace.return_value = ''
    testcase = test_utils.create_generic_testcase()
    with mock.patch(
        'clusterfuzz._internal.metrics.logs.warning') as mock_warn, mock.patch(
            'clusterfuzz._internal.metrics.logs.error') as mock_err:
      result = progression_task._check_fixed_for_custom_binary(  # pylint: disable=protected-access
          testcase, '/a/b/c', uworker_msg_pb2.Input())
    mock_warn.assert_called_once()
    mock_err.assert_not_called()
    self.assertEqual(result.error_type,
                     uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD)
    self.assertIn('code=127', result.error_message)


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
    }

    self.testcase = data_types.Testcase(
        overridden_fuzzer_name='libFuzzer_fuzzer')
    self.testcase.put()
    progression_task._update_issue_metadata(self.testcase, self.issue_metadata)  # pylint: disable=protected-access

  def test_update_issue_metadata_non_existent(self):
    """Test update issue metadata a testcase with no metadata."""
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

    testcase = self.testcase.key.get()
    self.assertDictEqual({
        'issue_labels': 'label1',
        'issue_components': 'component1',
    }, json.loads(testcase.additional_metadata))
    self.assertIsNone(testcase.crash_type)

  def test_update_issue_metadata_valid_integers(self):
    """Test updating integer metadata with valid values."""
    progression_task._update_issue_metadata(self.testcase, {  # pylint: disable=protected-access
        'last_tested_crash_revision': 12345,
        'last_progression_min': '100',
    })
    testcase = self.testcase.key.get()
    metadata = json.loads(testcase.additional_metadata)
    self.assertEqual(metadata.get('last_tested_crash_revision'), 12345)
    self.assertEqual(metadata.get('last_progression_min'), 100)

  def test_update_issue_metadata_invalid_integers_rejected(self):
    """Test that invalid integer strings are ignored."""
    progression_task._update_issue_metadata(self.testcase, {  # pylint: disable=protected-access
        'last_tested_crash_revision': 'EVIL/DEPS?x=',
        'last_progression_max': 'not_a_number',
    })
    testcase = self.testcase.key.get()
    metadata = json.loads(testcase.additional_metadata)
    self.assertNotIn('last_tested_crash_revision', metadata)
    self.assertNotIn('last_progression_max', metadata)


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


@test_utils.with_cloud_emulators('datastore')
class ProgressionRescheduleGuardTest(unittest.TestCase):
  """Tests progression reschedule guards for closed testcases and deleted jobs."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.task_creation.mark_unreproducible_if_flaky',
        'clusterfuzz._internal.google_cloud_utils.blobs.delete_blob',
    ])
    os.environ['FAIL_WAIT'] = '60'
    self.testcase = test_utils.create_generic_testcase()
    self.testcase.set_metadata('progression_pending', True)
    self.progression_task_input = uworker_msg_pb2.ProgressionTaskInput(
        blob_name='blob_name',
        stacktrace_upload_url='https://signed_upload_url')

  def _make_output(self, job_type, error_type, crash_revision=1):
    uworker_input = uworker_msg_pb2.Input(
        module_name=progression_task.__name__,
        testcase_id=str(self.testcase.key.id()),
        job_type=job_type,
        progression_task_input=self.progression_task_input)
    progression_output = uworker_msg_pb2.ProgressionTaskOutput(
        crash_revision=crash_revision)
    return uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        progression_task_output=progression_output,
        error_type=error_type,
        error_message='task error')

  def test_build_setup_error_with_deleted_job_clears_pending_without_raising(
      self):
    """Test deleted jobs do not raise in postprocess on build setup error."""
    output = self._make_output(
        'deleted_job_type',
        uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP_ERROR)

    progression_task.utask_postprocess(output)

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertFalse(updated.get_metadata('progression_pending'))

  def test_build_setup_error_skips_closed_testcase(self):
    """Test closed testcases are not rescheduled on build setup error."""
    self.testcase.open = False
    self.testcase.put()
    output = self._make_output(
        'deleted_job_type',
        uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP_ERROR)

    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add:
      progression_task.handle_progression_build_setup_error(output)
      mock_add.assert_not_called()

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertFalse(updated.get_metadata('progression_pending'))

  def test_no_crash_skips_closed_testcase_without_marking_flaky(self):
    """Test closed testcases are ignored on PROGRESSION_NO_CRASH."""
    self.testcase.open = False
    self.testcase.put()
    output = self._make_output('deleted_job_type',
                               uworker_msg_pb2.ErrorType.PROGRESSION_NO_CRASH)

    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add:
      progression_task.handle_progression_no_crash(output)
      mock_add.assert_not_called()

    self.mock.mark_unreproducible_if_flaky.assert_not_called()
    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertFalse(updated.get_metadata('progression_pending'))

  def test_no_crash_first_attempt_with_deleted_job_clears_pending(self):
    """Test first-attempt PROGRESSION_NO_CRASH with deleted job does not raise."""
    output = self._make_output('deleted_job_type',
                               uworker_msg_pb2.ErrorType.PROGRESSION_NO_CRASH)

    progression_task.handle_progression_no_crash(output)

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertFalse(updated.get_metadata('progression_pending'))

  def test_timeout_with_deleted_job_clears_pending_without_raising(self):
    """Test PROGRESSION_TIMEOUT with deleted job does not raise."""
    output = self._make_output('deleted_job_type',
                               uworker_msg_pb2.ErrorType.PROGRESSION_TIMEOUT)

    progression_task.handle_progression_timeout(output)

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertFalse(updated.get_metadata('progression_pending'))

  def test_testcase_setup_error_with_deleted_job_clears_pending_without_raising(
      self):
    """Test TESTCASE_SETUP error with deleted job clears pending without raising."""
    output = self._make_output('deleted_job_type',
                               uworker_msg_pb2.ErrorType.TESTCASE_SETUP)

    progression_task.utask_postprocess(output)

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertFalse(updated.get_metadata('progression_pending'))
    self.assertIn('task error', updated.comments)

  def test_testcase_setup_error_skips_closed_testcase(self):
    """Test TESTCASE_SETUP error does not reschedule closed progression testcase."""
    self.testcase.open = False
    self.testcase.put()
    output = self._make_output('deleted_job_type',
                               uworker_msg_pb2.ErrorType.TESTCASE_SETUP)

    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add:
      progression_task.utask_postprocess(output)
      mock_add.assert_not_called()

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertFalse(updated.get_metadata('progression_pending'))

  def test_testcase_setup_error_reschedules_open_testcase_with_active_job(self):
    """Test TESTCASE_SETUP error delegates to setup handler when job exists."""
    data_types.Job(name='active_job_type', platform='LINUX').put()
    output = self._make_output('active_job_type',
                               uworker_msg_pb2.ErrorType.TESTCASE_SETUP)

    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add:
      progression_task.utask_postprocess(output)
      mock_add.assert_called_once_with(
          'progression',
          str(self.testcase.key.id()),
          'active_job_type',
          wait_time=60)

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertIn('task error', updated.comments)

  def test_no_crash_retries_keep_progression_pending_until_terminal_flaky(self):
    """Test real 4-attempt non-crash state machine holds progression_pending."""
    data_types.Job(name='active_job_type', platform='LINUX').put()
    self.testcase.set_metadata('progression_bad_min_build_retry', True)
    output = self._make_output(
        'active_job_type',
        uworker_msg_pb2.ErrorType.PROGRESSION_NO_CRASH,
        crash_revision=42)

    def _real_mark_flaky(testcase, unused_task_name, potentially_flaky):
      if testcase.get_metadata('potentially_flaky'):
        testcase.one_time_crasher_flag = True
        testcase.fixed = 'NA'
        testcase.put()
        return
      testcase.set_metadata('potentially_flaky', potentially_flaky)

    self.mock.mark_unreproducible_if_flaky.side_effect = _real_mark_flaky
    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add:
      for attempt in range(1, 4):
        progression_task.handle_progression_no_crash(output)
        cur = data_handler.get_testcase_by_id(self.testcase.key.id())
        self.assertTrue(
            cur.get_metadata('progression_pending'), f'attempt={attempt}')
        self.assertIsNone(cur.get_metadata('progression_bad_min_build_retry'))
      self.assertEqual(2, mock_add.call_count)

      progression_task.handle_progression_no_crash(output)

    after_terminal = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertFalse(bool(after_terminal.get_metadata('progression_pending')))
    self.assertTrue(after_terminal.one_time_crasher_flag)
    self.assertEqual('NA', after_terminal.fixed)

  def test_custom_binary_first_non_crash_attempt_keeps_progression_pending(
      self):
    """Test custom-binary confirmation retry keeps progression_pending set."""
    data_types.Job(name='active_job_type', platform='LINUX').put()
    custom_input = uworker_msg_pb2.ProgressionTaskInput(
        custom_binary=True,
        blob_name='blob_name',
        stacktrace_upload_url='https://signed_upload_url')
    uworker_input = uworker_msg_pb2.Input(
        module_name=progression_task.__name__,
        testcase_id=str(self.testcase.key.id()),
        job_type='active_job_type',
        progression_task_input=custom_input)
    output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        progression_task_output=uworker_msg_pb2.ProgressionTaskOutput(
            crash_revision=77))

    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add, \
        mock.patch('clusterfuzz._internal.base.bisection.request_bisection'):
      progression_task.utask_postprocess(output)
      mock_add.assert_called_once()

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertTrue(updated.open)
    self.assertTrue(updated.get_metadata('progression_pending'))
    self.assertEqual(77, updated.get_metadata('last_tested_revision'))

  def test_unfiled_bad_min_build_after_clean_latest_retries_then_closes(self):
    """Test unfiled bad min_revision after clean trunk retries once then closes."""
    data_types.Job(name='active_job_type', platform='LINUX').put()
    uworker_input = uworker_msg_pb2.Input(
        module_name=progression_task.__name__,
        testcase_id=str(self.testcase.key.id()),
        job_type='active_job_type',
        progression_task_input=self.progression_task_input)
    output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        progression_task_output=uworker_msg_pb2.ProgressionTaskOutput(
            passed_on_latest=True, max_revision=500),
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD,
        error_message='Bad build at r100. Skipping')

    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add, \
        mock.patch('clusterfuzz._internal.metrics.events.emit') as mock_emit:
      progression_task.utask_postprocess(output)
      mock_add.assert_called_once()
      mock_emit.assert_not_called()

      after_attempt_1 = data_handler.get_testcase_by_id(self.testcase.key.id())
      self.assertTrue(after_attempt_1.open)
      self.assertEqual('', after_attempt_1.fixed)
      self.assertTrue(after_attempt_1.get_metadata('progression_pending'))
      self.assertEqual(500,
                       after_attempt_1.get_metadata('last_tested_revision'))

      progression_task.utask_postprocess(output)
      after_attempt_2 = data_handler.get_testcase_by_id(self.testcase.key.id())
      self.assertFalse(after_attempt_2.open)
      self.assertEqual('NA', after_attempt_2.fixed)
      self.assertFalse(
          bool(after_attempt_2.get_metadata('progression_pending')))
      mock_emit.assert_called_once()
      emitted_event = mock_emit.call_args[0][0]
      self.assertEqual(self.testcase.key.id(), emitted_event.testcase_id)
      self.assertEqual(
          events.RejectionReason.PROGRESSION_MIN_REVISION_BAD_BUILD,
          emitted_event.rejection_reason)

  def test_filed_bad_min_build_after_clean_latest_stays_open(self):
    """Test filed bugs hitting bad min_revision stay open without auto-closing."""
    data_types.Job(name='active_job_type', platform='LINUX').put()
    self.testcase.bug_information = '99999'
    self.testcase.put()
    uworker_input = uworker_msg_pb2.Input(
        module_name=progression_task.__name__,
        testcase_id=str(self.testcase.key.id()),
        job_type='active_job_type',
        progression_task_input=self.progression_task_input)
    output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        progression_task_output=uworker_msg_pb2.ProgressionTaskOutput(
            passed_on_latest=True, max_revision=500),
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD,
        error_message='Bad build at r100. Skipping')

    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add, \
        mock.patch('clusterfuzz._internal.metrics.events.emit') as mock_emit:
      progression_task.utask_postprocess(output)
      mock_add.assert_not_called()
      mock_emit.assert_not_called()

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertTrue(updated.open)
    self.assertEqual('', updated.fixed)
    self.assertFalse(bool(updated.get_metadata('progression_pending')))

  def test_grouped_sibling_bad_min_build_after_clean_latest_stays_open(self):
    """Test group-linked siblings with an open group bug stay open."""
    data_types.Job(name='active_job_type', platform='LINUX').put()
    self.testcase.group_id = 777
    self.testcase.group_bug_information = 88888
    self.testcase.put()
    uworker_input = uworker_msg_pb2.Input(
        module_name=progression_task.__name__,
        testcase_id=str(self.testcase.key.id()),
        job_type='active_job_type',
        progression_task_input=self.progression_task_input)
    output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        progression_task_output=uworker_msg_pb2.ProgressionTaskOutput(
            passed_on_latest=True, max_revision=500),
        error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD,
        error_message='Bad build at r100. Skipping')

    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add:
      progression_task.utask_postprocess(output)
      mock_add.assert_not_called()

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertTrue(updated.open)
    self.assertEqual('', updated.fixed)
    self.assertFalse(bool(updated.get_metadata('progression_pending')))

  def test_uploaded_or_pending_analysis_bad_min_build_stays_open(self):
    """Test user-uploaded, pending-analysis, and GitHub-linked cases stay open."""
    data_types.Job(name='active_job_type', platform='LINUX').put()
    protected_mutations = [
        {
            'uploader_email': 'researcher@example.com'
        },
        {
            'analyze_pending': True
        },
        {
            'github_issue_num': 42
        },
        {
            'status': 'Pending'
        },
    ]
    for attrs in protected_mutations:
      tc = test_utils.create_generic_testcase()
      tc.set_metadata('progression_pending', True)
      for key, val in attrs.items():
        setattr(tc, key, val)
      tc.put()
      uworker_input = uworker_msg_pb2.Input(
          module_name=progression_task.__name__,
          testcase_id=str(tc.key.id()),
          job_type='active_job_type',
          progression_task_input=self.progression_task_input)
      output = uworker_msg_pb2.Output(
          uworker_input=uworker_input,
          progression_task_output=uworker_msg_pb2.ProgressionTaskOutput(
              passed_on_latest=True, max_revision=500),
          error_type=uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD,
          error_message='Bad build at r100. Skipping')

      with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add:
        progression_task.utask_postprocess(output)
        mock_add.assert_not_called()

      updated = data_handler.get_testcase_by_id(tc.key.id())
      self.assertTrue(updated.open, f'attrs={attrs}')
      self.assertEqual('', updated.fixed, f'attrs={attrs}')
      self.assertFalse(
          bool(updated.get_metadata('progression_pending')), f'attrs={attrs}')

  def test_crash_on_latest_clears_stale_retry_flags(self):
    """Test crash_on_latest resets stale retry metadata keys."""
    self.testcase.set_metadata('progression_retry', True)
    self.testcase.set_metadata('progression_bad_min_build_retry', True)
    uworker_input = uworker_msg_pb2.Input(
        module_name=progression_task.__name__,
        testcase_id=str(self.testcase.key.id()),
        job_type='active_job_type',
        progression_task_input=self.progression_task_input)
    output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        progression_task_output=uworker_msg_pb2.ProgressionTaskOutput(
            crash_on_latest=True,
            crash_revision=300,
            crash_on_latest_message='Still crashes on latest revision r300.',
            last_tested_crash_stacktrace='stack'))

    progression_task.crash_on_latest(output)

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertIsNone(updated.get_metadata('progression_retry'))
    self.assertIsNone(updated.get_metadata('progression_bad_min_build_retry'))
    self.assertFalse(bool(updated.get_metadata('progression_pending')))

  def test_closed_custom_binary_testcase_skips_postprocess_updates(self):
    """Test closed custom-binary testcases are not modified in postprocess."""
    self.testcase.open = False
    self.testcase.fixed = 'NA'
    self.testcase.put()
    custom_input = uworker_msg_pb2.ProgressionTaskInput(
        custom_binary=True,
        blob_name='blob_name',
        stacktrace_upload_url='https://signed_upload_url')
    uworker_input = uworker_msg_pb2.Input(
        module_name=progression_task.__name__,
        testcase_id=str(self.testcase.key.id()),
        job_type='active_job_type',
        progression_task_input=custom_input)
    output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        progression_task_output=uworker_msg_pb2.ProgressionTaskOutput(
            crash_revision=77))

    with mock.patch('clusterfuzz._internal.base.tasks.add_task') as mock_add, \
        mock.patch('clusterfuzz._internal.base.bisection.request_bisection'):
      progression_task.utask_postprocess(output)
      mock_add.assert_not_called()

    updated = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertFalse(updated.open)
    self.assertEqual('NA', updated.fixed)
    self.assertFalse(bool(updated.get_metadata('progression_pending')))


@test_utils.with_cloud_emulators('datastore')
class FindFixedRangeBadMinRevisionAndErrorTest(unittest.TestCase):
  """Tests find_fixed_range min_revision bad-build recovery and bisect guards."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.get_task_completion_deadline',
        'clusterfuzz._internal.bot.fuzzers.engine_common.get_fuzz_target_issue_metadata',
        'clusterfuzz._internal.bot.tasks.setup.setup_testcase',
        'clusterfuzz._internal.bot.testcase_manager.check_for_bad_build',
        'clusterfuzz._internal.bot.testcase_manager.get_fuzz_target_from_input',
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
        'clusterfuzz._internal.build_management.build_manager.get_primary_bucket_path',
        'clusterfuzz._internal.build_management.build_manager.get_revisions_list',
        'clusterfuzz._internal.build_management.build_manager.is_custom_binary',
        'clusterfuzz._internal.build_management.build_manager.setup_build',
    ])
    self.mock.get_task_completion_deadline.return_value = 9999999999.0
    self.mock.get_fuzz_target_issue_metadata.return_value = {}
    self.mock.setup_testcase.return_value = (None, '/tmp/testcase', None)
    self.mock.get_fuzz_target_from_input.return_value = None
    self.mock.get_primary_bucket_path.return_value = 'gs://builds'
    self.mock.is_custom_binary.return_value = False
    self.mock.setup_build.return_value = True

    self.testcase = test_utils.create_generic_testcase()
    self.testcase.crash_revision = 100
    self.testcase.crash_type = 'AddressSanitizer: heap-use-after-free'
    self.testcase.crash_state = 'parse_frame\n'
    self.testcase.put()

  def _make_input(self):
    return uworker_msg_pb2.Input(
        job_type='job_type',
        testcase_id=str(self.testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(self.testcase),
        progression_task_input=uworker_msg_pb2.ProgressionTaskInput(
            blob_name='blob_name', stacktrace_upload_url='https://upload'))

  def _crashing_result(self):
    stacktrace = (
        '==12==ERROR: AddressSanitizer: heap-use-after-free on address '
        '0x602000000014 at pc 0x55a1234 bp 0x7ffd00 sp 0x7ffd08\n'
        'READ of size 4 at 0x602000000014 thread T0\n'
        '    #0 0x55a1233 in parse_frame /src/parser.c:42:9\n'
        'SUMMARY: AddressSanitizer: heap-use-after-free /src/parser.c:42:9\n')
    return crash_result_lib.CrashResult(1, 0.2, stacktrace)

  def _clean_result(self):
    return crash_result_lib.CrashResult(0, 0.1, '')

  def test_min_revision_bad_build_sets_passed_on_latest_true_when_trunk_clean(
      self):
    """Tests bad min_revision after clean latest trunk sets passed_on_latest."""
    self.mock.get_revisions_list.return_value = [100, 150, 200]
    self.mock.check_for_bad_build.side_effect = (
        lambda job_type, rev: uworker_msg_pb2.BuildData(
            revision=rev, is_bad_build=rev == 100))
    self.mock.test_for_crash_with_retries.return_value = self._clean_result()

    output = progression_task.find_fixed_range(self._make_input())

    self.assertEqual(uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD,
                     output.error_type)
    self.assertTrue(output.progression_task_output.passed_on_latest)
    self.assertEqual(200, output.progression_task_output.max_revision)
    self.assertFalse(output.progression_task_output.HasField('min_revision'))

  def test_max_revision_bad_build_sets_passed_on_latest_false(self):
    """Tests broken latest trunk leaves passed_on_latest False."""
    self.mock.get_revisions_list.return_value = [100, 200]
    self.mock.check_for_bad_build.side_effect = (
        lambda job_type, rev: uworker_msg_pb2.BuildData(
            revision=rev, is_bad_build=rev == 200))

    output = progression_task.find_fixed_range(self._make_input())

    self.assertEqual(uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD,
                     output.error_type)
    self.assertFalse(output.progression_task_output.passed_on_latest)

  def test_resumed_timeout_max_revision_does_not_set_passed_on_latest(self):
    """Tests capped last_progression_max from timeout does not claim latest pass."""
    self.testcase.set_metadata('last_progression_max', 150)
    self.mock.get_revisions_list.return_value = [100, 150, 200]
    self.mock.check_for_bad_build.side_effect = (
        lambda job_type, rev: uworker_msg_pb2.BuildData(
            revision=rev, is_bad_build=rev == 100))
    self.mock.test_for_crash_with_retries.return_value = self._clean_result()

    output = progression_task.find_fixed_range(self._make_input())

    self.assertEqual(uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD,
                     output.error_type)
    self.assertFalse(output.progression_task_output.passed_on_latest)
    self.assertTrue(output.progression_task_output.clear_min_max_metadata)

  def test_first_iteration_bisect_setup_error_does_not_raise_type_error(self):
    """Tests non-bad-build error on first bisect midpoint handles unset bounds."""
    self.mock.get_revisions_list.return_value = [100, 150, 200]
    tested_revisions = []

    def fake_setup(revision, fuzz_target=None):  # pylint: disable=unused-argument
      tested_revisions.append(revision)
      return revision != 150

    def fake_test(*args, **kwargs):  # pylint: disable=unused-argument
      if tested_revisions[-1] == 100:
        return self._crashing_result()
      return self._clean_result()

    self.mock.setup_build.side_effect = fake_setup
    self.mock.check_for_bad_build.side_effect = (
        lambda job_type, rev: uworker_msg_pb2.BuildData(
            revision=rev, is_bad_build=False))
    self.mock.test_for_crash_with_retries.side_effect = fake_test

    output = progression_task.find_fixed_range(self._make_input())

    self.assertEqual(uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP_ERROR,
                     output.error_type)
    self.assertFalse(
        output.progression_task_output.HasField('last_progression_min'))
    self.assertFalse(
        output.progression_task_output.HasField('last_progression_max'))

  def test_older_max_revision_than_known_crash_leaves_passed_on_latest_false(
      self):
    """Tests max_revision <= known_crash_revision never sets passed_on_latest."""
    self.testcase.set_metadata('last_tested_crash_revision', 200)
    self.mock.get_revisions_list.return_value = [100, 150]
    self.mock.check_for_bad_build.side_effect = (
        lambda job_type, rev: uworker_msg_pb2.BuildData(
            revision=rev, is_bad_build=rev == 200))
    self.mock.test_for_crash_with_retries.return_value = self._clean_result()

    output = progression_task.find_fixed_range(self._make_input())

    self.assertEqual(uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD,
                     output.error_type)
    self.assertFalse(output.progression_task_output.passed_on_latest)

  def test_clamped_min_past_bad_revisions_returns_bad_build_when_clean(self):
    """Tests aged-out crash_revision clamped past bad_revisions returns BAD_BUILD."""
    self.testcase.crash_revision = 90
    self.testcase.put()
    self.mock.get_revisions_list.return_value = [150, 200]
    self.mock.check_for_bad_build.side_effect = (
        lambda job_type, rev: uworker_msg_pb2.BuildData(
            revision=rev, is_bad_build=False))
    self.mock.test_for_crash_with_retries.return_value = self._clean_result()
    uworker_input = self._make_input()
    uworker_input.progression_task_input.bad_revisions.append(100)

    output = progression_task.find_fixed_range(uworker_input)

    self.assertEqual(uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD,
                     output.error_type)
    self.assertTrue(output.progression_task_output.passed_on_latest)
    self.assertEqual(200, output.progression_task_output.max_revision)

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
"""Tests for symbolize_task."""
import unittest

from clusterfuzz._internal.bot.tasks.utasks import symbolize_task
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class UtaskPreprocessTest(unittest.TestCase):
  """Tests symbolize_task.utask_preprocess."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.setup.preprocess_setup_testcase',
        'clusterfuzz._internal.build_management.build_manager.has_symbolized_builds',
        'clusterfuzz._internal.datastore.data_handler.get_stacktrace',
    ])
    self.mock.preprocess_setup_testcase.return_value = uworker_msg_pb2.SetupInput(
    )
    self.mock.get_stacktrace.return_value = 'some crash stacktrace'
    self.testcase = test_utils.create_generic_testcase()
    self.testcase.fixed = 'Yes'
    self.testcase.put()

  def test_no_symbolized_builds(self):
    """Ensure that nothing is done when symbolized builds are missing."""
    self.mock.has_symbolized_builds.return_value = False
    result = symbolize_task.utask_preprocess(self.testcase.key.id(), None, None)
    self.assertIsNone(result)

  def test_preprocess_uworker_input(self):
    """Tests the preprocess behaviour for non custom binaries."""
    result = symbolize_task.utask_preprocess(
        str(self.testcase.key.id()), 'job_type', None)
    self.assertEqual('job_type', result.job_type)
    returned_testcase = uworker_io.entity_from_protobuf(result.testcase,
                                                        data_types.Testcase)
    self.assertEqual(returned_testcase.key.id(), self.testcase.key.id())
    self.assertEqual(result.symbolize_task_input.old_crash_stacktrace,
                     'some crash stacktrace')


@test_utils.with_cloud_emulators('datastore')
class UTaskPostprocessTest(unittest.TestCase):
  """Tests for symbolize_task.utask_postprocess."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.uworker_handle_errors.handle',
        'clusterfuzz._internal.datastore.data_handler.handle_duplicate_entry',
        'clusterfuzz._internal.bot.tasks.task_creation.create_blame_task_if_needed'
    ])

  def test_error_handling_called_on_error(self):
    """Checks that an output with an error is handled properly."""
    testcase = test_utils.create_generic_testcase()
    uworker_input = uworker_msg_pb2.Input(testcase_id=str(testcase.key.id()))
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        error_type=uworker_msg_pb2.ErrorType.UNHANDLED)
    symbolize_task.utask_postprocess(uworker_output)
    self.assertTrue(self.mock.handle.called)

  def test_handle_build_setup_error(self):
    """Tests utask_postprocess behaviour when there is a crash on latest revision."""
    testcase = test_utils.create_generic_testcase()
    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()), job_type='job_type')
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        error_type=uworker_msg_pb2.ErrorType.SYMBOLIZE_BUILD_SETUP_ERROR)
    symbolize_task.utask_postprocess(uworker_output)
    self.assertTrue(self.mock.handle.called)

  def test_postprocess_behaviour_symbolize_failed(self):
    """Tests postprocess behaviour when symbolizing fails."""
    symbolize_task_output = uworker_msg_pb2.SymbolizeTaskOutput(
        crash_type='sym_crash_type',
        crash_address='sym_crash_address',
        crash_state='sym_crash_state',
        crash_stacktrace='sym_crash_stacktrace',
        symbolized=False,
        crash_revision=123,
        build_url='url')
    testcase = test_utils.create_generic_testcase()
    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()), job_type='job_type')
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        symbolize_task_output=symbolize_task_output)
    symbolize_task.utask_postprocess(uworker_output)

    self.assertFalse(self.mock.handle.called)

    testcase = data_handler.get_testcase_by_id(
        uworker_output.uworker_input.testcase_id)
    self.assertEqual(testcase.crash_type, symbolize_task_output.crash_type)
    self.assertEqual(testcase.crash_address,
                     symbolize_task_output.crash_address)
    self.assertEqual(testcase.crash_state, symbolize_task_output.crash_state)
    self.assertEqual(testcase.crash_stacktrace,
                     symbolize_task_output.crash_stacktrace)

    self.assertIsNone(testcase.get_metadata('build_url'))

    self.assertTrue(self.mock.handle_duplicate_entry.called)
    self.assertTrue(self.mock.create_blame_task_if_needed.called)

  def test_postprocess_behaviour_symbolize_passed(self):
    """Tests postprocess behaviour when symbolizing is successful."""
    symbolize_task_output = uworker_msg_pb2.SymbolizeTaskOutput(
        crash_type='sym_crash_type',
        crash_address='sym_crash_address',
        crash_state='sym_crash_state',
        crash_stacktrace='sym_crash_stacktrace',
        symbolized=True,
        crash_revision=123,
        build_url='url')
    testcase = test_utils.create_generic_testcase()
    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()), job_type='job_type')
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=uworker_input,
        symbolize_task_output=symbolize_task_output)
    symbolize_task.utask_postprocess(uworker_output)

    self.assertFalse(self.mock.handle.called)

    testcase = data_handler.get_testcase_by_id(
        uworker_output.uworker_input.testcase_id)
    self.assertEqual(testcase.crash_type, symbolize_task_output.crash_type)
    self.assertEqual(testcase.crash_address,
                     symbolize_task_output.crash_address)
    self.assertEqual(testcase.crash_state, symbolize_task_output.crash_state)
    self.assertEqual(testcase.crash_stacktrace,
                     symbolize_task_output.crash_stacktrace)

    self.assertEqual(testcase.get_metadata('build_url'), 'url')

    self.assertTrue(self.mock.handle_duplicate_entry.called)
    self.assertTrue(self.mock.create_blame_task_if_needed.called)


@test_utils.with_cloud_emulators('datastore')
class UtaskMainTest(unittest.TestCase):
  """Tests symbolize_task.utask_Main."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.setup.setup_testcase',
    ])
    self.testcase = test_utils.create_generic_testcase()
    self.testcase.fixed = 'Yes'
    self.testcase.put()

  def test_testcase_setup_failure(self):
    """Tests utask_main behaviour on setup_testcase failure."""
    self.mock.setup_testcase.return_value = (
        None, None,
        uworker_msg_pb2.Output(
            error_type=uworker_msg_pb2.ErrorType.TESTCASE_SETUP))
    uworker_input = uworker_msg_pb2.Input(
        testcase=uworker_io.entity_to_protobuf(self.testcase))
    result = symbolize_task.utask_main(uworker_input)
    self.assertEqual(result.error_type,
                     uworker_msg_pb2.ErrorType.TESTCASE_SETUP)

  def test_build_setup_failure(self):
    """Tests utask_main behaviour on build setup failure."""
    self.mock.setup_testcase.return_value = (None, '/testcase/file/path', None)
    uworker_input = uworker_msg_pb2.Input(
        testcase=uworker_io.entity_to_protobuf(self.testcase),
        job_type='job_type',
        setup_input=uworker_msg_pb2.SetupInput(),
        symbolize_task_input=uworker_msg_pb2.SymbolizeTaskInput(
            old_crash_stacktrace='some crash stacktrace'))
    result = symbolize_task.utask_main(uworker_input)
    self.assertEqual(result.error_type,
                     uworker_msg_pb2.ErrorType.SYMBOLIZE_BUILD_SETUP_ERROR)
    self.assertEqual(result.error_message, 'Build setup failed')

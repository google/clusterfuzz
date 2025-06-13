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
"""Tests for analyze task."""

import json
import os
import tempfile
import unittest

from clusterfuzz._internal.bot.tasks.utasks import analyze_task
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz._internal.tests.test_libs import utask_helpers


@test_utils.with_cloud_emulators('datastore')
class AddDefaultIssueMetadataTest(unittest.TestCase):
  """Test _add_default_issue_metadata."""

  def setUp(self):
    helpers.patch(
        self,
        [
            # Disable logging.
            'clusterfuzz._internal.datastore.data_types.Testcase._post_put_hook',
            'clusterfuzz._internal.metrics.logs.info',
        ])

  def test_union(self):
    """Test union of current testcase metadata and default issue metadata."""
    issue_metadata = {
        'issue_owners': 'dev1@example1.com, dev2@example2.com',
        'issue_components': 'component1',
        'issue_labels': 'label1, label2 ,label3'
    }

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('issue_owners', 'dev3@example3.com,dev2@example2.com')
    testcase.set_metadata('issue_components', 'component2')
    testcase.set_metadata('issue_labels', 'label4,label5, label2,')

    analyze_task._add_default_issue_metadata(testcase, issue_metadata)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com,dev3@example3.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1,component2',
                     testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3,label4,label5',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(3, self.mock.info.call_count)

  def test_no_testcase_metadata(self):
    """Test when we only have default issue metadata and no testcase
    metadata."""
    issue_metadata = {}

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('issue_owners', 'dev1@example1.com,dev2@example2.com')
    testcase.set_metadata('issue_components', 'component1')
    testcase.set_metadata('issue_labels', 'label1,label2,label3')

    analyze_task._add_default_issue_metadata(testcase, issue_metadata)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1', testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(0, self.mock.info.call_count)

  def test_no_default_issue_metadata(self):
    """Test when we only have testcase metadata and no default issue
    metadata."""
    issue_metadata = {
        'issue_owners': 'dev1@example1.com,dev2@example2.com',
        'issue_components': 'component1',
        'issue_labels': 'label1,label2,label3'
    }

    testcase = test_utils.create_generic_testcase()

    analyze_task._add_default_issue_metadata(testcase, issue_metadata)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1', testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(3, self.mock.info.call_count)

  def test_same_testcase_and_default_issue_metadata(self):
    """Test when we have same testcase metadata and default issue metadata."""
    issue_metadata = {
        'issue_owners': 'dev1@example1.com,dev2@example2.com',
        'issue_components': 'component1',
        'issue_labels': 'label1,label2,label3'
    }

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('issue_owners', 'dev1@example1.com,dev2@example2.com')
    testcase.set_metadata('issue_components', 'component1')
    testcase.set_metadata('issue_labels', 'label1,label2,label3')

    analyze_task._add_default_issue_metadata(testcase, issue_metadata)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1', testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(0, self.mock.info.call_count)


@test_utils.with_cloud_emulators('datastore')
class SetupTestcaseAndBuildTest(unittest.TestCase):
  """Tests for setup_testcase_and_build."""

  def setUp(self):
    """Do setup for tests."""
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.setup.setup_testcase',
        'clusterfuzz._internal.bot.tasks.utasks.analyze_task.setup_build',
    ])
    helpers.patch_environ(self)
    self.testcase_path = '/fake-testcase-path'
    self.build_url = 'https://build.zip'
    self.mock.setup_testcase.return_value = (None, self.testcase_path, None)
    self.gn_args = ('is_asan = true\n'
                    'use_goma = true\n'
                    'v8_enable_verify_heap = true')

    def setup_build(*args, **kwargs):  # pylint: disable=useless-return
      del args
      del kwargs
      os.environ['BUILD_URL'] = self.build_url
      return None

    self.mock.setup_build.side_effect = setup_build

  @unittest.skip('Metadata isn\'t set properly in tests.')
  def test_field_setting(self):
    """Tests that the correct fields are set after setting up the build.
    Especially testcase.metadata."""
    testcase = data_types.Testcase()
    testcase.put()
    with tempfile.NamedTemporaryFile() as gn_args_path:
      os.environ['GN_ARGS_PATH'] = gn_args_path.name
      gn_args_path.write(bytes(self.gn_args, 'utf-8'))
      gn_args_path.seek(0)
      result = analyze_task.setup_testcase_and_build(testcase, 'job', None, [],
                                                     None)
      metadata = json.loads(testcase.additional_metadata)
      self.assertEqual(metadata['gn_args'], self.gn_args)
    self.assertEqual(result, (self.testcase_path, None))
    self.assertEqual(testcase.absolute_path, self.testcase_path)
    self.assertEqual(metadata['build_url'], self.build_url)
    self.assertEqual(testcase.platform, 'linux')


@test_utils.with_cloud_emulators('datastore')
class AnalyzeTaskIntegrationTest(utask_helpers.UtaskIntegrationTest):
  """Integration tests for analyze_task."""

  def setUp(self):
    super().setUp()
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
    ])
    self.uworker_env['TASK_NAME'] = 'analyze'
    self.uworker_env['JOB_NAME'] = 'libfuzzer_chrome_asan'

  def test_analyze_reproducible(self):
    """Tests that analyze_task handles reproducible testcases properly."""
    self.execute(analyze_task, str(self.testcase.key.id()), self.job_type,
                 self.uworker_env)
    # TODO(metzman): Figure out why this test doesn't crash in CI. The reenable the checks.
    # For now, it's good to check that (de)serialization doesn't exception.
    # testcase = self.testcase.key.get(use_cache=False, use_memcache=False)
    # self.assertTrue(testcase.status, 'Processed')
    # self.assertIn('SCARINESS', testcase.crash_stacktrace)


@test_utils.with_cloud_emulators('datastore')
class UTaskPostprocessTest(unittest.TestCase):
  """Tests for analyze_task.utask_postprocess."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.analyze_task._ERROR_HANDLER.handle',
        'clusterfuzz._internal.bot.tasks.task_creation.create_tasks',
        'clusterfuzz._internal.bot.tasks.utasks.analyze_task._add_default_issue_metadata'
    ])
    self.testcase = test_utils.create_generic_testcase()
    self.testcase_metadata = data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase.key.id())
    self.testcase_metadata.put()
    self.uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(self.testcase.key.id()))

  def test_error_handling_called_on_error(self):
    """Checks that an output with an error is handled properly."""
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        error_type=uworker_msg_pb2.ErrorType.UNHANDLED)
    analyze_task.utask_postprocess(uworker_output)
    self.assertTrue(self.mock.handle.called)

  def test_processed_testcase_flow(self):
    """Tests utask_postprocess behaviour when there is a crash on latest revision."""
    analyze_task_output = uworker_msg_pb2.AnalyzeTaskOutput(
        crash_revision=123,
        absolute_path='absolute_path',
        minimized_arguments='minimized_arguments')
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=self.uworker_input,
        analyze_task_output=analyze_task_output,
        issue_metadata='{}')

    testcase = data_handler.get_testcase_by_id(
        uworker_output.uworker_input.testcase_id)
    self.assertEqual(testcase.crash_revision, 1)
    self.assertEqual(testcase.absolute_path, '/a/b/c/test.html')
    self.assertEqual(testcase.minimized_arguments, '')
    analyze_task.utask_postprocess(uworker_output)
    testcase = data_handler.get_testcase_by_id(
        uworker_output.uworker_input.testcase_id)
    self.assertFalse(self.mock.handle.called)
    # Make sure the testcase is updated with analyze_task output
    self.assertEqual(testcase.crash_revision, 123)
    self.assertEqual(testcase.absolute_path, 'absolute_path')
    self.assertEqual(testcase.minimized_arguments, 'minimized_arguments')
    self.assertTrue(self.mock._add_default_issue_metadata.called)  # pylint: disable=protected-access
    self.assertTrue(self.mock.create_tasks.called)


@test_utils.with_cloud_emulators('datastore')
class HandleEventEmitionNonCrashTest(unittest.TestCase):
  """Tests for handle_noncrash."""

  def setUp(self):
    helpers.patch_environ(self)
    self.mock_rejection_event = unittest.mock.Mock()

    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
        'clusterfuzz._internal.datastore.data_handler.is_first_attempt_for_task',
        'clusterfuzz._internal.datastore.data_handler.mark_invalid_uploaded_testcase',
        'clusterfuzz._internal.metrics.events.emit',
        'clusterfuzz._internal.metrics.events.TestcaseRejectionEvent',
    ])

    # When TestcaseRejectionEvent is created, call our helper to populate
    # the mock object and then return it.
    self.mock.TestcaseRejectionEvent.side_effect = self.init_rejection_event
    self.testcase = test_utils.create_generic_testcase()
    self.testcase_metadata = data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase.key.id())
    self.testcase_metadata.put()
    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(self.testcase.key.id()))
    self.uworker_output = uworker_msg_pb2.Output(uworker_input=uworker_input)

  def init_rejection_event(self, testcase, rejection_reason):
    """A side effect to capture arguments passed to TestcaseRejectionEvent."""
    self.mock_rejection_event.testcase_id = testcase.key.id()
    self.mock_rejection_event.rejection_reason = rejection_reason
    return self.mock_rejection_event

  def _assert_rejection_event_emitted(self, expected_reason):
    """Asserts that the correct rejection event was emitted once."""
    self.mock.emit.assert_called_once_with(self.mock_rejection_event)
    self.assertEqual(self.testcase.key.id(),
                     self.mock_rejection_event.testcase_id)
    self.assertEqual(expected_reason,
                     self.mock_rejection_event.rejection_reason)

  def test_event_emition_handle_noncrash_first_attempt(self):
    """Test that a non-crashing testcase is retried on the first attempt."""
    self.mock.is_first_attempt_for_task.return_value = True
    analyze_task.handle_noncrash(self.uworker_output)
    self._assert_rejection_event_emitted(
        expected_reason=events.RejectionReason.ANALYZE_FLAKE_ON_FIRST_ATTEMPT)

  def test_event_emition_handle_noncrash_second_attempt(self):
    """Test that a non-crashing testcase is marked invalid after the second attempt."""
    self.mock.is_first_attempt_for_task.return_value = False
    analyze_task.handle_noncrash(self.uworker_output)
    self._assert_rejection_event_emitted(
        expected_reason=events.RejectionReason.ANALYZE_NO_REPRO)

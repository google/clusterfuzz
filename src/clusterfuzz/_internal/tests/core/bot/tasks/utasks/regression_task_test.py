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
# pylint: disable=unused-argument
# pylint: disable=protected-access

import os
import unittest

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.bot.tasks.utasks import regression_task
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


def _roundtrip_input(uworker_input: uworker_io.UworkerInput
                    ) -> uworker_io.DeserializedUworkerMsg:
  serialized = uworker_io.serialize_uworker_input(uworker_input)
  return uworker_io.deserialize_uworker_input(serialized)


def _roundtrip_output(uworker_output: uworker_io.UworkerOutput
                     ) -> uworker_io.DeserializedUworkerMsg:
  serialized = uworker_io.serialize_uworker_output(uworker_output)
  return uworker_io.deserialize_uworker_output(serialized)


class WriteToBigQueryTest(unittest.TestCase):
  """Test write_to_big_query."""

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
    regression_task.write_to_big_query(self.testcase, 456, 789)
    self.mock.write_range.assert_called_once_with(
        table_id='regressions',
        testcase=self.testcase,
        range_name='regression',
        start=456,
        end=789)


class TestcaseReproducesInRevisionTest(unittest.TestCase):
  """Test _testcase_reproduces_in_revision."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.setup_regular_build',
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
        'clusterfuzz._internal.bot.testcase_manager.check_for_bad_build',
    ])

  def test_error_on_failed_setup(self):
    """Ensure that we throw an exception if we fail to set up a build."""
    os.environ['APP_NAME'] = 'app_name'
    # No need to implement a fake setup_regular_build. Since it's doing nothing,
    # we won't have the build directory properly set.
    with self.assertRaises(errors.BuildSetupError):
      regression_task._testcase_reproduces_in_revision(
          None, '/tmp/blah', 'job_type', 1, should_log=False)


@test_utils.with_cloud_emulators('datastore')
class TestFoundRegressionNearExtremeRevisions(unittest.TestCase):
  """Test found_regression_near_extreme_revisions."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.regression_task.save_regression_range',
        'clusterfuzz._internal.bot.tasks.utasks.regression_task._testcase_reproduces_in_revision',
    ])

    # Keep a dummy test case. Values are not important, but we need an id.
    self.testcase = data_types.Testcase()
    self.testcase.put()

    self.revision_list = [1, 2, 5, 8, 9, 12, 15, 19, 21, 22]

  def test_near_max_revision(self):
    """Ensure that we return True if this is a very recent regression."""

    def testcase_reproduces(testcase,
                            testcase_file_path,
                            job_type,
                            revision,
                            should_log=True,
                            min_revision=None,
                            max_revision=None):
      return revision > 20

    self.mock._testcase_reproduces_in_revision.side_effect = testcase_reproduces

    regression_task.found_regression_near_extreme_revisions(
        self.testcase, '/a/b', 'job_name', self.revision_list, 0, 9)

  def test_at_min_revision(self):
    """Ensure that we return True if we reproduce in min revision."""
    self.mock._testcase_reproduces_in_revision.return_value = True

    regression_task.found_regression_near_extreme_revisions(
        self.testcase, '/a/b', 'job_name', self.revision_list, 0, 9)

  def test_not_at_extreme_revision(self):
    """Ensure that we return False if we didn't regress near an extreme."""

    def testcase_reproduces(testcase,
                            testcase_file_path,
                            job_type,
                            revision,
                            should_log=True,
                            min_revision=None,
                            max_revision=None):
      return revision > 10

    self.mock._testcase_reproduces_in_revision.side_effect = testcase_reproduces

    regression_task.found_regression_near_extreme_revisions(
        self.testcase, '/a/b', 'job_name', self.revision_list, 0, 9)


def _sample(input_list, count):
  """Helper function to deterministically sample a list."""
  assert count <= len(input_list)
  return input_list[:count]


@test_utils.with_cloud_emulators('datastore')
class ValidateRegressionRangeTest(unittest.TestCase):
  """Tests for validate_regression_range."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.regression_task._testcase_reproduces_in_revision',
        'random.sample',
    ])

    self.mock.sample.side_effect = _sample

  def test_no_earlier_revisions(self):
    """Make sure we don't throw exceptions if nothing is before min revision."""
    testcase = data_types.Testcase()
    testcase.put()

    self.mock._testcase_reproduces_in_revision.return_value = False
    result = regression_task.validate_regression_range(testcase, '/a/b',
                                                       'job_type', [0], 0)
    self.assertTrue(result)

  def test_one_earlier_revision(self):
    """Test a corner-case with few revisions earlier than min revision."""
    testcase = data_types.Testcase()
    testcase.put()

    self.mock._testcase_reproduces_in_revision.return_value = False
    result = regression_task.validate_regression_range(testcase, '/a/b',
                                                       'job_type', [0, 1, 2], 1)
    self.assertTrue(result)

  def test_invalid_range(self):
    """Ensure that we handle invalid ranges correctly."""
    testcase = data_types.Testcase()
    testcase.put()

    self.mock._testcase_reproduces_in_revision.return_value = True
    result = regression_task.validate_regression_range(
        testcase, '/a/b', 'job_type', [0, 1, 2, 3, 4], 4)
    self.assertFalse(result)

    testcase = testcase.key.get()
    self.assertEqual(testcase.regression, 'NA')

  def test_valid_range(self):
    """Ensure that we handle valid ranges correctly."""
    testcase = data_types.Testcase()
    testcase.put()

    self.mock._testcase_reproduces_in_revision.return_value = False
    result = regression_task.validate_regression_range(
        testcase, '/a/b', 'job_type', [0, 1, 2, 3, 4], 4)
    self.assertTrue(result)


@test_utils.with_cloud_emulators('datastore')
class UtaskPreprocessTest(unittest.TestCase):
  """Test regression_task.utask_preprocess."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.setup.preprocess_setup_testcase',
    ])

  def test_invalid_testcase(self):
    """Verifies that an InvalidTestCase error is raised when we execute against
    an invalid testcase ID."""
    testcase_id = 11
    with self.assertRaises(errors.InvalidTestcaseError):
      regression_task.utask_preprocess(testcase_id, None, None)

  def test_already_regressed_testcase(self):
    """Verifies that if the testcase already has regression information stored,
    a new regression task is not started."""
    testcase = test_utils.create_generic_testcase()
    testcase.regression = 'foo'
    testcase.put()

    self.assertIsNone(
        regression_task.utask_preprocess(testcase.key.id(), None, None))

  def test_custom_binary(self):
    """Verifies that if the testcase concerns a custom binary, a new regression
    task is not started."""
    helpers.patch_environ(self)
    os.environ['CUSTOM_BINARY'] = 'some_value'

    testcase = test_utils.create_generic_testcase()

    self.assertIsNone(
        regression_task.utask_preprocess(testcase.key.id(), None, None))

    testcase = testcase.key.get()
    self.assertEqual(testcase.regression, 'NA')
    self.assertRegex(testcase.comments, 'Not applicable for custom binaries.$')

  def test_success(self):
    """Verifies that if the testcase concerns a custom binary, a new regression
    task is not started."""
    testcase = test_utils.create_generic_testcase()
    # Ensure this property exists before we check for it below.
    self.assertTrue(testcase.project_name)

    testcase_id = str(testcase.key.id())
    job_type = 'foo-job'
    uworker_env = {"foo": "bar"}
    fuzzer_name = 'foo-fuzzer'
    self.mock.preprocess_setup_testcase.return_value = uworker_io.SetupInput(
        fuzzer_name=fuzzer_name)

    uworker_input = regression_task.utask_preprocess(testcase_id, job_type,
                                                     uworker_env)

    self.assertEqual(uworker_input.testcase_id, testcase_id)
    self.assertEqual(uworker_input.testcase.project_name, testcase.project_name)
    self.assertEqual(uworker_input.job_type, job_type)
    self.assertTrue(uworker_input.HasField("regression_task_input"))

    testcase = testcase.key.get()
    self.assertRegex(testcase.comments, 'started.$')
    self.assertEqual(uworker_input.setup_input.fuzzer_name, fuzzer_name)
    self.assertEqual(uworker_input.uworker_env, uworker_env)


@test_utils.with_cloud_emulators('datastore')
class UtaskMainTest(unittest.TestCase):
  """Test regression_task.utask_main."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.setup.setup_testcase',
        'clusterfuzz._internal.build_management.build_manager.get_primary_bucket_path',
        'clusterfuzz._internal.build_management.build_manager.get_revisions_list',
    ])

  def test_setup_error(self):
    """Verifies that if setting up the testcase fails, the task bails out."""
    testcase = test_utils.create_generic_testcase()
    uworker_input = uworker_io.UworkerInput(
        testcase_id=str(testcase.key.id()),
        testcase=testcase,
        job_type='foo-job',
        setup_input=uworker_io.SetupInput(),
    )

    self.mock.setup_testcase.return_value = (
        None, None,
        uworker_io.UworkerOutput(
            error_type=uworker_msg_pb2.ErrorType.TESTCASE_SETUP))

    output = regression_task.utask_main(_roundtrip_input(uworker_input))
    output.error_type = uworker_msg_pb2.ErrorType.TESTCASE_SETUP

  def test_empty_revision_list(self):
    """Verifies that if no good revisions can be found, the task fails."""
    testcase = test_utils.create_generic_testcase()
    bad_revisions = [1, 2, 3]
    uworker_input = uworker_io.UworkerInput(
        testcase_id=str(testcase.key.id()),
        testcase=testcase,
        job_type='foo-job',
        setup_input=uworker_io.SetupInput(),
        regression_task_input=uworker_io.RegressionTaskInput(),
    )
    uworker_input.regression_task_input.bad_revisions.extend(bad_revisions)

    self.mock.setup_testcase.return_value = (None, None, None)
    # TODO: Set up environment more realistically and avoid mocking these out
    # entirely.
    self.mock.get_primary_bucket_path.return_value = 'gs://foo'
    self.mock.get_revisions_list.return_value = []

    output = regression_task.utask_main(_roundtrip_input(uworker_input))

    self.mock.get_revisions_list.assert_called_once()
    self.assertEqual(output.error_type,
                     uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR)
    self.assertEqual(output.testcase.key, testcase.key)


@test_utils.with_cloud_emulators('datastore')
class UtaskPostprocessTest(unittest.TestCase):
  """Test regression_task.utask_postprocess."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
    ])

  def test_error_testcase_setup(self):
    """Verifies that if the task failed during setup, the error is handled
    appropriately.
    """
    testcase = test_utils.create_generic_testcase()

    output = uworker_io.UworkerOutput(
        uworker_input=uworker_io.UworkerInput(
            testcase_id=str(testcase.key.id()),
            module_name=regression_task.__name__),
        error_type=uworker_msg_pb2.ErrorType.TESTCASE_SETUP)

    regression_task.utask_postprocess(_roundtrip_output(output))

    # TODO: Set up environment more realistically and check `add_task()` args.
    self.mock.add_task.assert_called()

  def test_revision_list_error(self):
    """Verifies that if the task failed with `REGRESSION_REVISION_LIST_ERROR`,
    the testcase is updated to reflect that."""
    testcase = test_utils.create_generic_testcase()

    output = uworker_io.UworkerOutput(
        uworker_input=uworker_io.UworkerInput(
            testcase_id=str(testcase.key.id()),
            module_name=regression_task.__name__),
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR,
        testcase=uworker_io.UworkerEntityWrapper(testcase))

    regression_task.utask_postprocess(_roundtrip_output(output))

    testcase = testcase.key.get()
    self.assertEqual(testcase.fixed, 'NA')
    self.assertRegex(testcase.comments, 'Failed to fetch revision list.$')

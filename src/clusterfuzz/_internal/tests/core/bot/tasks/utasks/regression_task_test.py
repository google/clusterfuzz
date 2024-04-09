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
        'clusterfuzz._internal.build_management.build_manager.check_app_path',
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
        'clusterfuzz._internal.bot.testcase_manager.check_for_bad_build',
    ])

  def test_error_on_failed_setup(self):
    """Ensure that we throw an exception if we fail to set up a build."""
    os.environ['APP_NAME'] = 'app_name'
    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    self.mock.check_app_path.return_value = False
    # No need to implement a fake setup_regular_build. Since it's doing nothing,
    # we won't have the build directory properly set.
    is_crash, error = regression_task._testcase_reproduces_in_revision(
        None,
        '/tmp/blah',
        'job_type',
        1,
        regression_task_output,
        None,
        should_log=False)
    self.assertIsNone(is_crash)
    self.assertIsNotNone(error)
    self.assertEqual(error.error_type,
                     uworker_msg_pb2.REGRESSION_BUILD_SETUP_ERROR)

  def test_bad_build_error(self):
    """Tests _testcase_reproduces_in_revision behaviour on bad builds."""
    self.mock.check_app_path.return_value = True
    build_data = uworker_msg_pb2.BuildData(
        revision=1, is_bad_build=True, should_ignore_crash_result=False)
    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    self.mock.check_for_bad_build.return_value = build_data
    result, worker_output = regression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        None, '/tmp/blah', 'job_type', 1, regression_task_output, None)
    self.assertIsNone(result)
    self.assertEqual(worker_output.error_type,
                     uworker_msg_pb2.ErrorType.REGRESSION_BAD_BUILD_ERROR)
    self.assertEqual(len(regression_task_output.build_data_list), 1)
    self.assertEqual(regression_task_output.build_data_list[0], build_data)


@test_utils.with_cloud_emulators('datastore')
class TestCheckLatestRevisions(unittest.TestCase):
  """Test check_latest_revisions."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.regression_task.save_regression_range',
        'clusterfuzz._internal.bot.tasks.utasks.regression_task._testcase_reproduces_in_revision',
    ])

    # Keep a dummy test case. Values are not important, but we need an id.
    self.testcase = data_types.Testcase()
    self.testcase.put()

    self.revision_list = [1, 2, 5, 8, 9, 12, 15, 19, 21, 22]
    self.reproduces_in_revision = lambda revision: (True, None)
    self.mock._testcase_reproduces_in_revision.side_effect = (
        self._testcase_reproduces)

  def _testcase_reproduces(self,
                           testcase,
                           testcase_file_path,
                           job_type,
                           revision,
                           fuzz_target,
                           regression_task_output,
                           should_log=True,
                           min_revision=None,
                           max_revision=None):
    """Mock for `regression_task._testcase_reproduces_in_revision()`."""
    return self.reproduces_in_revision(revision)

  def test_regressed_near_max_revision(self):
    """Ensures that `check_latest_revisions` returns a result if this is a very
    recent regression.
    """
    self.reproduces_in_revision = lambda revision: (revision > 20, None)

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.check_latest_revisions(
        self.testcase, '/a/b', 'job_name', self.revision_list, None,
        regression_task_output)

    self.assertIsNotNone(result)
    self.assertEqual(result.regression_task_output.regression_range_start, 19)
    self.assertEqual(result.regression_task_output.regression_range_end, 21)

  def test_latest_revisions_all_crash(self):
    """Ensures that `check_latest_revisions` returns None if all the latest
    revisions crash.
    """
    self.reproduces_in_revision = lambda revision: (revision > 10, None)

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.check_latest_revisions(
        self.testcase, '/a/b', 'job_name', self.revision_list, None,
        regression_task_output)

    self.assertIsNone(result)
    self.assertEqual(regression_task_output.last_regression_max, 15)

  def test_skip_latest_bad_builds(self):
    """Ensures that `check_latest_revisions` skips bad builds."""

    def repros(revision):
      if revision > 19:
        return False, uworker_msg_pb2.Output(
            error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)

      return True, None

    self.reproduces_in_revision = repros

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.check_latest_revisions(
        self.testcase, '/a/b', 'job_name', self.revision_list, None,
        regression_task_output)

    self.assertIsNone(result)
    self.assertEqual(regression_task_output.last_regression_max, 15)


@test_utils.with_cloud_emulators('datastore')
class TestFindEarliestGoodRevision(unittest.TestCase):
  """Test find_earliest_good_revision."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.regression_task.save_regression_range',
        'clusterfuzz._internal.bot.tasks.utasks.regression_task._testcase_reproduces_in_revision',
        'time.time',
    ])

    self.mock.time.return_value = 0.
    self.deadline = 1.

    # Keep a dummy test case. Values are not important, but we need an id.
    self.testcase = data_types.Testcase()
    self.testcase.put()

    self.revision_list = [1, 2, 5, 8, 9, 12, 15, 19, 21, 22]
    self.reproduces_in_revision = lambda revision: (True, None)
    self.mock._testcase_reproduces_in_revision.side_effect = (
        self._testcase_reproduces)

  def _testcase_reproduces(self,
                           testcase,
                           testcase_file_path,
                           job_type,
                           revision,
                           fuzz_target,
                           regression_task_output,
                           should_log=True,
                           min_revision=None,
                           max_revision=None):
    """Mock for `regression_task._testcase_reproduces_in_revision()`."""
    return self.reproduces_in_revision(revision)

  def test_regressed_at_min_revision(self):
    """Ensures that `find_earliest_good_revision` returns a result if we reproduce
    in the earliest revision.
    """
    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.find_earliest_good_revision(
        self.testcase, '/a/b', 'job_name', self.revision_list, None,
        self.deadline, regression_task_output)

    self.assertIsNotNone(result)
    self.assertEqual(result.regression_task_output.regression_range_start, 0)
    self.assertEqual(result.regression_task_output.regression_range_end, 1)

  def test_regressed_near_min_revision(self):
    """Ensures that `find_earliest_good_revision` returns a result if we reproduce
    in the earliest good revision.
    """

    def repros(revision):
      if revision < 10:
        return False, uworker_msg_pb2.Output(
            error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)

      return True, None

    self.reproduces_in_revision = repros

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.find_earliest_good_revision(
        self.testcase, '/a/b', 'job_name', self.revision_list, None,
        self.deadline, regression_task_output)

    self.assertIsNotNone(result)
    self.assertEqual(result.regression_task_output.regression_range_start, 0)
    self.assertEqual(result.regression_task_output.regression_range_end, 12)

  def test_earliest_revisions_all_good(self):
    """Ensures that `find_earliest_good_revision` returns None if the earliest
    revision is good.
    """
    self.reproduces_in_revision = lambda revision: (revision > 10, None)

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.find_earliest_good_revision(
        self.testcase, '/a/b', 'job_name', self.revision_list, None,
        self.deadline, regression_task_output)

    self.assertIsNone(result)
    self.assertEqual(regression_task_output.last_regression_min, 1)

  def test_skips_bad_builds(self):
    """Ensures that `find_earliest_good_revision` skips over all bad builds."""

    def repros(revision):
      if revision < 10:
        return False, uworker_msg_pb2.Output(
            error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)

      return False, None

    self.reproduces_in_revision = repros

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.find_earliest_good_revision(
        self.testcase, '/a/b', 'job_name', self.revision_list, None,
        self.deadline, regression_task_output)

    self.assertIsNone(result)
    self.assertEqual(regression_task_output.last_regression_min, 12)

  def test_revisions_all_bad(self):
    """Ensures that `find_earliest_good_revision` identifies that the max
    revision caused a regression if all previous builds are bad.
    """
    self.reproduces_in_revision = lambda revision: (False, uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR))

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.find_earliest_good_revision(
        self.testcase, '/a/b', 'job_name', self.revision_list, None,
        self.deadline, regression_task_output)

    self.assertIsNotNone(result)
    self.assertEqual(result.regression_task_output.regression_range_start, 0)
    self.assertEqual(result.regression_task_output.regression_range_end, 22)

  def test_timeout(self):
    """Ensures that `find_earliest_good_revision` stops after its deadline."""
    # Set up mock time such that we will time out after checking 3 revisions.
    mock_time = 0.

    def get_mock_time():
      nonlocal mock_time
      mock_time += 1.
      return mock_time

    self.mock.time.side_effect = get_mock_time
    deadline = 3.

    # All revisions being bad, we will iterate until we hit the deadline.
    self.reproduces_in_revision = lambda revision: (False, uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR))

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.find_earliest_good_revision(
        self.testcase, '/a/b', 'job_name', self.revision_list, None, deadline,
        regression_task_output)

    self.assertIsNotNone(result)
    self.assertEqual(result.error_type,
                     uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR)
    self.assertGreater(result.regression_task_output.last_regression_min, 1)


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

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    self.mock._testcase_reproduces_in_revision.return_value = False, None
    result = regression_task.validate_regression_range(
        testcase, '/a/b', 'job_type', [0], 0, regression_task_output, None)
    self.assertIsNone(result)

  def test_one_earlier_revision(self):
    """Test a corner-case with few revisions earlier than min revision."""
    testcase = data_types.Testcase()
    testcase.put()
    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    self.mock._testcase_reproduces_in_revision.return_value = False, None
    result = regression_task.validate_regression_range(
        testcase, '/a/b', 'job_type', [0, 1, 2], 1, regression_task_output,
        None)
    self.assertIsNone(result)

  def test_invalid_range(self):
    """Ensure that we handle invalid ranges correctly."""
    testcase = data_types.Testcase()
    testcase.put()

    self.mock._testcase_reproduces_in_revision.return_value = True, None
    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result = regression_task.validate_regression_range(
        testcase, '/a/b', 'job_type', [0, 1, 2, 3, 4], 4,
        regression_task_output, None)
    self.assertEqual(
        result.error_type,
        uworker_msg_pb2.REGRESSION_LOW_CONFIDENCE_IN_REGRESSION_RANGE)
    self.assertEqual(
        result.error_message,
        'Low confidence in regression range. Test case crashes in revision r0 but not later revision r4'
    )

  def test_valid_range(self):
    """Ensure that we handle valid ranges correctly."""
    testcase = data_types.Testcase()
    testcase.put()

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    self.mock._testcase_reproduces_in_revision.return_value = False, None
    result = regression_task.validate_regression_range(
        testcase, '/a/b', 'job_type', [0, 1, 2, 3, 4], 4,
        regression_task_output, None)
    self.assertIsNone(result)


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
    self.mock.preprocess_setup_testcase.return_value = uworker_msg_pb2.SetupInput(
        fuzzer_name=fuzzer_name)

    uworker_input = regression_task.utask_preprocess(testcase_id, job_type,
                                                     uworker_env)

    self.assertEqual(uworker_input.testcase_id, testcase_id)
    returned_testcase = uworker_io.entity_from_protobuf(uworker_input.testcase,
                                                        data_types.Testcase)
    self.assertEqual(returned_testcase.project_name, testcase.project_name)
    self.assertEqual(uworker_input.job_type, job_type)
    self.assertTrue(uworker_input.HasField('regression_task_input'))

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
    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        module_name=regression_task.__name__,
    )

    self.mock.setup_testcase.return_value = (
        None, None,
        uworker_msg_pb2.Output(
            error_type=uworker_msg_pb2.ErrorType.TESTCASE_SETUP))

    output = regression_task.utask_main(uworker_input)
    output.error_type = uworker_msg_pb2.ErrorType.TESTCASE_SETUP

  def test_empty_revision_list(self):
    """Verifies that if no good revisions can be found, the task fails."""
    testcase = test_utils.create_generic_testcase()
    bad_revisions = [1, 2, 3]
    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(
            bad_revisions=bad_revisions),
    )
    self.mock.setup_testcase.return_value = (None, None, None)
    # TODO: Set up environment more realistically and avoid mocking these out
    # entirely.
    self.mock.get_primary_bucket_path.return_value = 'gs://foo'
    self.mock.get_revisions_list.return_value = []

    output = regression_task.utask_main(uworker_input)

    self.mock.get_revisions_list.assert_called_once()
    self.assertEqual(output.error_type,
                     uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR)

  def test_min_revision_not_found(self):
    """Verifies that if the minimum revision in the regression range is not
    found, the task fails."""
    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('last_regression_min', 100)
    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    self.mock.setup_testcase.return_value = (None, None, None)
    self.mock.get_revisions_list.return_value = [101]

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_type,
                     uworker_msg_pb2.ErrorType.REGRESSION_BUILD_NOT_FOUND)
    self.assertEqual(output.error_message,
                     'Could not find good min revision <= 100.')

  def test_max_revision_not_found(self):
    """Verifies that if the maximum revision in the regression range is not
    found, the task fails."""
    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('last_regression_max', 101)
    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    self.mock.setup_testcase.return_value = (None, None, None)
    self.mock.get_revisions_list.return_value = [100]

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_type,
                     uworker_msg_pb2.ErrorType.REGRESSION_BUILD_NOT_FOUND)
    self.assertEqual(output.error_message,
                     'Could not find good max revision >= 101.')


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

    output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            testcase_id=str(testcase.key.id()),
            module_name=regression_task.__name__,
        ),
        error_type=uworker_msg_pb2.ErrorType.TESTCASE_SETUP)

    regression_task.utask_postprocess(output)

    # TODO: Set up environment more realistically and check `add_task()` args.
    self.mock.add_task.assert_called()

  def test_revision_list_error(self):
    """Verifies that if the task failed with `REGRESSION_REVISION_LIST_ERROR`,
    the testcase is updated to reflect that."""
    testcase = test_utils.create_generic_testcase()

    output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            testcase_id=str(testcase.key.id()),
            module_name=regression_task.__name__),
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR)

    regression_task.utask_postprocess(output)

    testcase = testcase.key.get()
    self.assertEqual(testcase.fixed, 'NA')
    self.assertRegex(testcase.comments, 'Failed to fetch revision list.$')

  def test_build_not_found_error(self):
    """Verifies that if the task failed with `REGRESSION_BUILD_NOT_FOUND_ERROR`,
    then the testcase is updated to reflect that regression failed."""
    testcase = test_utils.create_generic_testcase()

    output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            testcase_id=str(testcase.key.id()),
            module_name=regression_task.__name__),
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_BUILD_NOT_FOUND,
        error_message='foo')

    regression_task.utask_postprocess(output)

    testcase = testcase.key.get()
    self.assertEqual(testcase.regression, 'NA')
    self.assertRegex(testcase.comments, 'foo.$')

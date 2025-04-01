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
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
        'clusterfuzz._internal.bot.testcase_manager.check_for_bad_build',
    ])

  def test_error_on_failed_setup(self):
    """Ensure that we throw an exception if we fail to set up a build."""
    os.environ['APP_NAME'] = 'app_name'
    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    self.mock.setup_regular_build.return_value = False
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


class TestcaseReproducesInRevisionBadBuildTest(unittest.TestCase):
  """Test _testcase_reproduces_in_revision in case of bad builds.

     This is not part of TestcaseReproducesInRevisionTest because we need to
     exercise check_for_bad_build here.
  """

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.setup_regular_build',
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
    ])

  def test_bad_build_missing_app_error(self):
    """Tests _testcase_reproduces_in_revision behaviour on bad builds."""
    os.environ['APP_NAME'] = 'my_app'
    os.environ['APP_PATH'] = ''
    os.environ['BAD_BUILD_CHECK'] = 'True'
    build_data = uworker_msg_pb2.BuildData(
        revision=1,
        is_bad_build=True,
        should_ignore_crash_result=True,
        build_run_console_output='')
    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    result, worker_output = regression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
        None, '/tmp/blah', 'job_type', 1, regression_task_output, None)
    self.assertIsNone(result)
    self.assertEqual(worker_output.error_type,
                     uworker_msg_pb2.ErrorType.REGRESSION_BAD_BUILD_ERROR)
    self.assertEqual(len(regression_task_output.build_data_list), 1)
    self.assertEqual(regression_task_output.build_data_list[0], build_data)


@test_utils.with_cloud_emulators('datastore')
class TestFindMinRevision(unittest.TestCase):
  """Test find_min_revision."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.regression_task.save_regression_range',
        'clusterfuzz._internal.bot.tasks.utasks.regression_task._testcase_reproduces_in_revision',
        'time.time',
    ])

    self.mock_time = 0.
    self.mock.time.side_effect = lambda: self.mock_time

    self.deadline = 1.

    # Keep a dummy test case. Values are not important, but we need an id.
    self.testcase = data_types.Testcase()
    self.testcase.crash_revision = 128
    self.testcase.put()

    self.revision_list = list(range(2, 130, 2))  # [2, 4, 6, ..., 126, 128]
    self.reproduces_in_revision = lambda revision: (True, None)
    self.reproduces_calls = []
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
    self.reproduces_calls.append(revision)
    return self.reproduces_in_revision(revision)

  def test_regressed_at_min_revision(self):
    """Ensures that `find_min_revision` returns a result if we reproduce
    in the earliest revision.
    """
    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list,
        len(self.revision_list) - 1, regression_task_output)

    self.assertIsNone(min_index)
    self.assertIsNone(max_index)

    self.assertIsNotNone(output)
    self.assertEqual(output.regression_task_output.regression_range_start, 0)
    self.assertEqual(output.regression_task_output.regression_range_end, 2)

    self.assertEqual(self.reproduces_calls, [126, 124, 120, 112, 96, 64, 2])

  def test_regressed_at_min_good_revision(self):
    """Ensures that `find_min_revision` returns a result if we reproduce
    in the earliest good revision.
    """

    def repros(revision):
      if revision < 10:
        return False, uworker_msg_pb2.Output(
            error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)

      return True, None

    self.reproduces_in_revision = repros

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list,
        len(self.revision_list) - 1, regression_task_output)

    self.assertIsNone(min_index)
    self.assertIsNone(max_index)

    self.assertIsNotNone(output)
    self.assertEqual(output.regression_task_output.regression_range_start, 0)
    self.assertEqual(output.regression_task_output.regression_range_end, 10)

    self.assertEqual(self.reproduces_calls,
                     [126, 124, 120, 112, 96, 64, 2, 4, 6, 8, 10])

  def test_regressed_at_min_good_revision_with_min_revision(self):
    """Ensures that `find_min_revision` returns a result if we reproduce
    in the earliest good revision (with MIN_REVISION set).
    """
    os.environ['MIN_REVISION'] = '8'

    def repros(revision):
      if revision < 10:
        return False, uworker_msg_pb2.Output(
            error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)

      return True, None

    self.reproduces_in_revision = repros

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list,
        len(self.revision_list) - 1, regression_task_output)

    self.assertIsNone(min_index)
    self.assertIsNone(max_index)

    self.assertIsNotNone(output)
    self.assertEqual(output.regression_task_output.regression_range_start, 0)
    self.assertEqual(output.regression_task_output.regression_range_end, 10)

    self.assertEqual(self.reproduces_calls, [126, 124, 120, 112, 96, 64, 8, 10])

  def test_regressed_in_middle(self):
    """Ensures that `find_min_revision` finds a min revision that does not
    crash in the simple case when all revisions are good.
    """
    self.reproduces_in_revision = lambda revision: (revision > 64, None)

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list,
        len(self.revision_list) - 1, regression_task_output)

    self.assertIsNone(output)

    self.assertLess(min_index, max_index)
    min_revision = self.revision_list[min_index]
    max_revision = self.revision_list[max_index]

    self.assertEqual(max_revision, 96)
    self.assertEqual(min_revision, 64)

    self.assertEqual(regression_task_output.last_regression_min, min_revision)
    self.assertEqual(regression_task_output.last_regression_max, max_revision)

    self.assertEqual(self.reproduces_calls, [126, 124, 120, 112, 96, 64])

  def test_skips_bad_builds(self):
    """Ensures that `find_min_revision` skips over all bad builds. If all
    builds but the first one are bad, we still eventually get there.
    """

    def repros(revision):
      if revision == 2:
        return False, None

      return False, uworker_msg_pb2.Output(
          error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)

    self.reproduces_in_revision = repros

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    regression_task_output.last_regression_max = self.revision_list[-1]
    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list,
        len(self.revision_list) - 1, regression_task_output)

    self.assertIsNone(output)

    self.assertLess(min_index, max_index)
    min_revision = self.revision_list[min_index]
    max_revision = self.revision_list[max_index]

    self.assertEqual(min_revision, 2)
    self.assertEqual(max_revision, 128)

    self.assertEqual(regression_task_output.last_regression_min, 2)
    self.assertEqual(regression_task_output.last_regression_max, 128)

    # We try all revisions in reverse order.
    self.assertEqual(self.reproduces_calls, list(range(126, 0, -2)))

  def test_revisions_all_bad(self):
    """Ensures that `find_min_revision` identifies that the max
    revision caused a regression if all previous builds are bad.
    """
    self.reproduces_in_revision = lambda revision: (False, uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR))

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list,
        len(self.revision_list) - 1, regression_task_output)

    self.assertIsNone(min_index)
    self.assertIsNone(max_index)

    self.assertIsNotNone(output)
    self.assertEqual(output.regression_task_output.regression_range_start, 0)
    self.assertEqual(output.regression_task_output.regression_range_end, 128)

    # We try all revisions in reverse order.
    self.assertEqual(self.reproduces_calls, list(range(126, 0, -2)))

  def test_timeout(self):
    """Ensures that `find_min_revision` stops after its deadline."""

    # Set up mock time such that we will time out after checking 3 revisions.
    def get_mock_time():
      self.mock_time += 1.
      print(f'Advancing time to {self.mock_time}')
      return self.mock_time

    self.mock.time.side_effect = get_mock_time
    deadline = 3.

    # All revisions being bad, we will iterate until we hit the deadline.
    self.reproduces_in_revision = lambda revision: (False, uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR))

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    regression_task_output.last_regression_max = 128
    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, deadline, self.revision_list,
        len(self.revision_list) - 1, regression_task_output)

    self.assertIsNone(min_index)
    self.assertIsNone(max_index)

    self.assertIsNotNone(output)
    self.assertEqual(output.error_type,
                     uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR)
    self.assertEqual(
        output.error_message, 'Timed out searching for min revision. ' +
        'Current max: r128, next revision: r120')

    self.assertFalse(
        output.regression_task_output.HasField('last_regression_min'))
    self.assertEqual(output.regression_task_output.last_regression_max, 128)

    self.assertEqual(self.reproduces_calls, [126, 124, 122])

  def test_resume(self):
    """Ensures that `find_min_revision` can continue after a timeout."""
    self.reproduces_in_revision = lambda revision: (revision > 64, None)

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    regression_task_output.last_regression_max = 112

    max_index = 55
    self.assertEqual(self.revision_list[max_index], 112)

    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list, max_index, regression_task_output)

    self.assertIsNone(output)

    self.assertLess(min_index, max_index)
    min_revision = self.revision_list[min_index]
    max_revision = self.revision_list[max_index]

    self.assertEqual(min_revision, 64)
    self.assertEqual(max_revision, 96)

    self.assertEqual(regression_task_output.last_regression_min, min_revision)
    self.assertEqual(regression_task_output.last_regression_max, max_revision)

    # Exponentiation picks up where it left off.
    self.assertEqual(self.reproduces_calls, [96, 64])

  def test_missing_crash_revision(self):
    """Ensures that `find_min_revision` can make progress even if the crash
    revision is no longer available."""
    # Precondition for setup.
    self.assertEqual(self.testcase.crash_revision, 128)

    self.revision_list = list(range(2, 122, 2))
    self.reproduces_in_revision = lambda revision: (revision > 64, None)

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    regression_task_output.last_regression_max = 120
    self.assertEqual(self.revision_list[-1], 120)

    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list,
        len(self.revision_list) - 1, regression_task_output)

    self.assertIsNone(output)

    self.assertLess(min_index, max_index)
    min_revision = self.revision_list[min_index]
    max_revision = self.revision_list[max_index]

    self.assertEqual(min_revision, 56)
    self.assertEqual(max_revision, 88)

    self.assertEqual(regression_task_output.last_regression_min, min_revision)
    self.assertEqual(regression_task_output.last_regression_max, max_revision)

    # Exponentiation restarts from 120 with step size 1.
    self.assertEqual(self.reproduces_calls, [118, 116, 112, 104, 88, 56])

  def test_resume_missing_crash_revision(self):
    """Ensures that `find_min_revision` can resume execution even if the crash
    revision is no longer available."""
    # Precondition for setup.
    self.assertEqual(self.testcase.crash_revision, 128)

    self.revision_list = list(range(2, 122, 2))
    self.reproduces_in_revision = lambda revision: (revision > 64, None)

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    regression_task_output.last_regression_max = 112

    max_index = 55
    self.assertEqual(self.revision_list[max_index], 112)

    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list, max_index, regression_task_output)

    self.assertIsNone(output)

    self.assertLess(min_index, max_index)
    min_revision = self.revision_list[min_index]
    max_revision = self.revision_list[max_index]

    self.assertEqual(min_revision, 56)
    self.assertEqual(max_revision, 88)

    self.assertEqual(regression_task_output.last_regression_min, min_revision)
    self.assertEqual(regression_task_output.last_regression_max, max_revision)

    # Exponentiation continues assuming crash revision is 120, the maximum
    # revision in the list. 120 - 112 = 8, so the first try is 112 - 8 = 104.
    # Then 104 - 16 = 88, and 88 - 32 = 56.
    self.assertEqual(self.reproduces_calls, [104, 88, 56])

  def test_resume_from_higher_than_crash_revision(self):
    """Ensures that `find_min_revision` can resume execution even if the max
    revision given as input is higher than the crash revision (which must have
    gone missing during a previous execution, then resurfaced)."""
    self.reproduces_in_revision = lambda revision: (revision > 64, None)

    self.revision_list = list(range(2, 258, 2))

    regression_task_output = uworker_msg_pb2.RegressionTaskOutput()
    regression_task_output.last_regression_max = 256

    min_index, max_index, output = regression_task.find_min_revision(
        self.testcase, '/a/b', 'job_name', None, self.deadline,
        self.revision_list,
        len(self.revision_list) - 1, regression_task_output)

    self.assertIsNone(output)

    self.assertLess(min_index, max_index)
    min_revision = self.revision_list[min_index]
    max_revision = self.revision_list[max_index]

    self.assertEqual(min_revision, 64)
    self.assertEqual(max_revision, 96)

    self.assertEqual(regression_task_output.last_regression_min, min_revision)
    self.assertEqual(regression_task_output.last_regression_max, max_revision)

    # Exponentiation starts back from crash revision with step size 1.
    self.assertEqual(self.reproduces_calls, [126, 124, 120, 112, 96, 64])


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
        'clusterfuzz._internal.base.tasks.get_task_completion_deadline',
        'clusterfuzz._internal.bot.tasks.setup.setup_testcase',
        'clusterfuzz._internal.build_management.build_manager.get_primary_bucket_path',
        'clusterfuzz._internal.build_management.build_manager.get_revisions_list',
        'clusterfuzz._internal.bot.tasks.utasks.regression_task._testcase_reproduces_in_revision',
        'random.sample',
        'time.time',
    ])

    # Success by default.
    self.mock.setup_testcase.return_value = (None, "", None)

    self.reproduces_in_revision = lambda revision: (True, None)
    self.reproduces_calls = []
    self.mock._testcase_reproduces_in_revision.side_effect = (
        self._testcase_reproduces)

    # Timeout in secs.
    self.mock_time = 0.
    self.deadline = 1.

    self.mock.time.side_effect = lambda: self.mock_time
    self.mock.get_task_completion_deadline.side_effect = lambda: self.deadline

    # Makes `_validate_regresion_range` deterministic.
    self.mock.sample.side_effect = _sample

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
    self.reproduces_calls.append(revision)
    return self.reproduces_in_revision(revision)

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

    # TODO: Set up environment more realistically and avoid mocking these out
    # entirely.
    self.mock.get_primary_bucket_path.return_value = 'gs://foo'
    self.mock.get_revisions_list.return_value = []

    output = regression_task.utask_main(uworker_input)

    self.mock.get_revisions_list.assert_called_once()
    self.assertEqual(output.error_type,
                     uworker_msg_pb2.ErrorType.REGRESSION_REVISION_LIST_ERROR)

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

    self.mock.get_revisions_list.return_value = [100]

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_type,
                     uworker_msg_pb2.ErrorType.REGRESSION_BUILD_NOT_FOUND)
    self.assertEqual(output.error_message,
                     'Could not find good max revision >= 101.')

  def test_success(self):
    """Verifies that in the simple case where the testcase regressed once and
    in the absence of bad builds, the task identifies the regression range.
    """
    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100
    testcase.put()

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    self.mock.get_revisions_list.return_value = list(range(0, 102, 2))

    self.reproduces_in_revision = lambda revision: (revision > 50, None)

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_message, "")
    self.assertEqual(output.error_type, uworker_msg_pb2.ErrorType.NO_ERROR)

    self.assertEqual(output.regression_task_output.regression_range_start, 50)
    self.assertEqual(output.regression_task_output.regression_range_end, 52)

    self.assertEqual(
        self.reproduces_calls,
        # Check that the testcase still reproduces.
        [100] +
        # Search for min.
        [98, 96, 92, 84, 68, 36] +
        # Bisect.
        [52, 44, 48, 50] +
        # Validate regression range.
        [30, 32])

  def test_min_revision_not_found(self):
    """Verifies that if the minimum revision in the regression range is not
    found, the task restarts the search for a minimum revision."""
    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100  # put() called by set_metadata()
    testcase.set_metadata('last_regression_max', 100)
    testcase.set_metadata('last_regression_min', 10)

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    self.mock.get_revisions_list.return_value = list(range(20, 102, 2))

    self.reproduces_in_revision = lambda revision: (revision > 50, None)

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_message, "")
    self.assertEqual(output.error_type, uworker_msg_pb2.ErrorType.NO_ERROR)

    self.assertEqual(output.regression_task_output.regression_range_start, 50)
    self.assertEqual(output.regression_task_output.regression_range_end, 52)

  def test_timeout_immediate(self):
    """Verifies that regression task can time out before even starting the
    search for a min revision. This is just a special case of the search being
    interrupted midway.
    """
    # Deadline is already in the past.
    self.deadline = 0.
    self.mock_time = 1.

    self.mock.get_revisions_list.return_value = list(range(0, 102, 2))

    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_type,
                     uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR)
    self.assertEqual(
        output.error_message, 'Timed out searching for min revision. ' +
        'Current max: r100, next revision: r98')

    self.assertEqual(output.regression_task_output.last_regression_max, 100)
    self.assertFalse(
        output.regression_task_output.HasField('last_regression_min'))

  def test_timeout_min_search(self):
    """Verifies that regression task can time out during the search for a min
    revision.
    """
    self.mock.get_revisions_list.return_value = list(range(0, 102, 2))

    def repros(revision):
      # Time out after searching a few revision back.
      if revision < 95:
        self.mock_time = self.deadline + 1.

      return revision > 50, None

    self.reproduces_in_revision = repros

    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_type,
                     uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR)
    self.assertEqual(
        output.error_message, 'Timed out searching for min revision. ' +
        'Current max: r92, next revision: r84')

    # Keep these in sync with `test_resume_min_search` and
    # `UtaskPostprocessTest.test_timeout_min_search`.
    self.assertEqual(output.regression_task_output.last_regression_max, 92)
    self.assertFalse(
        output.regression_task_output.HasField('last_regression_min'))

  def test_resume_min_search(self):
    """Verifies that regression task can resume after a timed out search for
    a min revision.
    """
    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100

    # Pick up where `test_resume_min_search` left off.
    testcase.set_metadata('last_regression_max', 92)

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    self.mock.get_revisions_list.return_value = list(range(0, 102, 2))

    self.reproduces_in_revision = lambda revision: (revision > 50, None)

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_message, "")
    self.assertEqual(output.error_type, uworker_msg_pb2.ErrorType.NO_ERROR)

    self.assertEqual(output.regression_task_output.regression_range_start, 50)
    self.assertEqual(output.regression_task_output.regression_range_end, 52)

  def test_timeout_bisect(self):
    """Verifies that regression task can time out during bisection.
    """
    self.mock.get_revisions_list.return_value = list(range(0, 102, 2))

    def repros(revision):
      if revision < 50:
        # Time out after finding the min revision.
        self.mock_time = self.deadline + 1.
        return False, None

      return True, None

    self.reproduces_in_revision = repros

    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_type,
                     uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR)
    self.assertEqual(output.error_message, 'Timed out, current range r36:r68')

    # Keep these in sync with `test_resume_bisect` and
    # `test_timeout_restart_min_search`.
    self.assertEqual(output.regression_task_output.last_regression_max, 68)
    self.assertEqual(output.regression_task_output.last_regression_min, 36)

  def test_resume_bisect(self):
    """Verifies that regression task can resume after a timed out bisection.
    """
    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100

    # Pick up where `test_timeout_bisect` left off.
    testcase.set_metadata('last_regression_max', 68)
    testcase.set_metadata('last_regression_min', 36)

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    self.mock.get_revisions_list.return_value = list(range(0, 102, 2))

    self.reproduces_in_revision = lambda revision: (revision > 50, None)

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_message, "")
    self.assertEqual(output.error_type, uworker_msg_pb2.ErrorType.NO_ERROR)

    self.assertEqual(output.regression_task_output.regression_range_start, 50)
    self.assertEqual(output.regression_task_output.regression_range_end, 52)

  def test_timeout_restart_min_search(self):
    """Verifies that regression task can time out during the search for a min
    revision for the second time.
    """

    # We had previously found 36 to be a good revision, but it no longer exists,
    # nor do any earlier revisions.
    self.mock.get_revisions_list.return_value = list(range(40, 102, 2))

    def repros(revision):
      # Time out before finding the min revision.
      self.mock_time = self.deadline + 1.
      return revision > 50, None

    self.reproduces_in_revision = repros

    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100

    # Pick up where `test_timeout_bisect` left off.
    testcase.set_metadata('last_regression_max', 68)
    testcase.set_metadata('last_regression_min', 36)

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_type,
                     uworker_msg_pb2.REGRESSION_TIMEOUT_ERROR)

    # Keep these in sync with
    # `UtaskPostprocessTest.test_timeout_restart_min_search`.
    self.assertEqual(output.regression_task_output.last_regression_max, 68)
    self.assertFalse(
        output.regression_task_output.HasField('last_regression_min'))

  def test_skips_bad_builds(self):
    """Verifies that regression task can succeed even if most builds are bad.
    """
    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    self.mock.get_revisions_list.return_value = list(range(0, 102, 2))

    def reproduces(revision):
      if revision == 100:
        return True, None
      if revision == 50:
        return False, None

      # Literally ever other build is bad.
      return False, uworker_msg_pb2.Output(
          error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)

    self.reproduces_in_revision = reproduces

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_message, "")
    self.assertEqual(output.error_type, uworker_msg_pb2.ErrorType.NO_ERROR)

    self.assertEqual(output.regression_task_output.regression_range_start, 50)
    self.assertEqual(output.regression_task_output.regression_range_end, 100)

  def test_timeout_bisect_no_progress(self):
    """Verifies that bisection without progress will terminate."""
    self.mock.get_revisions_list.return_value = list(range(0, 102, 2))
    self.deadline = 5.

    def repros(revision):
      self.mock_time += 1.

      if revision < 68:
        # Let every revision except the max revision have bad build errors.
        return False, uworker_msg_pb2.Output(
            error_type=uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)
      return True, None

    self.reproduces_in_revision = repros

    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100

    # Pick up an unfinished task.
    testcase.set_metadata('last_regression_max', 68)
    testcase.set_metadata('last_regression_min', 36)

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_type,
                     uworker_msg_pb2.REGRESSION_BAD_BUILD_ERROR)

    # The task made no progress.
    self.assertEqual(output.regression_task_output.last_regression_max, 68)
    self.assertEqual(output.regression_task_output.last_regression_min, 36)

  def test_inconsistent_state_max_none_min_not_none(self):
    """Verifies that when last_regression_max is None and last_regression_min
    is not None, we ignore the latter and restart from scratch."""
    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 100
    testcase.put()

    # `last_regression_max` is missing, but min is not, unexpectedly.
    testcase.set_metadata('last_regression_min', 50)

    # Time out immediately so that we can observe that `last_regression_min`
    # was ignored.
    self.deadline = 0.
    self.mock_time = 1.

    uworker_input = uworker_msg_pb2.Input(
        testcase_id=str(testcase.key.id()),
        testcase=uworker_io.entity_to_protobuf(testcase),
        job_type='foo-job',
        setup_input=uworker_msg_pb2.SetupInput(),
        regression_task_input=uworker_msg_pb2.RegressionTaskInput(),
    )

    self.mock.get_revisions_list.return_value = list(range(0, 102, 2))

    output = regression_task.utask_main(uworker_input)

    self.assertEqual(output.error_type,
                     uworker_msg_pb2.ErrorType.REGRESSION_TIMEOUT_ERROR)

    # State invariants restored, will be fixed in testcase in postprocess.
    self.assertEqual(output.regression_task_output.last_regression_max, 100)
    self.assertFalse(
        output.regression_task_output.HasField('last_regression_min'))


@test_utils.with_cloud_emulators('datastore')
class UtaskPostprocessTest(unittest.TestCase):
  """Test regression_task.utask_postprocess."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
        'clusterfuzz._internal.bot.tasks.task_creation.create_blame_task_if_needed',
        'clusterfuzz._internal.bot.tasks.task_creation.create_impact_task_if_needed',
        'clusterfuzz._internal.google_cloud_utils.big_query.write_range',
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

  def test_timeout_min_search(self):
    """Verifies that if the task timed out while searching for the min revision,
    we reschedule it."""
    testcase = test_utils.create_generic_testcase()
    testcase_id = str(testcase.key.id())

    # Output of `UtaskMainTest.test_timeout_min_search`.
    output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            testcase_id=testcase_id,
            module_name=regression_task.__name__,
            job_type='foo_job',
        ),
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_TIMEOUT_ERROR,
        error_message='foo error',
        regression_task_output=uworker_msg_pb2.RegressionTaskOutput(
            last_regression_max=92,),
    )

    regression_task.utask_postprocess(output)

    testcase = testcase.key.get()
    self.assertEqual(testcase.regression, '')
    self.assertRegex(testcase.comments, 'foo error.$')

    self.assertEqual(testcase.get_metadata('last_regression_max'), 92)
    self.assertIsNone(testcase.get_metadata('last_regression_min'))

    self.mock.add_task.assert_called_once_with('regression', testcase_id,
                                               'foo_job')

    self.mock.write_range.assert_not_called()
    self.mock.create_blame_task_if_needed.assert_not_called()
    self.mock.create_impact_task_if_needed.assert_not_called()

  def test_timeout_restart_min_search(self):
    """Verifies that if the task timed out while searching for the min revision
    for the second time, we reschedule it."""
    testcase = test_utils.create_generic_testcase()
    testcase_id = str(testcase.key.id())

    # Input of `UtaskMainTest.test_timeout_restart_min_search`.
    testcase.set_metadata('last_regression_max', 68)
    testcase.set_metadata('last_regression_min', 36)

    # Output of `UtaskMainTest.test_timeout_restart_min_search`.
    output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            testcase_id=testcase_id,
            module_name=regression_task.__name__,
            job_type='foo_job',
        ),
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_TIMEOUT_ERROR,
        error_message='foo error',
        regression_task_output=uworker_msg_pb2.RegressionTaskOutput(
            last_regression_max=68,),
    )

    regression_task.utask_postprocess(output)

    testcase = testcase.key.get()
    self.assertEqual(testcase.regression, '')
    self.assertRegex(testcase.comments, 'foo error.$')

    self.assertEqual(testcase.get_metadata('last_regression_max'), 68)
    self.assertIsNone(testcase.get_metadata('last_regression_min'))

    self.mock.add_task.assert_called_once_with('regression', testcase_id,
                                               'foo_job')

    self.mock.write_range.assert_not_called()
    self.mock.create_blame_task_if_needed.assert_not_called()
    self.mock.create_impact_task_if_needed.assert_not_called()

  def test_timeout_bisect(self):
    """Verifies that if the task timed out while bisecting, we reschedule it."""
    testcase = test_utils.create_generic_testcase()
    testcase_id = str(testcase.key.id())

    # Output of `UtaskMainTest.test_timeout_bisect`.
    output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            testcase_id=testcase_id,
            module_name=regression_task.__name__,
            job_type='foo_job',
        ),
        error_type=uworker_msg_pb2.ErrorType.REGRESSION_TIMEOUT_ERROR,
        error_message='foo error',
        regression_task_output=uworker_msg_pb2.RegressionTaskOutput(
            last_regression_max=68,
            last_regression_min=36,
        ),
    )

    regression_task.utask_postprocess(output)

    testcase = testcase.key.get()
    self.assertEqual(testcase.regression, '')
    self.assertRegex(testcase.comments, 'foo error.$')

    self.assertEqual(testcase.get_metadata('last_regression_max'), 68)
    self.assertEqual(testcase.get_metadata('last_regression_min'), 36)

    self.mock.add_task.assert_called_once_with('regression', testcase_id,
                                               'foo_job')

    self.mock.write_range.assert_not_called()
    self.mock.create_blame_task_if_needed.assert_not_called()
    self.mock.create_impact_task_if_needed.assert_not_called()

  def test_success(self):
    """Verifies that if the task succeeded, we store the regression range."""
    testcase = test_utils.create_generic_testcase()

    output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            testcase_id=str(testcase.key.id()),
            module_name=regression_task.__name__),
        error_type=uworker_msg_pb2.ErrorType.NO_ERROR,
        regression_task_output=uworker_msg_pb2.RegressionTaskOutput(
            regression_range_start=13,
            regression_range_end=37,
            last_regression_min=12,
            last_regression_max=38,
        ),
    )

    regression_task.utask_postprocess(output)

    testcase = testcase.key.get()
    self.assertEqual(testcase.regression, '13:37')
    self.assertRegex(testcase.comments, 'regressed in range 13:37.$')

    self.assertEqual(testcase.get_metadata('last_regression_min'), 12)
    self.assertEqual(testcase.get_metadata('last_regression_max'), 38)

    self.mock.write_range.assert_called()

    self.mock.create_blame_task_if_needed.assert_called()
    self.mock.create_impact_task_if_needed.assert_called()

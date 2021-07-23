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
from clusterfuzz._internal.bot.tasks import regression_task
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
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
        'clusterfuzz._internal.bot.tasks.regression_task.save_regression_range',
        'clusterfuzz._internal.bot.tasks.regression_task._testcase_reproduces_in_revision',
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
        'clusterfuzz._internal.bot.tasks.regression_task._testcase_reproduces_in_revision',
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

    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    self.assertEqual(testcase.regression, 'NA')

  def test_valid_range(self):
    """Ensure that we handle valid ranges correctly."""
    testcase = data_types.Testcase()
    testcase.put()

    self.mock._testcase_reproduces_in_revision.return_value = False
    result = regression_task.validate_regression_range(
        testcase, '/a/b', 'job_type', [0, 1, 2, 3, 4], 4)
    self.assertTrue(result)

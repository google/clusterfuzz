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

import unittest

from base import errors
from bot.tasks import progression_task
from datastore import data_types
from tests.test_libs import helpers


class WriteToBigqueryTest(unittest.TestCase):
  """Test _write_to_big_query."""

  def setUp(self):
    helpers.patch(self, [
        'google_cloud_utils.big_query.write_range',
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
        'build_management.build_manager.setup_regular_build',
        'fuzzing.tests.test_for_crash_with_retries',
        'fuzzing.tests.check_for_bad_build',
    ])

  def test_error_on_failed_setup(self):
    """Ensure that we throw an exception if we fail to set up a build."""
    # No need to implement a fake setup_regular_build. Since it's doing nothing,
    # we won't have the build directory properly set.
    with self.assertRaises(errors.BuildSetupError):
      progression_task._testcase_reproduces_in_revision(  # pylint: disable=protected-access
          None, '/tmp/blah', 'job_type', 1)

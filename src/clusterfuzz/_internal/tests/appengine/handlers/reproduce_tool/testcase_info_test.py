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
"""Tests for the reproduce tool testcase_info handler."""
# pylint: disable=protected-access

import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.reproduce_tool import testcase_info


@test_utils.with_cloud_emulators('datastore')
class PrepareTestcaseDictTest(unittest.TestCase):
  """Tests for _prepare_testcase_dict."""

  def setUp(self):
    job = data_types.Job(name='test_job', environment_string='X = 1\nY = 2\n')
    job.put()

    testcase = data_types.Testcase()
    testcase.status = 'Pending'
    testcase.open = True
    testcase.job_type = 'test_job'
    testcase.put()

    self.testcase = testcase

  def test_expected_properties_included(self):
    """Ensure that a few of the common test case properties are included."""
    result = testcase_info._prepare_testcase_dict(self.testcase)
    self.assertEqual(result['status'], 'Pending')
    self.assertEqual(result['open'], True)
    self.assertEqual(result['group_id'], 0)

  def test_job_included(self):
    """Ensure that the job definition has been included."""
    result = testcase_info._prepare_testcase_dict(self.testcase)
    job_definition = result['job_definition']

    # Order is not necessarily preserved.
    self.assertIn('X = 1\n', job_definition)
    self.assertIn('Y = 2\n', job_definition)

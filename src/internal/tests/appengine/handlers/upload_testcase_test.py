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
"""Tests for upload_testcase."""

import unittest

from internal.datastore import data_types
from handlers import upload_testcase
from libs import helpers
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class FindFuzzTargetTest(unittest.TestCase):
  """Tests for find_fuzz_target."""

  def setUp(self):
    test_helpers.patch_environ(self)

    data_types.FuzzTarget(
        engine='libFuzzer', project='test-project', binary='binary').put()

    data_types.FuzzTarget(
        engine='libFuzzer', project='proj', binary='binary').put()

  def test_without_project_prefix(self):
    """Test find_fuzz_target with a target_name that isn't prefixed with the
    project."""
    data_types.Job(name='job', environment_string='PROJECT_NAME = proj\n').put()
    self.assertEqual(('libFuzzer_proj_binary', 'binary'),
                     upload_testcase.find_fuzz_target('libFuzzer', 'binary',
                                                      'job'))

  def test_with_project_prefix(self):
    """Test find_fuzz_target with a target_name that is prefixed with the
    project."""
    data_types.Job(name='job', environment_string='PROJECT_NAME = proj\n').put()
    self.assertEqual(('libFuzzer_proj_binary', 'binary'),
                     upload_testcase.find_fuzz_target('libFuzzer',
                                                      'proj_binary', 'job'))

  def test_with_main_project(self):
    """Test find_fuzz_target with a target in the main project."""
    data_types.Job(name='job', environment_string='').put()
    self.assertEqual(('libFuzzer_binary', 'binary'),
                     upload_testcase.find_fuzz_target('libFuzzer', 'binary',
                                                      'job'))

  def test_not_found(self):
    """Test target not found."""
    data_types.Job(name='job', environment_string='').put()
    with self.assertRaises(helpers.EarlyExitException):
      self.assertEqual((None, None),
                       upload_testcase.find_fuzz_target('libFuzzer', 'notfound',
                                                        'job'))

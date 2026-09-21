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
"""Tests for task_creation."""

import unittest

from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class CreateTasksTest(unittest.TestCase):
  """Tests for create_tasks."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.task_creation.create_minimize_task_if_needed',
        'clusterfuzz._internal.bot.tasks.task_creation.create_postminimize_tasks',
        'clusterfuzz._internal.system.environment.is_minimization_supported',
    ])
    self.mock.is_minimization_supported.return_value = True

  def test_create_tasks_skip_minimization(self):
    """Test create_tasks with skip_minimization metadata."""
    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('skip_minimization', True)
    task_creation.create_tasks(testcase)

    testcase = testcase.key.get()
    self.assertEqual(testcase.minimized_keys, 'NA')
    self.assertFalse(self.mock.create_minimize_task_if_needed.called)
    self.assertTrue(self.mock.create_postminimize_tasks.called)

  def test_create_tasks_no_skip_minimization(self):
    """Test create_tasks without skip_minimization metadata."""
    testcase = test_utils.create_generic_testcase()
    task_creation.create_tasks(testcase)

    testcase = testcase.key.get()
    self.assertNotEqual(testcase.minimized_keys, 'NA')
    self.assertTrue(self.mock.create_minimize_task_if_needed.called)
    self.assertFalse(self.mock.create_postminimize_tasks.called)

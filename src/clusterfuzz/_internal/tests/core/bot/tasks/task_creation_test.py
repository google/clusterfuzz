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
from clusterfuzz._internal.datastore import data_types
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


@test_utils.with_cloud_emulators('datastore')
class SwarmingTaskCreationTest(unittest.TestCase):
  """Tests for Swarming task creation and TrustedTask gating."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
        'clusterfuzz._internal.base.utils.is_chromium',
        'clusterfuzz._internal.build_management.build_manager.is_custom_binary',
        'clusterfuzz._internal.build_management.build_manager.has_symbolized_builds',
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
    ])
    self.mock.is_chromium.return_value = True
    self.mock.is_custom_binary.return_value = False
    self.mock.has_symbolized_builds.return_value = False
    self.mock.is_remotely_executing_utasks.return_value = True

    data_types.FeatureFlag(id='swarming_remote_execution', enabled=True).put()
    data_types.Job(
        name='swarming_asan',
        platform='ANDROID_EMULATOR',
        project='chromium',
        environment_string='IS_SWARMING_JOB = True\nPROJECT_NAME = chromium\n'
    ).put()
    data_types.Job(
        name='swarming_ubsan',
        platform='ANDROID_EMULATOR',
        project='chromium',
        environment_string='IS_SWARMING_JOB = True\nPROJECT_NAME = chromium\n'
    ).put()
    data_types.Fuzzer(
        name='libFuzzer', jobs=['swarming_asan', 'swarming_ubsan']).put()

    self.testcase = test_utils.create_generic_testcase()
    self.testcase.job_type = 'swarming_asan'
    self.testcase.project_name = 'chromium'
    self.testcase.fuzzer_name = 'libFuzzer'
    self.testcase.regression = '100:200'
    self.testcase.trusted = False
    self.testcase.put()

  def test_skips_blame_and_impact_for_swarming_job(self):
    """Tests that blame and impact tasks are skipped for Swarming jobs."""
    task_creation.create_blame_task_if_needed(self.testcase)
    task_creation.create_impact_task_if_needed(self.testcase)
    self.mock.add_task.assert_not_called()

  def test_variant_routes_untrusted_swarming_job_to_preprocess_swarming(self):
    """Tests that untrusted Swarming variant tasks route to preprocess-swarming."""
    task_creation.create_variant_tasks_if_needed(self.testcase)
    self.mock.add_task.assert_called_once_with(
        'variant', self.testcase.key.id(), 'swarming_ubsan',
        'preprocess-swarming')

  def test_disabled_feature_flag_preserves_non_swarming_behavior(self):
    """Tests that disabling SWARMING_REMOTE_EXECUTION blocks untrusted variants
    from privileged queues and allows blame/impact on regular queues."""
    data_types.FeatureFlag(id='swarming_remote_execution', enabled=False).put()

    task_creation.create_variant_tasks_if_needed(self.testcase)
    self.mock.add_task.assert_not_called()

    task_creation.create_blame_task_if_needed(self.testcase)
    task_creation.create_impact_task_if_needed(self.testcase)
    self.assertEqual(2, self.mock.add_task.call_count)

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
  """Tests for blame, impact, and variant task creation on Swarming jobs."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
        'clusterfuzz._internal.base.tasks.task_utils.is_remotely_executing_utasks',
        'clusterfuzz._internal.base.utils.is_chromium',
        'clusterfuzz._internal.build_management.build_manager.has_symbolized_builds',
        'clusterfuzz._internal.build_management.build_manager.is_custom_binary',
    ])
    self.mock.is_chromium.return_value = True
    self.mock.is_custom_binary.return_value = False
    self.mock.has_symbolized_builds.return_value = False
    self.mock.is_remotely_executing_utasks.return_value = True

    data_types.Job(
        name='linux_asan_chrome',
        platform='LINUX',
        project='chromium',
        environment_string='PROJECT_NAME = chromium\n').put()
    data_types.Job(
        name='android_emu_swarming',
        platform='ANDROID_EMULATOR',
        project='chromium',
        environment_string=(
            'PROJECT_NAME = chromium\nIS_SWARMING_JOB = True\n')).put()

    self.testcase = test_utils.create_generic_testcase()
    self.testcase.job_type = 'android_emu_swarming'
    self.testcase.project_name = 'chromium'
    self.testcase.regression = '100:200'
    self.testcase.trusted = False
    self.testcase.put()

  def _set_swarming_flag(self, enabled):
    data_types.FeatureFlag(
        id='swarming_remote_execution', enabled=enabled).put()

  def test_skips_blame_and_impact_when_swarming_enabled(self):
    """Tests that blame and impact tasks are skipped for Swarming jobs when
    SWARMING_REMOTE_EXECUTION is enabled."""
    self._set_swarming_flag(True)

    task_creation.create_blame_task_if_needed(self.testcase)
    task_creation.create_impact_task_if_needed(self.testcase)
    self.mock.add_task.assert_not_called()

  def test_creates_blame_and_impact_when_swarming_disabled(self):
    """Tests that blame and impact tasks are still created for Swarming jobs
    when SWARMING_REMOTE_EXECUTION is disabled."""
    self._set_swarming_flag(False)

    task_creation.create_blame_task_if_needed(self.testcase)
    task_creation.create_impact_task_if_needed(self.testcase)
    self.assertEqual([call[0][0] for call in self.mock.add_task.call_args_list],
                     ['blame', 'impact'])

  def test_skips_variant_for_untrusted_testcase_on_swarming_job(self):
    """Tests that untrusted testcases don't get variant tasks on Swarming jobs,
    since Swarming can't run untrusted workloads."""
    linux_testcase = test_utils.create_generic_testcase()
    linux_testcase.job_type = 'linux_asan_chrome'
    linux_testcase.project_name = 'chromium'
    linux_testcase.trusted = False
    linux_testcase.put()

    task_creation.create_variant_tasks_if_needed(linux_testcase)
    self.mock.add_task.assert_not_called()

  def test_creates_variant_for_trusted_testcase_on_swarming_job(self):
    """Tests that trusted testcases still get variant tasks on Swarming jobs."""
    linux_testcase = test_utils.create_generic_testcase()
    linux_testcase.job_type = 'linux_asan_chrome'
    linux_testcase.project_name = 'chromium'
    linux_testcase.trusted = True
    linux_testcase.put()

    task_creation.create_variant_tasks_if_needed(linux_testcase)
    self.mock.add_task.assert_called_once_with(
        'variant', linux_testcase.key.id(), 'android_emu_swarming',
        'jobs-android-emulator')

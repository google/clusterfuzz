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
"""Tests for app specific trials and experiments."""

import unittest

from bot.tasks import trials
from datastore import data_types
from system import environment
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class TrialsTest(unittest.TestCase):
  """Tests for trials."""

  def setUp(self):
    test_helpers.patch_environ(self, env={'APP_ARGS': '--dummy'})

    data_types.Trial(app_name='app_1', probability=0.5, app_args='--a1').put()

    data_types.Trial(app_name='app_2', probability=0.4, app_args='--a2').put()
    data_types.Trial(app_name='app_2', probability=0.2, app_args='--b2').put()

    data_types.Trial(app_name='app_3', probability=1.0, app_args='--a3').put()

    test_helpers.patch(self, ['bot.tasks.trials.select_trial'])

  def test_no_effect_on_no_match(self):
    """Ensure that no additional flags are added if a binary has no trials."""
    self.mock.select_trial.side_effect = lambda q: None
    environment.set_value('APP_NAME', 'app_0')
    trials.setup_additional_args_for_app()
    self.assertEqual(environment.get_value('APP_ARGS'), '--dummy')
    self.assertIsNone(environment.get_value('TRIAL_APP_ARGS'))

  def test_trial_selected_one_option(self):
    """Ensure that the expected flags are added if a trial is selected."""
    self.mock.select_trial.side_effect = lambda q: q.fetch(100)[0]
    environment.set_value('APP_NAME', 'app_1')
    trials.setup_additional_args_for_app()
    self.assertEqual(environment.get_value('APP_ARGS'), '--dummy --a1')
    self.assertEqual(environment.get_value('TRIAL_APP_ARGS'), '--a1')

  def test_trial_not_selected_one_option(self):
    """Ensure that no additional flags a trial was not selected."""
    self.mock.select_trial.side_effect = lambda q: None
    environment.set_value('APP_NAME', 'app_1')
    self.assertEqual(environment.get_value('APP_ARGS'), '--dummy')
    self.assertIsNone(environment.get_value('TRIAL_APP_ARGS'))

  def test_multiple_trial_selection(self):
    """Ensure that we can suggest the second trial in a batch of multiple."""
    self.mock.select_trial.side_effect = lambda q: q.fetch(100)[1]
    environment.set_value('APP_NAME', 'app_2')
    trials.setup_additional_args_for_app()
    self.assertEqual(environment.get_value('APP_ARGS'), '--dummy --b2')
    self.assertEqual(environment.get_value('TRIAL_APP_ARGS'), '--b2')

  def test_selection_for_windows_executable(self):
    """Ensure that flags are added when the app name ends in ".exe"."""
    self.mock.select_trial.side_effect = lambda q: q.get()
    environment.set_value('APP_NAME', 'app_3.exe')
    trials.setup_additional_args_for_app()
    self.assertEqual(environment.get_value('APP_ARGS'), '--dummy --a3')
    self.assertEqual(environment.get_value('TRIAL_APP_ARGS'), '--a3')

  def test_selection_for_android_apk(self):
    """Ensure that flags are added for the Android APK format."""
    self.mock.select_trial.side_effect = lambda q: q.get()
    environment.set_value('APP_NAME', 'App_3.apk')
    trials.setup_additional_args_for_app()
    self.assertEqual(environment.get_value('APP_ARGS'), '--dummy --a3')
    self.assertEqual(environment.get_value('TRIAL_APP_ARGS'), '--a3')


class SelectTrialTest(unittest.TestCase):
  """Tests for select_trial."""

  def setUp(self):
    test_helpers.patch(self, ['random.random'])

  def test_select_trial_empty_list(self):
    """Ensure that select_trial returns None for the empty list."""
    self.assertIsNone(trials.select_trial([]))

  def test_select_trial_not_selected(self):
    """Ensure that we return None if we did not randomly select a trial."""
    self.mock.random.return_value = 0.5
    trial = data_types.Trial(probability=0.5)
    self.assertIsNone(trials.select_trial([trial]))

  def test_select_trial_single_item(self):
    """Ensure that we return a Trial if we select one."""
    self.mock.random.return_value = 0.0
    trial = data_types.Trial(probability=0.5)
    self.assertEqual(trials.select_trial([trial]), trial)

  def test_select_trial_multiple_items(self):
    """Ensure that we can select a Trial from a list of multiple."""
    self.mock.random.return_value = 0.5
    trial_1 = data_types.Trial(probability=0.5)
    trial_2 = data_types.Trial(probability=0.3)
    self.assertEqual(trials.select_trial([trial_1, trial_2]), trial_2)

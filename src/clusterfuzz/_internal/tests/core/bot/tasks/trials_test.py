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

import json

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.bot.tasks import trials
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class TrialsTest(fake_filesystem_unittest.TestCase):
  """Tests for trials."""

  def setUp(self):
    environment.set_value('APP_DIR', '/src')
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch_environ(self, env={'APP_ARGS': '-x'})

    data_types.Trial(app_name='app_1', probability=0.5, app_args='--a1').put()

    data_types.Trial(app_name='app_2', probability=0.4, app_args='--b1').put()
    data_types.Trial(app_name='app_2', probability=0.2, app_args='--b2').put()

    data_types.Trial(app_name='app_3', probability=1.0, app_args='--c1').put()
    data_types.Trial(app_name='app_3', probability=0.2, app_args='--c2').put()
    data_types.Trial(app_name='app_3', probability=0.2, app_args='--c3').put()

    test_helpers.patch(self, ['random.random'])

  def source_side_test(self, config_file_content, probability, app_name,
                       app_args, trial_app_args):
    """Source side trials test template."""
    self.fs.create_file('/src/clusterfuzz_trials_config.json')

    with open('/src/clusterfuzz_trials_config.json', 'w') as f:
      f.write(json.dumps(config_file_content))

    self.mock.random.return_value = probability
    environment.set_value('APP_NAME', app_name)
    trial_selector = trials.Trials()
    trial_selector.setup_additional_args_for_app(shuffle=False)
    self.assertEqual(environment.get_value('APP_ARGS'), app_args)
    self.assertEqual(environment.get_value('TRIAL_APP_ARGS'), trial_app_args)

  def test_no_effect_on_no_match(self):
    """Ensure that no additional flags are added if a binary has no trials."""
    self.mock.random.return_value = 0.0
    environment.set_value('APP_NAME', 'app_0')
    trial_selector = trials.Trials()
    trial_selector.setup_additional_args_for_app(shuffle=False)
    self.assertEqual(environment.get_value('APP_ARGS'), '-x')
    self.assertIsNone(environment.get_value('TRIAL_APP_ARGS'))

  def test_trial_selected_one_option(self):
    """Ensure that the expected flags are added if a trial is selected."""
    self.mock.random.return_value = 0.3
    environment.set_value('APP_NAME', 'app_1')
    trial_selector = trials.Trials()
    trial_selector.setup_additional_args_for_app(shuffle=False)
    self.assertEqual(environment.get_value('APP_ARGS'), '-x --a1')
    self.assertEqual(environment.get_value('TRIAL_APP_ARGS'), '--a1')

  def test_trial_not_selected(self):
    """Ensure no additional flags if a trial was not selected."""
    self.mock.random.return_value = 0.5
    environment.set_value('APP_NAME', 'app_2')
    trial_selector = trials.Trials()
    trial_selector.setup_additional_args_for_app(shuffle=False)
    self.assertEqual(environment.get_value('APP_ARGS'), '-x')
    self.assertIsNone(environment.get_value('TRIAL_APP_ARGS'))

  def test_multiple_trial_selection(self):
    """Ensure that we can suggest the second trial in a batch of multiple."""
    self.mock.random.return_value = 0.1
    environment.set_value('APP_NAME', 'app_3')
    trial_selector = trials.Trials()
    trial_selector.setup_additional_args_for_app(shuffle=False)
    self.assertEqual(environment.get_value('APP_ARGS'), '-x --c1 --c2 --c3')
    self.assertEqual(environment.get_value('TRIAL_APP_ARGS'), '--c1 --c2 --c3')

  def test_selection_for_windows_executable(self):
    """Ensure that flags are added when the app name ends in ".exe"."""
    self.mock.random.return_value = 0.3
    environment.set_value('APP_NAME', 'app_1.exe')
    trial_selector = trials.Trials()
    trial_selector.setup_additional_args_for_app(shuffle=False)
    self.assertEqual(environment.get_value('APP_ARGS'), '-x --a1')
    self.assertEqual(environment.get_value('TRIAL_APP_ARGS'), '--a1')

  def test_selection_for_android_apk(self):
    """Ensure that flags are added for the Android APK format."""
    self.mock.random.return_value = 0.3
    environment.set_value('APP_NAME', 'App_1.apk')
    trial_selector = trials.Trials()
    trial_selector.setup_additional_args_for_app(shuffle=False)
    self.assertEqual(environment.get_value('APP_ARGS'), '-x --a1')
    self.assertEqual(environment.get_value('TRIAL_APP_ARGS'), '--a1')

  def test_no_effect_on_no_match_source_side(self):
    """Ensure that no additional flags are added if a binary has no trials on source side."""
    config_file_content = [{
        "app_args": "--c4",
        "app_name": "app_4",
        "probability": 0.2
    }]
    self.source_side_test(config_file_content, 0.0, 'app_0', '-x', None)

  def test_trial_selected_one_option_source_side(self):
    """Ensure that the expected flags are added if a trial is selected on source side."""
    config_file_content = [{
        "app_args": "--c4",
        "app_name": "app_4",
        "probability": 0.5
    }]
    self.source_side_test(config_file_content, 0.3, 'app_4', '-x --c4', '--c4')

  def test_trial_not_selected_source_side(self):
    """Ensure no additional flags if a trial was not selected on source side."""
    config_file_content = [{
        "app_args": "--c4",
        "app_name": "app_4",
        "probability": 0.4
    }, {
        "app_args": "--c5",
        "app_name": "app_4",
        "probability": 0.2
    }]
    self.source_side_test(config_file_content, 0.5, 'app_4', '-x', None)

  def test_multiple_trial_selection_source_side(self):
    """Ensure that we can suggest the second trial in a batch of multiple on source side."""
    config_file_content = [{
        "app_args": "--c4",
        "app_name": "app_4",
        "probability": 1.0
    }, {
        "app_args": "--c5",
        "app_name": "app_4",
        "probability": 0.2
    }, {
        "app_args": "--c6",
        "app_name": "app_4",
        "probability": 0.2
    }]
    self.source_side_test(config_file_content, 0.1, 'app_4',
                          '-x --c4 --c5 --c6', '--c4 --c5 --c6')

  def test_selection_for_windows_executable_source_side(self):
    """Ensure that flags are added when the app name ends in ".exe" on source side."""
    config_file_content = [{
        "app_args": "--c4",
        "app_name": "app_4",
        "probability": 1.0
    }]
    self.source_side_test(config_file_content, 0.3, 'app_4.exe', '-x --c4',
                          '--c4')

  def test_selection_for_android_apk_source_side(self):
    """Ensure that flags are added for the Android APK format on source side."""
    config_file_content = [{
        "app_args": "--c4",
        "app_name": "app_4",
        "probability": 1.0
    }]
    self.source_side_test(config_file_content, 0.3, 'App_4.apk', '-x --c4',
                          '--c4')

  def test_trial_args_adding_using_config_file(self):
    """Ensure that a trial can add args using the config file."""
    config_file_content = [{
        "app_args": "--c4",
        "app_name": "app_1",
        "probability": 0.5
    }]
    self.source_side_test(config_file_content, 0.3, 'app_1', '-x --a1 --c4',
                          '--a1 --c4')

  def test_trial_probability_override_using_config_file(self):
    """Ensure that a trial probability can be overriden using the config file."""
    config_file_content = [{
        "app_args": "--a1",
        "app_name": "app_1",
        "probability": 0.8
    }]
    self.source_side_test(config_file_content, 0.7, 'app_1', '-x --a1', '--a1')

  def test_corrupted_config_file_is_ignored(self):
    """Ensure that a trial probability will not be overriden using a corrupted config file."""
    config_file_content = '[{"app_args": "--a1", "app_name": "app_1", "probability": 0.8]'
    self.source_side_test(config_file_content, 0.7, 'app_1', '-x', None)

  def test_trial_ignored_if_there_is_symmetrical_contradiction(self):
    """Ensure that a flag is not added if it contradicts an already added flag."""
    config_file_content = [{
        "app_args": "--c4",
        "app_name": "app_4",
        "probability": 1.0,
        "contradicts": ["--c5"]
    }, {
        "app_args": "--c5",
        "app_name": "app_4",
        "probability": 1.0,
        "contradicts": ["--c4"]
    }]
    self.source_side_test(config_file_content, 0.1, 'app_4', '-x --c4', '--c4')

  def test_trial_ignored_if_there_is_asymmetrical_contradiction(self):
    """Ensure that a flag is not added if it contradicts an already added flag."""
    config_file_content = [{
        "app_args": "--c4",
        "app_name": "app_4",
        "probability": 1.0
    }, {
        "app_args": "--c5",
        "app_name": "app_4",
        "probability": 1.0,
        "contradicts": ["--c4"]
    }]
    self.source_side_test(config_file_content, 0.1, 'app_4', '-x --c4', '--c4')

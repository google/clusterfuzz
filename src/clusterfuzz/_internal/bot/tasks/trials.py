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
"""Helper functions for app-specific trials/experiments."""

import json
import os
import random
from warnings import warn
from collections import OrderedDict

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment


class Trials:
  """Helper class for selecting app-specific extra flags."""

  def __init__(self):
    self.trials = []

    app_name = environment.get_value('APP_NAME')
    if not app_name:
      return

    # Convert the app_name to lowercase. Case may vary by platform.
    app_name = app_name.lower()

    # Hack: strip file extensions that may be appended on various platforms.
    extensions_to_strip = ['.exe', '.apk']
    for extension in extensions_to_strip:
      app_name = utils.strip_from_right(app_name, extension)

    db_trials = list(
        data_types.Trial.query(data_types.Trial.app_name == app_name))

    self.trials = OrderedDict()
    for trial in db_trials:
      self.trials[trial.app_args] = trial.probability

    trials_config_file = environment.get_value('SOURCE_SIDE_TRIALS')
    app_dir = environment.get_value('APP_DIR')
    if not trials_config_file or not app_dir:
      return

    trials_config_path = os.path.join(app_dir, trials_config_file)
    if not os.path.exists(trials_config_path):
      return

    try:
      with open(trials_config_path) as json_file:
        trials_config = json.load(json_file)
      for config in trials_config:
        if config['app_name'] != app_name:
          continue
        self.trials[config['app_args']] = config['probability']
    except:
      warn('Unable to parse config file')
      return

  def setup_additional_args_for_app(self):
    """Select additional args for the specified app at random."""
    trial_args = [
        app_args
        for app_args, probability in self.trials.items()
        if random.random() < probability
    ]
    if not trial_args:
      return

    trial_app_args = ' '.join(trial_args)
    app_args = environment.get_value('APP_ARGS', '')
    environment.set_value('APP_ARGS', '%s %s' % (app_args, trial_app_args))
    environment.set_value('TRIAL_APP_ARGS', trial_app_args)

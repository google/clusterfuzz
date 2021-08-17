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

import random

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

    self.trials = list(
        data_types.Trial.query(data_types.Trial.app_name == app_name))

  def setup_additional_args_for_app(self):
    """Select additional args for the specified app at random."""
    trial_args = [
        trial.app_args
        for trial in self.trials
        if random.random() < trial.probability
    ]
    if not trial_args:
      return

    trial_app_args = ' '.join(trial_args)
    app_args = environment.get_value('APP_ARGS', '')
    environment.set_value('APP_ARGS', '%s %s' % (app_args, trial_app_args))
    environment.set_value('TRIAL_APP_ARGS', trial_app_args)

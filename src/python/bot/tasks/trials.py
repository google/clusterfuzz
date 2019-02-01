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

from base import utils
from datastore import data_types
from system import environment


def select_trial(trials):
  """Select a trial at random from a list of trials."""
  selection = random.random()
  for trial in trials:
    if selection < trial.probability:
      return trial

    # If there are multiple trials for this app, we assume the sum of the
    # probabilities is <= 1. Subtracting the current probability here gives us a
    # chance to select the next trial.
    selection -= trial.probability

  return None


def setup_additional_args_for_app():
  """Select additional args for the specified app at random."""
  # Convert the app_name to lowercase. Case may vary by platform.
  app_name = environment.get_value('APP_NAME', '').lower()

  # Hack: strip file extensions that may be appended on various platforms.
  extensions_to_strip = ['.exe', '.apk']
  for extension in extensions_to_strip:
    app_name = utils.strip_from_right(app_name, extension)

  trials = data_types.Trial.query(data_types.Trial.app_name == app_name)
  trial = select_trial(trials)
  if not trial or not trial.app_args:
    return

  current_app_args = environment.get_value('APP_ARGS', '').rstrip()
  environment.set_value('APP_ARGS',
                        '%s %s' % (current_app_args, trial.app_args))

  environment.set_value('TRIAL_APP_ARGS', trial.app_args)

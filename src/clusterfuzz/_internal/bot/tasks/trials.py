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

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

TRIALS_CONFIG_FILENAME = 'clusterfuzz_trials_config.json'


class AppArgs:

  def __init__(self, probability, contradicts=None):
    self.probability = probability
    self.contradicts = contradicts or []


def _get_app_name(app_name):
  """Normalize the app name."""
  # Convert the app_name to lowercase. Case may vary by platform.
  app_name = app_name.lower()

  # Hack: strip file extensions that may be appended on various platforms.
  extensions_to_strip = ['.exe', '.apk']
  for extension in extensions_to_strip:
    app_name = utils.strip_from_right(app_name, extension)
  return app_name


def get_db_trials(app_name):
  """Return trials from the datastore."""
  if not app_name:
    return {}

  app_name = _get_app_name(app_name)
  trials = {}
  for trial in data_types.Trial.query(data_types.Trial.app_name == app_name):
    trials[trial.app_args] = AppArgs(trial.probability, trial.contradicts)
  return trials


def get_build_trials(app_name, app_dir):
  """Return trials from the build-specific config file."""
  if not app_name or not app_dir:
    return {}

  app_name = _get_app_name(app_name)
  trials_config_path = os.path.join(app_dir, TRIALS_CONFIG_FILENAME)
  if not os.path.exists(trials_config_path):
    return {}

  trials = {}
  try:
    with open(trials_config_path) as json_file:
      trials_config = json.load(json_file)
    for config in trials_config:
      if config['app_name'] != app_name:
        continue
      trials[config['app_args']] = AppArgs(config['probability'],
                                             config.get('contradicts', []))
  except Exception as e:
    logs.warning('Unable to parse config file: %s' % str(e))

  return trials


class Trials:
  """Helper class for selecting app-specific extra flags."""

  def __init__(self, app_name=None, app_dir=None):
    if app_name is None:
      app_name = environment.get_value('APP_NAME')

    if app_dir is None:
      app_dir = environment.get_value('APP_DIR')

    self.trials = get_db_trials(app_name)
    self.trials.update(get_build_trials(app_name, app_dir))

def get_additional_args(trials, existing_args=None, shuffle=True):
  """Select additional args for the specified app at random."""
  trial_args = []
  contradicts = set()
  if existing_args:
    contradicts.update(existing_args)

  trial_keys = list(trials.keys())

  if shuffle:
    random.shuffle(trial_keys)

  for app_args in trial_keys:
    if random.random() < trials[app_args].probability:
      # Check if the flag is contradicted by an already added flag
      if app_args in contradicts:
        continue
      # Check if the flag contradicts an already added flag
      if trials[app_args].contradicts and any(
          flag in trials[app_args].contradicts for flag in trial_args):
        continue
      trial_args.append(app_args)
      contradicts.update(trials[app_args].contradicts)

  return trial_args


class Trials:
  """Helper class for selecting app-specific extra flags."""

  def __init__(self, app_name=None, app_dir=None):
    if app_name is None:
      app_name = environment.get_value('APP_NAME')

    if app_dir is None:
      app_dir = environment.get_value('APP_DIR')

    self.trials = get_db_trials(app_name)
    self.trials.update(get_build_trials(app_name, app_dir))

  def setup_additional_args_for_app(self, shuffle=True):
    """Select additional args for the specified app at random."""
    trial_app_args_list = get_additional_args(self.trials, shuffle=shuffle)
    if not trial_app_args_list:
      return

    trial_app_args = ' '.join(trial_app_args_list)
    app_args = environment.get_value('APP_ARGS', '')
    environment.set_value('APP_ARGS', '%s %s' % (app_args, trial_app_args))
    environment.set_value('TRIAL_APP_ARGS', trial_app_args)

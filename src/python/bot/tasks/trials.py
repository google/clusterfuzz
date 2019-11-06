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


def setup_additional_args_for_app():
  """Select additional args for the specified app at random."""
  if environment.is_engine_fuzzer_job():
    # Not applicable to engine fuzzers.
    return

  app_name = environment.get_value('APP_NAME')
  if not app_name:
    return

  # Convert the app_name to lowercase. Case may vary by platform.
  app_name = app_name.lower()

  # Hack: strip file extensions that may be appended on various platforms.
  extensions_to_strip = ['.exe', '.apk']
  for extension in extensions_to_strip:
    app_name = utils.strip_from_right(app_name, extension)

  trials = data_types.Trial.query(data_types.Trial.app_name == app_name)
  trials = [trial for trial in trials if random.random() < trial.probability]
  if not trials:
    return

  app_args = environment.get_value('APP_ARGS', '') + ' ' + trials[0].app_args
  trial_app_args = trials[0].app_args
  for trial in trials[1:]:
    app_args += ' ' + trial.app_args
    trial_app_args += ' ' + trial.app_args

  environment.set_value('APP_ARGS', app_args)
  environment.set_value('TRIAL_APP_ARGS', trial_app_args)

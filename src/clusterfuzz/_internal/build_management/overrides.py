# Copyright 2021 Google LLC
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
"""Helper functions to apply build and revisions path overrides"""

import json
import os

from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.system import environment

PLATFORM_ID_URLS_FILENAME = 'config.json'
PLATFORM_ID_TO_BUILD_PATH_KEY = 'build_paths'
PLATFORM_ID_TO_REV_PATH_KEY = 'revisions_paths'

OVERRIDE_PATH_NOT_FOUND_ERROR = 'Could not find override path from config.'
OVERRIDE_CONFIG_NOT_JSON_ERROR = 'Could not read config as json.'
OVERRIDE_CONFIG_NOT_READ_ERROR = 'Could not import config file.'


def check_and_apply_overrides(curr_path, config_key):
  """Check if the given file points to a config, if so, use that to override
  any given paths"""
  if not curr_path:
    return curr_path
  if os.path.basename(curr_path) == PLATFORM_ID_URLS_FILENAME:
    curr_path = _apply_platform_id_overrides(environment.get_platform_id(),
                                             curr_path, config_key)
  return curr_path


def _apply_platform_id_overrides(platform_id, config_url, config_key):
  """read the `bucket_path`, parse as JSON, and map based on platform_id."""
  config_dict = _get_config_dict(config_url)
  path = _get_path_from_config(config_dict, config_key, platform_id)
  if not path:
    raise BuildOverrideError(OVERRIDE_PATH_NOT_FOUND_ERROR)
  return path


def _get_config_dict(url):
  """Read configs from a json and return them as a dict"""
  url_data = storage.read_data(url)
  if not url_data:
    raise BuildOverrideError(OVERRIDE_CONFIG_NOT_READ_ERROR)
  try:
    config_dict = json.loads(url_data)
  except ValueError:
    raise BuildOverrideError(OVERRIDE_CONFIG_NOT_JSON_ERROR)
  return config_dict


def _get_path_from_config(config_dict, config_key, platform_id):
  """Return True if a path override is present and return the override."""
  if config_key not in config_dict:
    return None
  return config_dict[config_key].get(platform_id)


class BuildOverrideError(Exception):
  """Build override error"""

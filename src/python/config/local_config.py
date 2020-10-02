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
"""Get values / settings from local configuration."""

import os
import six
import yaml

from base import errors
from base import memoize
from system import environment

CACHE_SIZE = 1024
YAML_FILE_EXTENSION = '.yaml'

SEPARATOR = '.'

GAE_AUTH_PATH = 'gae.auth'
GAE_CONFIG_PATH = 'gae.config'
GCE_CLUSTERS_PATH = 'gce.clusters'
ISSUE_TRACKERS_PATH = 'issue_trackers.config'
MONITORING_REGIONS_PATH = 'monitoring.regions'
PROJECT_PATH = 'project'


def _load_yaml_file(yaml_file_path):
  """Load yaml file and return parsed contents."""
  with open(yaml_file_path) as f:
    try:
      return yaml.safe_load(f.read())
    except Exception:
      raise errors.ConfigParseError(yaml_file_path)


def _find_key_in_yaml_file(yaml_file_path, search_keys, full_key_name,
                           value_is_relative_path):
  """Find a key in a yaml file."""
  if not os.path.isfile(yaml_file_path):
    return None

  result = _load_yaml_file(yaml_file_path)

  if not search_keys:
    # Give the entire yaml file contents.
    # |value_is_relative_path| is not applicable here.
    return result

  for search_key in search_keys:
    if not isinstance(result, dict):
      raise errors.InvalidConfigKey(full_key_name)

    if search_key not in result:
      return None

    result = result[search_key]

  if value_is_relative_path:
    yaml_directory = os.path.dirname(yaml_file_path)
    if isinstance(result, list):
      result = [os.path.join(yaml_directory, str(i)) for i in result]
    else:
      result = os.path.join(yaml_directory, str(result))

  return result


def _get_key_location(search_path, full_key_name):
  """Get the path of the the yaml file and the key components given a full key
  name."""
  key_parts = full_key_name.split(SEPARATOR)
  dir_path = search_path

  # Find the directory components of the key path
  for i, search_key in enumerate(key_parts):
    search_path = os.path.join(dir_path, search_key)
    if os.path.isdir(search_path):
      # Don't allow both a/b/... and a/b.yaml
      if os.path.isfile(search_path + YAML_FILE_EXTENSION):
        raise errors.InvalidConfigKey(full_key_name)

      dir_path = search_path
    else:
      # The remainder of the key path is a yaml_filename.key1.key2...
      key_parts = key_parts[i:]
      break
  else:
    # The entirety of the key reference a directory.
    key_parts = []

  if key_parts:
    return dir_path, key_parts[0] + YAML_FILE_EXTENSION, key_parts[1:]

  return dir_path, '', []


def _validate_root(search_path, root):
  """Validate that a root is valid."""
  if root is None:
    return True

  directory, filename, search_keys = _get_key_location(search_path, root)

  if not filename:
    # _get_key_location already validated that the directory exists, so the root
    # is valid.
    return True

  # Check that the yaml file and keys exist.
  yaml_path = os.path.join(directory, filename)
  return (_find_key_in_yaml_file(
      yaml_path, search_keys, root, value_is_relative_path=False) is not None)


def _search_key(search_path, full_key_name, value_is_relative_path):
  """Search the key in a search path."""
  directory, filename, search_keys = _get_key_location(search_path,
                                                       full_key_name)

  # Search in the yaml file.
  yaml_path = os.path.join(directory, filename)
  return _find_key_in_yaml_file(yaml_path, search_keys, full_key_name,
                                value_is_relative_path)


class Config(object):
  """Config class helper."""

  def __init__(self, root=None, *args, **kwargs):  # pylint: disable=keyword-arg-before-vararg
    self._root = root.format(*args, **kwargs) if root is not None else None
    self._config_dir = environment.get_config_directory()
    self._cache = memoize.FifoInMemory(CACHE_SIZE)

    # Check that config directory is valid.
    if not self._config_dir or not os.path.exists(self._config_dir):
      raise errors.BadConfigError(self._config_dir)

    # Config roots should exist.
    if not _validate_root(self._config_dir, self._root):
      raise errors.BadConfigError(self._config_dir)

  def sub_config(self, path):
    """Return a new config with a new sub-root."""
    if self._root:
      new_root = self._root + SEPARATOR + path
    else:
      new_root = path

    return Config(root=new_root)

  def _get_helper(self, key_name='', default=None,
                  value_is_relative_path=False):
    """Helper for get and get_absolute_functions."""
    if self._root:
      key_name = self._root + SEPARATOR + key_name if key_name else self._root

    if not key_name:
      raise errors.InvalidConfigKey(key_name)

    cache_key_name = self._cache.get_key(self._get_helper,
                                         (key_name, value_is_relative_path), {})
    value = self._cache.get(cache_key_name)
    if value is not None:
      return value

    value = _search_key(self._config_dir, key_name, value_is_relative_path)
    if value is None:
      return default

    self._cache.put(cache_key_name, value)
    return value

  def get(self, key_name='', default=None):
    """Get key value using a key name."""
    return self._get_helper(key_name, default=default)

  def get_absolute_path(self, key_name='', default=None):
    """Get absolute path of key value using a key name."""
    return self._get_helper(
        key_name, default=default, value_is_relative_path=True)


class ProjectConfig(Config):
  """Project Config class helper."""

  def __init__(self):
    super(ProjectConfig, self).__init__(PROJECT_PATH)

  def set_environment(self):
    """Sets environment vars from project config."""
    env_variable_values = self.get('env')
    if not env_variable_values:
      return

    for variable, value in six.iteritems(env_variable_values):
      if variable in os.environ:
        # Don't override existing values.
        continue

      os.environ[variable] = str(value)


class AuthConfig(Config):
  """Authentication config."""

  def __init__(self):
    super(AuthConfig, self).__init__(GAE_AUTH_PATH)


class GAEConfig(Config):
  """GAE config."""

  def __init__(self):
    super(GAEConfig, self).__init__(GAE_CONFIG_PATH)


class MonitoringRegionsConfig(Config):
  """Monitoring regions config."""

  def __init__(self):
    super(MonitoringRegionsConfig, self).__init__(MONITORING_REGIONS_PATH)


class IssueTrackerConfig(Config):
  """Issue tracker config."""

  def __init__(self):
    super(IssueTrackerConfig, self).__init__(ISSUE_TRACKERS_PATH)

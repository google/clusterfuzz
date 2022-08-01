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
"""Disk backed cache for preserving values across runs of
run.py."""

import hashlib
import os

from clusterfuzz._internal.base import json_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

# For any given value file, if a file with the same name with this added
# extension exists, it is not cleared during initialization.
PERSIST_FILE_EXTENSION = '.persist'


def initialize():
  """Initialize the persistent cache, creating the directory used to store the
  values."""
  cache_directory_path = environment.get_value('CACHE_DIR')
  if os.path.exists(cache_directory_path):
    clear_values()
  else:
    os.makedirs(cache_directory_path)


def clear_values(clear_all=False):
  """Remove all values."""
  cache_directory_path = environment.get_value('CACHE_DIR')
  if not os.path.exists(cache_directory_path):
    return

  for root_directory, _, filenames in os.walk(cache_directory_path):
    for filename in filenames:
      if filename.endswith(PERSIST_FILE_EXTENSION) and not clear_all:
        continue

      file_path = os.path.join(root_directory, filename)
      persist_file_path = file_path + PERSIST_FILE_EXTENSION
      if os.path.exists(persist_file_path) and not clear_all:
        continue

      os.remove(file_path)


def delete_value(key):
  """Removes the value for a key."""
  value_path = get_value_file_path(key)
  if os.path.exists(value_path):
    os.remove(value_path)


def get_value(key, default_value=None, constructor=None):
  """Get the value for a key."""
  value_path = get_value_file_path(key)

  if not os.path.exists(value_path):
    return default_value

  try:
    with open(value_path, 'rb') as f:
      value_str = f.read()
  except IOError:
    logs.log_error('Failed to read %s from persistent cache.' % key)
    return default_value

  try:
    value = json_utils.loads(value_str)
  except Exception:
    logs.log_warn('Non-serializable value read from cache key %s: "%s"' %
                  (key, value_str))
    return default_value

  if constructor:
    try:
      value = constructor(value)
    except Exception:
      logs.log_warn('Failed to construct value "%s" using %s '
                    'and key "%s" in persistent cache. Using default value %s.'
                    % (value, constructor, key, default_value))
      return default_value

  return value


def get_value_file_path(key):
  """Return the full path to the value file for the given key."""
  # Not using utils.string_hash here to avoid a circular dependency.
  # TODO(mbarbella): Avoid this once utils.py is broken into multiple files.
  key_filename = 'cache-%s.json' % hashlib.sha1(str(key).encode()).hexdigest()
  cache_directory_path = environment.get_value('CACHE_DIR')
  return os.path.join(cache_directory_path, key_filename)


def set_value(key, value, persist_across_reboots=False):
  """Set the value for a key. If |persist_across_restarts| is set, then the key
  won't be deleted even run.py is restarted. """
  value_path = get_value_file_path(key)

  try:
    value_str = json_utils.dumps(value)
  except Exception:
    logs.log_error(
        'Non-serializable value stored to cache key %s: "%s"' % (key, value))
    return

  try:
    with open(value_path, 'wb') as f:
      f.write(value_str.encode())
  except IOError:
    logs.log_error('Failed to write %s to persistent cache.' % key)

  if not persist_across_reboots:
    return

  persist_value_path = value_path + PERSIST_FILE_EXTENSION
  if os.path.exists(persist_value_path):
    return

  try:
    open(persist_value_path, 'wb').close()
  except IOError:
    logs.log_error(
        'Failed to write presistent metadata file for cache key %s' % key)

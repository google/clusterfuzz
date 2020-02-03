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
"""Functions for module management."""

# Do not add any imports to non-standard modules here.
import os
import site
import sys


def _config_modules_directory(root_directory):
  """Get the config modules directory."""
  config_dir = os.getenv('CONFIG_DIR_OVERRIDE')
  if not config_dir:
    config_dir = os.path.join(root_directory, 'src', 'appengine', 'config')

  return os.path.join(config_dir, 'modules')


def _patch_appengine_modules_for_bots():
  """Patch out App Engine reliant behaviour from bots."""
  if os.getenv('SERVER_SOFTWARE'):
    # Not applicable on App Engine.
    return

  # google.auth uses App Engine credentials based on importability of
  # google.appengine.api.app_identity.
  try:
    from google.auth import app_engine as auth_app_engine
    if auth_app_engine.app_identity:
      auth_app_engine.app_identity = None
  except ImportError:
    pass


def fix_module_search_paths():
  """Add directories that we must be able to import from to path."""
  root_directory = os.environ['ROOT_DIR']
  source_directory = os.path.join(root_directory, 'src')

  python_path = os.getenv('PYTHONPATH', '').split(os.pathsep)

  third_party_libraries_directory = os.path.join(source_directory,
                                                 'third_party')
  config_modules_directory = _config_modules_directory(root_directory)

  if (os.path.exists(config_modules_directory) and
      config_modules_directory not in sys.path):
    sys.path.insert(0, config_modules_directory)
    python_path.insert(0, config_modules_directory)

  if third_party_libraries_directory not in sys.path:
    sys.path.insert(0, third_party_libraries_directory)
    python_path.insert(0, third_party_libraries_directory)

  python_source_directory = os.path.join(source_directory, 'python')
  if python_source_directory not in sys.path:
    sys.path.insert(0, python_source_directory)
    python_path.insert(0, python_source_directory)

  if source_directory not in sys.path:
    sys.path.insert(0, source_directory)
    python_path.insert(0, source_directory)

  os.environ['PYTHONPATH'] = os.pathsep.join(python_path)

  # Add site directory to make from imports work in google namespace.
  site.addsitedir(third_party_libraries_directory)

  # TODO(ochang): Remove this once SDK is removed from images.
  _patch_appengine_modules_for_bots()

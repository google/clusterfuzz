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


def _patch_google_auth_for_swarming_bots() -> None:
  """Patch google.auth.default to use explicit credentials via GCE metadata.

  This is required for Swarming bots to authenticate with GCP services
  since they do not always have application default credentials configured
  in their environment.
  """
  if not os.getenv('SWARMING_BOT'):
    # Only applicable when explicitly deployed as a Swarming task worker.
    return

  try:
    import google.auth
    from google.auth import compute_engine
    import requests

    def patched_default_credentials(
        *_args, **_kwargs) -> tuple[compute_engine.Credentials, str] | None:
      url = f"http://{os.environ['GCE_METADATA_HOST']}/computeMetadata/v1/" \
            "project/project-id"
      project_id = os.environ.get('GOOGLE_CLOUD_PROJECT') or os.environ.get(
          'APPLICATION_ID')
      if not project_id and os.environ.get('GCE_METADATA_HOST'):
        try:
          project_id = requests.get(
              url, headers={
                  "Metadata-Flavor": "Google"
              }, timeout=2).text.strip()
        except Exception:
          pass

      if not project_id:
        print('''[Swarming] [Error] Failed to patch google.auth.default.
            Reason: failed to get project ID''')
        return None

      return compute_engine.Credentials(), project_id

    google.auth.default = patched_default_credentials
  except ImportError as e:
    print(f'[Swarming] [Error] Failed to patch google.auth.default. {e.msg}')


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

  if source_directory not in sys.path:
    sys.path.insert(0, source_directory)
    python_path.insert(0, source_directory)

  os.environ['PYTHONPATH'] = os.pathsep.join(python_path)

  # Add site directory to make from imports work in google namespace.
  site.addsitedir(third_party_libraries_directory)

  # TODO(ochang): Remove this once SDK is removed from images.
  _patch_appengine_modules_for_bots()
  _patch_google_auth_for_swarming_bots()

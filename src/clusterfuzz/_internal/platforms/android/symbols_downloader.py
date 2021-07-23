# Copyright 2020 Google LLC
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
"""Used to download Android symbols."""

import os

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.platforms.android import fetch_artifact
from clusterfuzz._internal.platforms.android import kernel_utils
from clusterfuzz._internal.platforms.android import settings
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell


def get_repo_prop_archive_filename(build_id, target):
  return f'{target}-{build_id}-repo.prop'


def should_download_symbols():
  """Return True if we should continue to download symbols."""
  # For local testing or when running the reproduce tool locally, we do not
  # have access to the cloud storage bucket with the symbols. In this case,
  # just bail out.
  # We have archived symbols for google builds only.
  return (not environment.get_value('LOCAL_DEVELOPMENT') and
          not environment.get_value('REPRODUCE_TOOL') and
          settings.is_google_device())


def download_artifact_if_needed(
    build_id, artifact_directory, artifact_archive_path,
    targets_with_type_and_san, artifact_file_name, output_filename_override,
    build_params, build_params_check_path):
  """Downloads artifact to actifacts_archive_path if needed"""
  # Check if we already have the symbols in cache.
  cached_build_params = utils.read_data_from_file(
      build_params_check_path, eval_data=True)
  if cached_build_params and cached_build_params == build_params:
    # No work to do, same system symbols already in cache.
    return

  # Delete existing symbols directory first.
  shell.remove_directory(artifact_directory, recreate=True)

  # Fetch symbol file from cloud storage cache (if available).
  found_in_cache = storage.get_file_from_cache_if_exists(
      artifact_archive_path, update_modification_time_on_access=False)
  if not found_in_cache:
    for target_with_type_and_san in targets_with_type_and_san:
      # Fetch the artifact now.
      fetch_artifact.get(build_id, target_with_type_and_san, artifact_file_name,
                         artifact_directory, output_filename_override)
      if os.path.exists(artifact_archive_path):
        break


def download_repo_prop_if_needed(symbols_directory, build_id, cache_target,
                                 targets_with_type_and_san, cache_type):
  """Downloads the repo.prop for a branch"""
  artifact_file_name = 'repo.prop'
  symbols_archive_filename = get_repo_prop_archive_filename(
      build_id, cache_target)
  output_filename_override = symbols_archive_filename
  # We create our own build_params for cache
  build_params = {
      'build_id': build_id,
      'target': cache_target,
      'type': cache_type
  }

  build_params_check_path = os.path.join(symbols_directory,
                                         '.cached_build_params')

  symbols_archive_path = os.path.join(symbols_directory,
                                      symbols_archive_filename)
  download_artifact_if_needed(build_id, symbols_directory, symbols_archive_path,
                              targets_with_type_and_san, artifact_file_name,
                              output_filename_override, build_params,
                              build_params_check_path)
  if not os.path.exists(symbols_archive_path):
    logs.log_error('Unable to locate repo.prop %s.' % symbols_archive_path)
    return

  # Store the artifact for later use or for use by other bots.
  storage.store_file_in_cache(symbols_archive_path)
  utils.write_data_to_file(build_params, build_params_check_path)


def download_kernel_repo_prop_if_needed(symbols_directory):
  """Downloads the repo.prop for the kernel of a device"""
  if not should_download_symbols():
    return

  # For Android kernel we want to get the repro.prop
  # Note: kasan and non-kasan kernel should have the same repo.prop for a given
  # build_id.
  _, build_id = kernel_utils.get_kernel_hash_and_build_id()
  target = kernel_utils.get_kernel_name()
  if not build_id or not target:
    logs.log_error('Could not get kernel parameters, exiting.')
    return

  tool_suffix = environment.get_value('SANITIZER_TOOL_NAME')
  # Some kernels are just 'kernel', some are kernel_target
  if tool_suffix:
    targets_with_type_and_san = [
        f'kernel_{tool_suffix}', f'kernel_{tool_suffix}_{target}'
    ]
  else:
    targets_with_type_and_san = ['kernel', f'kernel_{target}']

  download_repo_prop_if_needed(symbols_directory, build_id, target,
                               targets_with_type_and_san, 'kernel')


def download_system_symbols_if_needed(symbols_directory):
  """Download system libraries from |SYMBOLS_URL| and cache locally."""
  if not should_download_symbols():
    return

  # Get the build fingerprint parameters.
  build_params = settings.get_build_parameters()
  if not build_params:
    logs.log_error('Unable to determine build parameters.')
    return

  build_params_check_path = os.path.join(symbols_directory,
                                         '.cached_build_params')
  build_id = build_params.get('build_id')
  target = build_params.get('target')
  build_type = build_params.get('type')
  if not build_id or not target or not build_type:
    logs.log_error('Null build parameters found, exiting.')
    return

  symbols_archive_filename = f'{target}-symbols-{build_id}.zip'
  artifact_file_name = symbols_archive_filename
  output_filename_override = None

  # Include type and sanitizer information in the target.
  tool_suffix = environment.get_value('SANITIZER_TOOL_NAME')
  target_with_type_and_san = f'{target}-{build_type}'
  if tool_suffix and not tool_suffix in target_with_type_and_san:
    target_with_type_and_san += f'_{tool_suffix}'

  targets_with_type_and_san = [target_with_type_and_san]

  symbols_archive_path = os.path.join(symbols_directory,
                                      symbols_archive_filename)
  download_artifact_if_needed(build_id, symbols_directory, symbols_archive_path,
                              targets_with_type_and_san, artifact_file_name,
                              output_filename_override, build_params,
                              build_params_check_path)
  if not os.path.exists(symbols_archive_path):
    logs.log_error(
        'Unable to locate symbols archive %s.' % symbols_archive_path)
    return

  # Store the artifact for later use or for use by other bots.
  storage.store_file_in_cache(symbols_archive_path)

  archive.unpack(symbols_archive_path, symbols_directory, trusted=True)
  shell.remove_file(symbols_archive_path)

  utils.write_data_to_file(build_params, build_params_check_path)


def _get_binary_from_build_or_device(binary_path):
  """Look for binary on build server or on device."""
  # Initialize some helper variables.
  symbols_directory = environment.get_value('SYMBOLS_DIR')
  binary_filename = os.path.basename(binary_path)

  # We didn't find the library locally in the build directory.
  # Try finding the library in the local system library cache.
  download_system_symbols_if_needed(symbols_directory)
  local_binary_path = utils.find_binary_path(symbols_directory, binary_path)
  if local_binary_path:
    return local_binary_path

  # Try pulling in the binary directly from the device into the
  # system library cache directory.
  local_binary_path = os.path.join(symbols_directory, binary_filename)
  adb.run_command('pull %s %s' % (binary_path, local_binary_path))
  if os.path.exists(local_binary_path):
    return local_binary_path

  return None


def filter_binary_path(binary_path):
  """Filter binary path to provide local copy."""
  # LKL fuzzer name is not full path.
  if environment.is_android():
    # Skip symbolization when running it on bad entries like [stack:XYZ].
    if not binary_path.startswith('/') or '(deleted)' in binary_path:
      return ''

  # Initialize some helper variables.
  build_directory = environment.get_value('BUILD_DIR')

  # Try to find the library in the build directory first.
  local_binary_path = utils.find_binary_path(build_directory, binary_path)
  if local_binary_path:
    return local_binary_path

  # We should only download from the build server if we are Android.
  if environment.is_android():
    local_binary_path = _get_binary_from_build_or_device(binary_path)
    if local_binary_path:
      return local_binary_path

  # Unable to find library.
  logs.log_error('Unable to find library %s for symbolization.' % binary_path)
  return ''

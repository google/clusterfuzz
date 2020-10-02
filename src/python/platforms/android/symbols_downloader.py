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

from base import utils
from google_cloud_utils import storage
from metrics import logs
from platforms.android import fetch_artifact
from platforms.android import kernel_utils
from platforms.android import settings
from system import archive
from system import environment
from system import shell


def get_symbols_archive_filename(build_id, target):
  return '%s-%s-repo.prop' % (target, build_id)


def download_system_symbols_if_needed(symbols_directory, is_kernel=False):
  """Download system libraries from |SYMBOLS_URL| and cache locally."""
  # For local testing, we do not have access to the cloud storage bucket with
  # the symbols. In this case, just bail out.
  if environment.get_value('LOCAL_DEVELOPMENT'):
    return

  # When running reproduce tool locally, we do not have access to the cloud
  # storage bucket with the symbols. In this case, just bail out.
  if environment.get_value('REPRODUCE_TOOL'):
    return

  # We have archived symbols for google builds only.
  if not settings.is_google_device():
    return

  # For Android kernel we want to get the repro.prop
  # Note: kasan and non-kasan kernel should have the same repo.prop for a given
  # build_id.
  if is_kernel:
    _, build_id = kernel_utils.get_kernel_hash_and_build_id()
    target = kernel_utils.get_kernel_name()
    if not build_id or not target:
      logs.log_error('Could not get kernel parameters, exiting.')
      return

    artifact_file_name = 'repo.prop'
    symbols_archive_filename = get_symbols_archive_filename(build_id, target)
    output_filename_override = symbols_archive_filename
    # We create our own build_params for cache
    build_params = {'build_id': build_id, 'target': target, 'type': 'kernel'}
  else:
    # Get the build fingerprint parameters.
    build_params = settings.get_build_parameters()
    if not build_params:
      logs.log_error('Unable to determine build parameters.')
      return

    build_id = build_params.get('build_id')
    target = build_params.get('target')
    build_type = build_params.get('type')
    if not build_id or not target or not build_type:
      logs.log_error('Null build parameters found, exiting.')
      return

    symbols_archive_filename = '%s-symbols-%s.zip' % (target, build_id)
    artifact_file_name = symbols_archive_filename
    output_filename_override = None

  # Check if we already have the symbols in cache.
  build_params_check_path = os.path.join(symbols_directory,
                                         '.cached_build_params')
  cached_build_params = utils.read_data_from_file(
      build_params_check_path, eval_data=True)
  if cached_build_params and cached_build_params == build_params:
    # No work to do, same system symbols already in cache.
    return

  symbols_archive_path = os.path.join(symbols_directory,
                                      symbols_archive_filename)

  # Delete existing symbols directory first.
  shell.remove_directory(symbols_directory, recreate=True)

  # Fetch symbol file from cloud storage cache (if available).
  found_in_cache = storage.get_file_from_cache_if_exists(
      symbols_archive_path, update_modification_time_on_access=False)
  if not found_in_cache:
    tool_suffix = environment.get_value('SANITIZER_TOOL_NAME')

    if is_kernel:
      # Some kernels are just 'kernel', some are kernel_target
      if tool_suffix:
        targets_with_type_and_san = [
            'kernel_%s' % tool_suffix,
            'kernel_%s_%s' % (tool_suffix, target)
        ]
      else:
        targets_with_type_and_san = ['kernel', 'kernel_%s' % target]
    else:
      # Include type and sanitizer information in the target.
      target_with_type_and_san = '%s-%s' % (target, build_type)
      if tool_suffix and not tool_suffix in target_with_type_and_san:
        target_with_type_and_san += '_%s' % tool_suffix

      targets_with_type_and_san = [target_with_type_and_san]

    for target_with_type_and_san in targets_with_type_and_san:
      # Fetch the artifact now.
      fetch_artifact.get(build_id, target_with_type_and_san, artifact_file_name,
                         symbols_directory, output_filename_override)
      if os.path.exists(symbols_archive_path):
        break

  if not os.path.exists(symbols_archive_path):
    logs.log_error(
        'Unable to locate symbols archive %s.' % symbols_archive_path)
    return

  # Store the artifact for later use or for use by other bots.
  storage.store_file_in_cache(symbols_archive_path)

  # repo.prop is not a zip archive.
  if not is_kernel:
    archive.unpack(symbols_archive_path, symbols_directory, trusted=True)
    shell.remove_file(symbols_archive_path)

  utils.write_data_to_file(build_params, build_params_check_path)

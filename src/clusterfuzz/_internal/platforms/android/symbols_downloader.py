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
import re
import shutil
import tempfile
from typing import NamedTuple
import zipfile
import zlib

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.platforms.android import fetch_artifact
from clusterfuzz._internal.platforms.android import settings
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

from . import constants


class SymbolDownloadError(errors.Error):
  """Raised when symbol artifacts are unavailable or fail to download."""


class TrustySymbols(NamedTuple):
  """Resolved local ELF paths for Trusty kernel and Trusted App symbols."""
  kernel_binary: str
  app_binary: str


def get_repo_prop_archive_filename(build_id: str, target: str) -> str:
  return '%s-%s-repo.prop' % (target, build_id)


def should_download_symbols():
  """Return True if we should continue to download symbols."""
  # For local testing, we do not have access to the cloud storage bucket with
  # the symbols. In this case, just bail out. We have archived symbols for
  # google builds only.
  return (not environment.get_value('LOCAL_DEVELOPMENT') and
          settings.is_google_device())


def download_artifact_if_needed(
    build_id, artifact_directory, artifact_archive_path,
    targets_with_type_and_san, artifact_file_name, output_filename_override):
  """Downloads artifact to actifacts_archive_path if needed"""
  # Delete existing symbols directory first.
  shell.remove_directory(artifact_directory, recreate=True)

  for target_with_type_and_san in targets_with_type_and_san:
    # Fetch the artifact now.
    fetch_artifact.get(build_id, target_with_type_and_san, artifact_file_name,
                       artifact_directory, output_filename_override)
    if os.path.exists(artifact_archive_path):
      break


def check_symbols_cached(build_params_check_path, build_params):
  # Check if we already have the symbols locally.
  cached_build_params = utils.read_data_from_file(
      build_params_check_path, eval_data=True)
  return cached_build_params and cached_build_params == build_params


def _get_kernel_artifact_targets(target: str) -> list[str]:
  """Returns candidate Android Build target names for a kernel build."""
  tool_suffix = environment.get_value('SANITIZER_TOOL_NAME')
  # Some kernels are just 'kernel', some are 'kernel_<target>'.
  if tool_suffix:
    return [
        'kernel_%s' % tool_suffix,
        'kernel_%s_%s' % (tool_suffix, target),
    ]
  return ['kernel', 'kernel_%s' % target]


def download_repo_prop_if_needed(
    symbols_directory: str,
    build_id: str,
    cache_target: str,
    targets_with_type_and_san: list[str],
    *,
    can_download: bool,
) -> str:
  """Returns the local path to repo.prop, downloading it if not already present.

  Args:
    symbols_directory: Directory where repo.prop is cached or downloaded.
    build_id: Android Build ID to fetch repo.prop for.
    cache_target: Target name used to construct the local repo.prop filename.
    targets_with_type_and_san: Candidate Android Build targets to query.
    can_download: Whether downloading is allowed when repo.prop is absent.

  Returns:
    Path to the local repo.prop file.

  Raises:
    SymbolDownloadError: If repo.prop is not present locally and downloading
      is disabled or fails.
  """
  symbols_archive_filename = get_repo_prop_archive_filename(
      build_id, cache_target)
  symbols_archive_path = os.path.join(symbols_directory,
                                      symbols_archive_filename)
  if os.path.isfile(symbols_archive_path):
    return symbols_archive_path

  if not can_download:
    raise SymbolDownloadError(
        'Symbol downloading is disabled for this environment.')

  download_artifact_if_needed(build_id, symbols_directory, symbols_archive_path,
                              targets_with_type_and_san, 'repo.prop',
                              symbols_archive_filename)
  if not os.path.isfile(symbols_archive_path):
    raise SymbolDownloadError(
        'Unable to download repo.prop to %s.' % symbols_archive_path)

  return symbols_archive_path


def download_kernel_repo_prop_if_needed(
    symbols_directory: str,
    build_id: str,
    target: str,
) -> str:
  """Returns the local Android kernel repo.prop path, downloading if needed.

  Args:
    symbols_directory: Directory where repo.prop is cached or downloaded.
    build_id: Android kernel build ID.
    target: Android kernel target name.

  Returns:
    Path to the local repo.prop file.

  Raises:
    SymbolDownloadError: If repo.prop is absent locally and downloading is
      disabled or fails.
  """
  # Note: kasan and non-kasan kernels share the same repo.prop for a build_id.
  targets_with_type_and_san = _get_kernel_artifact_targets(target)
  return download_repo_prop_if_needed(
      symbols_directory,
      build_id,
      target,
      targets_with_type_and_san,
      can_download=should_download_symbols())


def download_system_symbols_if_needed(symbols_directory):
  """Download system libraries from |SYMBOLS_URL| and cache locally."""
  if not should_download_symbols():
    return

  # Get the build fingerprint parameters.
  build_params = settings.get_build_parameters()
  if not build_params:
    logs.error('Unable to determine build parameters.')
    return

  build_params_check_path = os.path.join(symbols_directory,
                                         '.cached_build_params')
  if check_symbols_cached(build_params_check_path, build_params):
    return

  build_id = build_params.get('build_id')
  target = build_params.get('target')
  build_type = build_params.get('type')

  if environment.is_android() and \
  target not in constants.NO_RELEASE_CONFIGURATION_TARGET_LIST and \
  target not in constants.AUTOMOTIVE_TARGET_LIST:
    build_type = constants.RELEASE_CONFIGURATION + '-' + build_type

  if environment.is_android_auto() and \
  target in constants.AUTOMOTIVE_TARGET_LIST:
    build_type = constants.AUTOMOTIVE_RELEASE_CONFIGURATION + '-' + build_type

  if not build_id or not target or not build_type:
    logs.error('Null build parameters found, exiting.')
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
                              output_filename_override)
  if not os.path.exists(symbols_archive_path):
    logs.error('Unable to locate symbols archive %s.' % symbols_archive_path)
    return

  with archive.open(symbols_archive_path) as reader:
    reader.extract_all(symbols_directory, trusted=True)
  shell.remove_file(symbols_archive_path)

  utils.write_data_to_file(build_params, build_params_check_path)


def _get_trusty_build_target() -> str:
  """Returns the Android Build target for the current Trusty device.

  Returns:
    The Android Build target string for fetching Trusty symbols.

  Raises:
    SymbolDownloadError: If device build parameters are unavailable or the
      device is unsupported.
  """
  build_params = settings.get_build_parameters()
  if not build_params or not build_params.get('target'):
    raise SymbolDownloadError('Unable to determine device target for Trusty.')
  device = build_params['target']
  if 'cheetah' in device or 'panther' in device:
    return 'cloudripper-fuzz-test-debug'
  if 'oriole' in device or 'raven' in device or 'bluejay' in device:
    return 'slider-fuzz-test-debug'
  raise SymbolDownloadError('Unsupported Trusty device: %s.' % device)


def _extract_trusty_symbols(symbols_archive_path: str, symbols_directory: str,
                            app_name: str) -> None:
  """Extracts lk.elf and the Trusted App ELF from a Trusty symbols archive.

  Args:
    symbols_archive_path: Path to the downloaded Trusty symbols zip archive.
    symbols_directory: Directory where extracted ELF files will be written.
    app_name: Name of the Trusted App whose symbols ELF should be extracted.

  Raises:
    SymbolDownloadError: If the symbols archive is not a valid zip file or
      cannot be decompressed.
  """
  app_filename = '%s.syms.elf' % app_name
  try:
    with zipfile.ZipFile(symbols_archive_path, 'r') as symbols_zipfile:
      for member in symbols_zipfile.infolist():
        if member.is_dir():
          continue
        if os.path.basename(member.filename) == app_filename:
          target_path = os.path.join(symbols_directory, app_filename)
        elif member.filename == 'lk.elf':
          target_path = os.path.join(symbols_directory, 'lk.elf')
        else:
          continue
        with symbols_zipfile.open(member, 'r') as src, open(target_path,
                                                            'wb') as dst:
          shutil.copyfileobj(src, dst)
  except (zipfile.BadZipFile, zlib.error, EOFError) as error:
    raise SymbolDownloadError(
        'Invalid Trusty symbols archive %s.' % symbols_archive_path) from error


def _download_trusty_symbols(
    trusty_root: str,
    bid: str,
    app_name: str,
    trusty_symbols_dir: str,
) -> None:
  """Downloads, extracts, and installs Trusty ELF symbols into a bid dir."""
  ab_target = _get_trusty_build_target()
  artifact_filename = '%s-%s.syms.zip' % (ab_target, bid)
  app_filename = '%s.syms.elf' % app_name
  os.makedirs(trusty_root, exist_ok=True)
  with tempfile.TemporaryDirectory(dir=trusty_root) as temp_dir:
    symbols_archive_path = os.path.join(temp_dir, artifact_filename)
    fetch_artifact.get(bid, ab_target, artifact_filename, temp_dir, None)
    if not os.path.isfile(symbols_archive_path):
      raise SymbolDownloadError(
          'Unable to download Trusty symbols archive %s.' % artifact_filename)

    _extract_trusty_symbols(symbols_archive_path, temp_dir, app_name)
    temp_kernel_path = os.path.join(temp_dir, 'lk.elf')
    temp_app_path = os.path.join(temp_dir, app_filename)
    if not (os.path.isfile(temp_kernel_path) and os.path.isfile(temp_app_path)):
      raise SymbolDownloadError(
          'Missing Trusty ELF symbols after extracting %s.' % artifact_filename)

    os.makedirs(trusty_symbols_dir, exist_ok=True)
    os.replace(temp_kernel_path, os.path.join(trusty_symbols_dir, 'lk.elf'))
    os.replace(temp_app_path, os.path.join(trusty_symbols_dir, app_filename))


def download_trusty_symbols_if_needed(
    symbols_directory: str,
    app_name: str,
    bid: str,
) -> TrustySymbols:
  """Returns local Trusty ELF paths, downloading and extracting if needed.

  Args:
    symbols_directory: Base symbols directory under which Trusty ELF symbols
      are cached in ``trusty/<bid>/``.
    app_name: Name of the crashed Trusted App.
    bid: Trusty build ID.

  Returns:
    TrustySymbols containing local paths to lk.elf and <app_name>.syms.elf.

  Raises:
    SymbolDownloadError: If the ELF symbols are not present locally and
      downloading is disabled or fails, or extraction fails.
  """
  trusty_root = os.path.join(symbols_directory, 'trusty')
  trusty_symbols_dir = os.path.join(trusty_root, bid)
  app_filename = '%s.syms.elf' % app_name
  kernel_binary_path = os.path.join(trusty_symbols_dir, 'lk.elf')
  app_binary_path = os.path.join(trusty_symbols_dir, app_filename)
  if os.path.isfile(kernel_binary_path) and os.path.isfile(app_binary_path):
    return TrustySymbols(
        kernel_binary=kernel_binary_path, app_binary=app_binary_path)

  if environment.get_value('LOCAL_DEVELOPMENT'):
    raise SymbolDownloadError(
        'Symbol downloading is disabled in local development.')

  _download_trusty_symbols(trusty_root, bid, app_name, trusty_symbols_dir)
  return TrustySymbols(
      kernel_binary=kernel_binary_path, app_binary=app_binary_path)


_VALID_DEVICE_BINARY_PATH_REGEX = re.compile(r'^/[A-Za-z0-9._+@~=/!-]+\Z')


def _is_valid_device_binary_path(binary_path):
  """Returns True if |binary_path| is a safe absolute device file path."""
  if not binary_path or '(deleted)' in binary_path:
    return False
  if binary_path.endswith(
      '/') or not _VALID_DEVICE_BINARY_PATH_REGEX.match(binary_path):
    return False
  parts = binary_path.split('/')
  if any(part in ('', '.', '..') for part in parts[1:]):
    return False
  basename = parts[-1]
  return bool(basename) and not basename.startswith(('-', '.'))


def _get_binary_from_build_or_device(binary_path):
  """Look for binary on build server or on device."""
  if not _is_valid_device_binary_path(binary_path):
    logs.warning('Skipping invalid Android binary path: %s.' % binary_path)
    return None

  # Initialize some helper variables.
  symbols_directory = environment.get_value('SYMBOLS_DIR')
  if not symbols_directory:
    return None
  relative_binary_path = binary_path.lstrip('/')
  binary_filename = os.path.basename(relative_binary_path)

  # We didn't find the library locally in the build directory.
  # Try finding the library in the local system library cache.
  download_system_symbols_if_needed(symbols_directory)
  local_binary_path = utils.find_binary_path(symbols_directory,
                                             relative_binary_path)
  if local_binary_path and os.path.isfile(local_binary_path):
    return local_binary_path

  # Try pulling in the binary directly from the device into the
  # system library cache directory.
  local_binary_path = os.path.join(symbols_directory, binary_filename)
  if os.path.exists(local_binary_path):
    return None
  adb.run_command(['pull', binary_path, local_binary_path])
  if os.path.isfile(local_binary_path):
    return local_binary_path

  return None


def filter_binary_path(binary_path):
  """Filter binary path to provide local copy."""
  # LKL fuzzer name is not full path.
  is_android = environment.is_android()
  if is_android:
    # Skip symbolization when running it on bad entries like [stack:XYZ].
    if not _is_valid_device_binary_path(binary_path):
      return ''

  # Initialize some helper variables.
  build_directory = environment.get_value('BUILD_DIR')

  # Try to find the library in the build directory first.
  lookup_subpath = binary_path.lstrip('/') if is_android else binary_path
  if build_directory:
    local_binary_path = utils.find_binary_path(build_directory, lookup_subpath)
    if local_binary_path and os.path.isfile(local_binary_path):
      return local_binary_path

  # We should only download from the build server if we are Android.
  if is_android:
    local_binary_path = _get_binary_from_build_or_device(binary_path)
    if local_binary_path:
      return local_binary_path

  # Unable to find library.
  logs.error('Unable to find library %s for symbolization.' % binary_path)
  return ''

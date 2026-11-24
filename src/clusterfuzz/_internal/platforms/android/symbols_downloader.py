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
import shlex
import tempfile
import zipfile

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.platforms.android import fetch_artifact
from clusterfuzz._internal.platforms.android import kernel_utils
from clusterfuzz._internal.platforms.android import settings
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

from . import constants


def get_repo_prop_archive_filename(build_id, target):
  return f'{target}-{build_id}-repo.prop'


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
  if check_symbols_cached(build_params_check_path, build_params):
    return

  symbols_archive_path = os.path.join(symbols_directory,
                                      symbols_archive_filename)
  download_artifact_if_needed(build_id, symbols_directory, symbols_archive_path,
                              targets_with_type_and_san, artifact_file_name,
                              output_filename_override)
  if not os.path.exists(symbols_archive_path):
    logs.error('Unable to locate repo.prop %s.' % symbols_archive_path)
    return

  # Store the artifact for later use or for use by other bots.
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
    logs.error('Could not get kernel parameters, exiting.')
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


def download_trusty_symbols_if_needed(symbols_directory, app_name, bid):
  """Downloads and extracts Trusted App ELF files"""
  ab_target = ''
  device = settings.get_build_parameters().get('target')
  if 'cheetah' in device or 'panther' in device:
    ab_target = 'cloudripper-fuzz-test-debug'
  elif 'oriole' in device or 'raven' in device or 'bluejay' in device:
    ab_target = 'slider-fuzz-test-debug'
  else:
    logs.error(f'Unsupported device {device}.')

  branch = 'polygon-trusty-whitechapel-master'
  if not bid:
    build_info = fetch_artifact.get_latest_artifact_info(branch, ab_target)
    if not build_info:
      logs.info(f'Unable to fetch build info for branch {branch} '
                f'and target {ab_target}.')
      return
    bid = build_info['bid']

  artifact_filename = f'{ab_target}-{bid}.syms.zip'
  symbols_archive_path = os.path.join(symbols_directory, artifact_filename)

  download_artifact_if_needed(bid, symbols_directory, symbols_archive_path,
                              [ab_target], artifact_filename, None)

  if not os.path.exists(symbols_archive_path):
    logs.error(f'Unable to locate symbols archive {symbols_archive_path}.')
    return

  with zipfile.ZipFile(symbols_archive_path, 'r') as symbols_zipfile:
    for filepath in symbols_zipfile.namelist():
      if f'{app_name}.syms.elf' in filepath:
        symbols_zipfile.extract(filepath, symbols_directory)
        os.rename(f'{symbols_directory}/{filepath}',
                  f'{symbols_directory}/{app_name}.syms.elf')
      if 'lk.elf' == filepath:
        symbols_zipfile.extract(filepath, symbols_directory)


_VALID_DEVICE_BINARY_PATH_REGEX = re.compile(r'^/[A-Za-z0-9._+@~=/!-]+\Z')
_ALLOWED_DEVICE_ROOT_DIRS = frozenset({
    'apex',
    'data',
    'odm',
    'oem',
    'product',
    'sbin',
    'system',
    'system_ext',
    'vendor',
})
_ABI_64_PATH_SEGMENTS = frozenset({'arm64', 'arm64-v8a', 'lib64', 'x86_64'})
_ABI_32_PATH_SEGMENTS = frozenset(
    {'arm', 'armeabi', 'armeabi-v7a', 'lib', 'x86'})


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
  if binary_path != '/init':
    if len(parts) < 3 or parts[1] not in _ALLOWED_DEVICE_ROOT_DIRS:
      return False
    if parts[1] == 'data' and parts[2] == 'misc':
      return False
  basename = parts[-1]
  if not basename or basename.startswith(('-', '.')):
    return False
  if '!' in binary_path:
    archive_part, member_part = binary_path.split('!', 1)
    archive_basename = os.path.basename(archive_part)
    member_basename = os.path.basename(member_part)
    if (not archive_basename or archive_basename.startswith(
        ('-', '.')) or not member_part or '!' in member_part or
        not member_basename or member_basename.startswith(('-', '.'))):
      return False
  return True


def _infer_abi_bitness(path):
  """Infers 64-bit or 32-bit ABI from path segments, or None if unspecified."""
  segments = set(path.replace('!', '/').split('/'))
  if segments & _ABI_64_PATH_SEGMENTS:
    return 64
  if segments & _ABI_32_PATH_SEGMENTS:
    return 32
  return None


def _find_cached_symbol_path(symbols_directory, relative_binary_path):
  """Finds a cached regular file matching |relative_binary_path|."""
  candidates = [
      os.path.join(symbols_directory, relative_binary_path),
      os.path.join(symbols_directory, 'device', relative_binary_path),
  ]
  product_root = os.path.join(symbols_directory, 'out', 'target', 'product')
  if os.path.isdir(product_root):
    for product_name in sorted(os.listdir(product_root)):
      candidates.append(
          os.path.join(product_root, product_name, 'symbols',
                       relative_binary_path))
  for candidate in candidates:
    if os.path.isfile(candidate):
      return candidate

  # Search extracted build symbols (excluding device-pulled files so distinct
  # device paths sharing a basename cannot collide).
  subpath_suffix = os.sep + relative_binary_path
  binary_filename = os.path.basename(relative_binary_path.rsplit('!', 1)[-1])
  requested_bitness = _infer_abi_bitness(relative_binary_path)
  arch_basename_match = None
  neutral_basename_match = None
  for root, dirs, filenames in os.walk(symbols_directory):
    if root == symbols_directory and 'device' in dirs:
      dirs.remove('device')
    dirs.sort()
    filenames.sort()
    for filename in filenames:
      file_path = os.path.join(root, filename)
      if file_path.endswith(subpath_suffix) and os.path.isfile(file_path):
        return file_path
      if filename != binary_filename or not os.path.isfile(file_path):
        continue
      candidate_rel_path = os.path.relpath(file_path, symbols_directory)
      candidate_bitness = _infer_abi_bitness(candidate_rel_path)
      if requested_bitness is None:
        if neutral_basename_match is None:
          neutral_basename_match = file_path
      elif candidate_bitness == requested_bitness:
        if arch_basename_match is None:
          arch_basename_match = file_path
      elif candidate_bitness is None and neutral_basename_match is None:
        neutral_basename_match = file_path
  return arch_basename_match or neutral_basename_match


def _pull_device_binary(binary_path, local_binary_path, symbols_directory):
  """Validates |binary_path| on the device and atomically pulls it to host."""
  quoted_path = shlex.quote(binary_path)
  resolved_output = adb.run_shell_command(
      f'test -f {quoted_path} && realpath {quoted_path}')
  resolved_path = (resolved_output or '').strip()
  if '\n' in resolved_path or not _is_valid_device_binary_path(resolved_path):
    return None

  device_cache_root = os.path.join(symbols_directory, 'device')
  try:
    os.makedirs(device_cache_root, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=device_cache_root, prefix='.pull_', delete=False) as temp_file:
      temp_path = temp_file.name
  except OSError:
    return None

  try:
    pull_cmd = adb.get_adb_command_line(
        shlex.join(['pull', resolved_path, temp_path]))
    return_code, _ = adb.execute_command_with_return_code(
        pull_cmd, timeout=adb.ADB_TIMEOUT)
    if (return_code != 0 or not os.path.isfile(temp_path) or
        os.path.getsize(temp_path) == 0):
      return None
    os.makedirs(os.path.dirname(local_binary_path), exist_ok=True)
    os.replace(temp_path, local_binary_path)
    return local_binary_path if os.path.isfile(local_binary_path) else None
  except OSError:
    return None
  finally:
    if os.path.exists(temp_path):
      try:
        os.remove(temp_path)
      except OSError:
        pass


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

  # We didn't find the library locally in the build directory.
  # Try finding the library in the local system library cache.
  download_system_symbols_if_needed(symbols_directory)
  local_binary_path = _find_cached_symbol_path(symbols_directory,
                                               relative_binary_path)
  if local_binary_path:
    return local_binary_path

  # APK-embedded paths (e.g. base.apk!libchrome.so) are not standalone files on
  # the device filesystem and cannot be fetched via adb pull.
  if '!' in binary_path:
    return None

  # Try pulling in the binary directly from the device into a dedicated
  # subdirectory of the system library cache directory.
  local_binary_path = os.path.abspath(
      os.path.join(symbols_directory, 'device', relative_binary_path))
  if os.path.exists(local_binary_path):
    return None
  return _pull_device_binary(binary_path, local_binary_path, symbols_directory)


def filter_binary_path(binary_path):
  """Filter binary path to provide local copy."""
  # LKL fuzzer name is not full path.
  is_android = environment.is_android()
  if is_android:
    # Skip symbolization when running it on bad entries like [stack:XYZ] or
    # malformed/untrusted paths.
    if not _is_valid_device_binary_path(binary_path):
      return ''

  # Initialize some helper variables.
  build_directory = environment.get_value('BUILD_DIR')

  # Try to find the library in the build directory first.
  lookup_subpath = binary_path.lstrip('/') if is_android else binary_path
  if build_directory:
    local_binary_path = utils.find_binary_path(build_directory, lookup_subpath)
    if not local_binary_path and is_android and '!' in lookup_subpath:
      member_subpath = lookup_subpath.split('!', 1)[1].lstrip('/')
      local_binary_path = utils.find_binary_path(build_directory,
                                                 member_subpath)
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

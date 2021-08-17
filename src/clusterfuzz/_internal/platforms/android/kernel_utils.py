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
"""Android kernel util functions."""

import os
import re

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.android import constants
from clusterfuzz._internal.platforms.android import settings
from clusterfuzz._internal.platforms.android import symbols_downloader
from clusterfuzz._internal.system import environment

# Linux version 3.18.0-g(8de8e79)-ab(1234567) where 8de8e79 is the hash and
# 1234567 optional is the kernel build id.
LINUX_VERSION_REGEX = re.compile(
    r'Linux version .+-g([0-9a-f]+)[\s\-](ab([0-9a-f]+)\s)')

# Similar to source_mapper.STACK_FRAME_PATH_LINE_REGEX but also matches column
# number.
LLVM_SYMBOLIZER_STACK_FRAME_PATH_LINE_REGEX = re.compile(
    r'(?<=\[|\(|\s)([a-zA-Z/.][^\s]*?)\s*(:|@)\s*(\d+)(?=\]$|\)$|:\d+$|$)'
    r'(:\d+)?')


def _get_clean_kernel_path(path):
  """Sometimes kernel paths start with
  /buildbot/src/partner-android/BRANCH/private/PROJ.  We want to remove all
  of this."""
  # Remove the stuff before 'private', since it is build-server dependent
  # and not part of the final URL.
  if '/private/' in path:
    path_parts = path.split('/')
    path_parts = path_parts[path_parts.index('private') + 2:]
    return '/'.join(path_parts)

  return path


def get_kernel_stack_frame_link(stack_frame, kernel_prefix, kernel_hash):
  """Add source links data to kernel stack frames."""
  match = LLVM_SYMBOLIZER_STACK_FRAME_PATH_LINE_REGEX.search(stack_frame)
  if not match:
    # If this stack frame does not contain a path and line, bail out.
    return stack_frame

  path = _get_clean_kernel_path(match.group(1))
  line = match.group(3)
  kernel_prefix = utils.strip_from_left(kernel_prefix, 'kernel/private/')
  display_path = f'{kernel_prefix}/{path}:{line}'

  # If we have a column number, lets add it to the display path.
  if match.group(4):
    display_path += match.group(4)

  kernel_url_info = (r'http://go/pakernel/{prefix}/+/{hash}/{path}#{line};'
                     r'{display_path};').format(
                         prefix=kernel_prefix,
                         hash=kernel_hash,
                         path=path,
                         line=line,
                         display_path=display_path)

  link_added_stack_frame = LLVM_SYMBOLIZER_STACK_FRAME_PATH_LINE_REGEX.sub(
      kernel_url_info, stack_frame)

  return link_added_stack_frame


def _get_prefix_and_full_hash(repo_data, kernel_partial_hash):
  """Find the prefix and full hash in the repo_data based on the partial."""
  kernel_partial_hash_lookup = 'u\'%s' % kernel_partial_hash
  for line in repo_data.splitlines():
    if kernel_partial_hash_lookup in line:
      prefix, full_hash = line.split(' ', 1)
      return prefix, full_hash.strip('u\'')

  return None, None


def _get_repo_prop_data(build_id, target):
  """Downloads repo.prop and returns the data based on build_id and target."""
  symbols_directory = os.path.join(
      environment.get_value('SYMBOLS_DIR'), 'kernel')
  repro_filename = symbols_downloader.get_repo_prop_archive_filename(
      build_id, target)

  # Grab repo.prop, it is not on the device nor in the build_dir.
  symbols_downloader.download_kernel_repo_prop_if_needed(symbols_directory)
  local_repo_path = utils.find_binary_path(symbols_directory, repro_filename)

  if local_repo_path and os.path.exists(local_repo_path):
    return utils.read_data_from_file(local_repo_path, eval_data=False).decode()

  return None


def get_kernel_prefix_and_full_hash():
  """Download repo.prop and return the full hash and prefix."""

  kernel_partial_hash, build_id = get_kernel_hash_and_build_id()
  target = get_kernel_name()
  if not build_id or not target:
    logs.log_error('Could not get kernel parameters, exiting.')
    return None

  android_kernel_repo_data = _get_repo_prop_data(build_id, target)
  if android_kernel_repo_data:
    return _get_prefix_and_full_hash(android_kernel_repo_data,
                                     kernel_partial_hash)

  return None, None


def get_kernel_name():
  """Returns the kernel name for the device, since some kernels are shared."""
  product_name = settings.get_product_name()
  build_product = settings.get_build_product()

  # Strip _kasan off of the end as we will add it later if needed.
  utils.strip_from_right(product_name, '_kasan')

  # Some devices have a different kernel name than product_name, if so use the
  # kernel name.
  return constants.PRODUCT_TO_KERNEL.get(build_product, product_name)


def get_kernel_hash_and_build_id():
  """Returns the (partial_hash, build_id) of the kernel."""
  version_string = settings.get_kernel_version_string()
  match = re.match(LINUX_VERSION_REGEX, version_string)
  if match:
    return match.group(2), match.group(3)

  return None

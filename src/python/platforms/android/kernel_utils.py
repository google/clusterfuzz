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

from base import utils
from build_management import source_mapper
from metrics import logs
from platforms.android import constants
from platforms.android import settings
from platforms.android import symbols_downloader
from system import environment

# Linux version 3.18.0-g(8de8e79)-ab(1234567) where 8de8e79 is the hash and
# 1234567 optional is the kernel build id.
LINUX_VERSION_REGEX = re.compile(
    r'Linux version .+-g([0-9a-f]+)[\s\-](ab([0-9a-f]+)\s)')


def get_kernel_stack_frame_link(stack_frame, kernel_prefix, kernel_hash):
  """Add source links data to kernel stack frames."""
  match = source_mapper.STACK_FRAME_PATH_LINE_REGEX.search(stack_frame)
  if not match:
    # If this stack frame does not contain a path and line, bail out.
    return stack_frame

  path = match.group(1)
  line = match.group(3)
  kernel_prefix = utils.strip_from_left(kernel_prefix, 'kernel/private/')
  display_path = '/'.join([kernel_prefix, path])
  kernel_url_info = (r'http://go/pakernel/{prefix}/+/{hash}/{path}#{line};'
                     r'{display_path};').format(
                         prefix=kernel_prefix,
                         hash=kernel_hash,
                         path=path,
                         line=line,
                         display_path=display_path)

  link_added_stack_frame = source_mapper.STACK_FRAME_PATH_LINE_REGEX.sub(
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


def get_kernel_prefix_and_full_hash():
  """Download repo.prop and return the full hash and prefix."""
  symbols_directory = os.path.join(
      environment.get_value('SYMBOLS_DIR'), 'kernel')
  kernel_partial_hash, build_id = get_kernel_hash_and_build_id()
  target = get_kernel_name()
  if not build_id or not target:
    logs.log_error('Could not get kernel parameters, exiting.')
    return None

  repro_filename = symbols_downloader.get_symbols_archive_filename(
      build_id, target)

  # Grab repo.prop, it is not on the device nor in the build_dir.
  symbols_downloader.download_system_symbols_if_needed(
      symbols_directory, is_kernel=True)
  local_repo_path = utils.find_binary_path(symbols_directory, repro_filename)

  if local_repo_path and os.path.exists(local_repo_path):
    android_kernel_repo_data = utils.read_data_from_file(
        local_repo_path, eval_data=False).decode()
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
  """Returns the build id  and hash of the kernel."""
  version_string = settings.get_kernel_version_string()
  match = re.match(LINUX_VERSION_REGEX, version_string)
  if match:
    return match.group(2), match.group(3)

  return None

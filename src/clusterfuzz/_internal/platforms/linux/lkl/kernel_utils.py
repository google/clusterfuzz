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
"""Linux Kernel Library kernel utils functions."""
import os

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.platforms.android import symbols_downloader
from clusterfuzz._internal.system import environment

from . import constants


def _should_download_symbols():
  """Return True if we should continue to download symbols."""
  # For local testing or when running the reproduce tool locally, we do not
  # have access to the cloud storage bucket with the symbols. In this case,
  # just bail out.
  return (not environment.get_value('LOCAL_DEVELOPMENT') and
          not environment.get_value('REPRODUCE_TOOL'))


def get_kernel_prefix_and_full_hash(build_id):
  """Download repo.prop and return the full hash and prefix."""
  android_kernel_repo_data = _get_repo_prop_data(build_id,
                                                 constants.LKL_BUILD_TARGET)
  if android_kernel_repo_data:
    for line in android_kernel_repo_data.splitlines():
      if line.startswith(constants.LKL_REPO_KERNEL_PREFIX):
        # line is of form: prefix u'hash'
        return (constants.LKL_REPO_KERNEL_PREFIX, line.split(' ',
                                                             1)[1].strip('u\''))

  return None, None


def _get_repo_prop_data(build_id, fuzz_target):
  """Downloads repo.prop and returuns the data based on build_id and target."""
  symbols_directory = os.path.join(
      environment.get_value('SYMBOLS_DIR'), fuzz_target)
  repro_filename = symbols_downloader.get_repo_prop_archive_filename(
      build_id, fuzz_target)

  # Grab repo.prop, it is not on the device nor in the build_dir.
  _download_kernel_repo_prop_if_needed(symbols_directory, build_id, fuzz_target)
  local_repo_path = utils.find_binary_path(symbols_directory, repro_filename)
  if local_repo_path and os.path.exists(local_repo_path):
    return utils.read_data_from_file(local_repo_path, eval_data=False).decode()

  return None


def _download_kernel_repo_prop_if_needed(symbols_directory, build_id,
                                         fuzz_target):
  """Downloads the repo.prop for an LKL fuzzer"""
  if not _should_download_symbols():
    return

  symbols_downloader.download_repo_prop_if_needed(
      symbols_directory, build_id, fuzz_target, [fuzz_target], 'lkl_fuzzer')

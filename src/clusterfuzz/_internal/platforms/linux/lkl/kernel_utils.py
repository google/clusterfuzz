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
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.android import symbols_downloader
from clusterfuzz._internal.system import environment

from . import constants


def _should_download_symbols():
  """Return True if we should continue to download symbols."""
  # For local testing, we do not have access to the cloud storage bucket with
  # the symbols. In this case, just bail out.
  return not environment.get_value('LOCAL_DEVELOPMENT')


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


def _get_repo_prop_data(build_id: str, fuzz_target: str) -> str | None:
  """Returns the LKL repo.prop contents, or None if unavailable."""
  symbols_directory = os.path.join(
      environment.get_value('SYMBOLS_DIR'), fuzz_target)
  try:
    local_repo_path = symbols_downloader.download_repo_prop_if_needed(
        symbols_directory,
        build_id,
        fuzz_target, [fuzz_target],
        can_download=_should_download_symbols())
  except symbols_downloader.SymbolDownloadError as error:
    logs.warning(f'Unable to obtain LKL kernel repo.prop: {error}')
    return None

  return utils.read_data_from_file(local_repo_path, eval_data=False).decode()

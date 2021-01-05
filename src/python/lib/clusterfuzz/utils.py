# Copyright 2021 Google LLC
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
"""Module containing fuzzer utils."""

try:
  from clusterfuzz._internal.bot.fuzzers import utils
except ImportError:
  from bot.fuzzers import utils


def is_fuzz_target(file_path, file_handle=None):
  """Returns whether |file_path| is a fuzz target."""
  return utils.is_fuzz_target_local(file_path, file_handle)


def get_fuzz_targets(directory):
  """Returns the list of fuzz targets in |directory|."""
  return utils.get_fuzz_targets_local(directory)

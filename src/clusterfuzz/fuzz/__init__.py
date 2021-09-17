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
"""Fuzzing functions."""

from clusterfuzz._internal import fuzzing
from clusterfuzz._internal.bot.fuzzers import init
from clusterfuzz._internal.bot.fuzzers import utils

from . import engine

_initialized = False

ENGINES = fuzzing.PUBLIC_ENGINES


def _initialize():
  """Initialize the engine implementations."""
  global _initialized

  init.run(include_private=False, include_lowercase=True)
  _initialized = True


def get_engine(name):
  """Get the engine with the given name."""
  if not _initialized:
    _initialize()

  engine_impl = engine.get(name)
  engine_impl.do_strategies = False
  return engine_impl


def is_fuzz_target(file_path, file_handle=None):
  """Returns whether |file_path| is a fuzz target."""
  return utils.is_fuzz_target_local(file_path, file_handle)


def get_fuzz_targets(directory):
  """Returns the list of fuzz targets in |directory|."""
  return utils.get_fuzz_targets_local(directory)

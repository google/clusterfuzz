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

from . import engine

_initialized = False


def _initialize():
  """Initialize the engine implementations."""
  global _initialized

  try:
    from clusterfuzz._internal.bot.fuzzers.honggfuzz \
        import engine as honggfuzz_engine
    from clusterfuzz._internal.bot.fuzzers.libFuzzer \
        import engine as libFuzzer_engine
  except ImportError:
    from bot.fuzzers.honggfuzz import engine as honggfuzz_engine
    from bot.fuzzers.libFuzzer import engine as libFuzzer_engine

  engine.register('honggfuzz', honggfuzz_engine.HonggfuzzEngine)
  engine.register('libFuzzer', libFuzzer_engine.LibFuzzerEngine)

  _initialized = True


def get_engine(name):
  """Get the engine with the given name."""
  if not _initialized:
    _initialize()

  return engine.get(name)

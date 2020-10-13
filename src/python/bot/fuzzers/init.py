# Copyright 2019 Google LLC
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
"""Fuzzing engine initialization."""

from bot.fuzzers.blackbox import engine as blackbox_engine
from bot.fuzzers.honggfuzz import engine as honggfuzz_engine
from bot.fuzzers.libFuzzer import engine as libFuzzer_engine
from bot.fuzzers.syzkaller import engine as syzkaller_engine
from lib.clusterfuzz.fuzz import engine


def run():
  """Initialise builtin fuzzing engines."""
  engine.register('blackbox', blackbox_engine.BlackboxEngine)
  engine.register('honggfuzz', honggfuzz_engine.HonggfuzzEngine)
  engine.register('libFuzzer', libFuzzer_engine.LibFuzzerEngine)
  engine.register('syzkaller', syzkaller_engine.SyzkallerEngine)

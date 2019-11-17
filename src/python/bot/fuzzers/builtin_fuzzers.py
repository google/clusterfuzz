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
"""Builtin fuzzers."""

from bot.fuzzers.afl import fuzzer as afl
from bot.fuzzers.libFuzzer import fuzzer as libFuzzer

BUILTIN_FUZZERS = {
    'afl': afl.Afl(),
    'libFuzzer': libFuzzer.LibFuzzer(),
}


def get(fuzzer_name):
  """Get the builtin fuzzer with the given name, or None."""
  if fuzzer_name not in BUILTIN_FUZZERS:
    return None

  return BUILTIN_FUZZERS[fuzzer_name]

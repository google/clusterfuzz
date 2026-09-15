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
"""libFuzzer fuzzer."""
import psutil

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import builtin
from clusterfuzz._internal.bot.fuzzers import options
from clusterfuzz._internal.bot.fuzzers.libFuzzer import constants


def get_extra_env(fuzzer_path):
  """Get environment variables for a given fuzz target if any (or None)."""
  fuzzer_options = options.get_fuzz_target_options(fuzzer_path)
  if fuzzer_options:
    return fuzzer_options.get_env()

  return None


def get_rss_limit_mb(fuzzer_options=None) -> int:
  """Returns the rss_limit_mb to use for a target with the given options."""
  rss_limit_mb = None
  if fuzzer_options:
    rss_limit_mb = fuzzer_options.get_engine_arguments('libfuzzer').get(
        'rss_limit_mb', constructor=int)

  if rss_limit_mb is None:
    if utils.is_chromium() or utils.default_project_name() == 'google':
      return 0
    return constants.DEFAULT_RSS_LIMIT_MB

  # psutil gives the total amount of memory in bytes, but we're only dealing
  # with options that are counting memory space in MB, so we need to do the
  # conversion first.
  max_memory_limit_mb = (psutil.virtual_memory().total //
                         (1 << 20)) - constants.MEMORY_OVERHEAD
  # Custom rss_limit_mb value shouldn't be greater than the actual memory
  # allocated on the machine.
  return min(rss_limit_mb, max_memory_limit_mb)


def get_arguments(fuzzer_path) -> options.FuzzerArguments:
  """Get arguments for a given fuzz target."""
  arguments = options.FuzzerArguments()
  timeout = None

  fuzzer_options = options.get_fuzz_target_options(fuzzer_path)

  if fuzzer_options:
    arguments = fuzzer_options.get_engine_arguments('libfuzzer')
    timeout = arguments.get('timeout', constructor=int)

  if timeout is None:
    arguments[constants.TIMEOUT_FLAGNAME] = constants.DEFAULT_TIMEOUT_LIMIT

  arguments[constants.RSS_LIMIT_FLAGNAME] = get_rss_limit_mb(fuzzer_options)

  return arguments


class LibFuzzer(builtin.EngineFuzzer):
  """Builtin libFuzzer fuzzer."""

  def generate_arguments(self, fuzzer_path):
    """Generate arguments for fuzzer using .options file or default values."""
    return ' '.join(get_arguments(fuzzer_path).list())

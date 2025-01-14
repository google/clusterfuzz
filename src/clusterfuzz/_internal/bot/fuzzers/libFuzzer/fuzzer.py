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


def get_arguments(fuzzer_path) -> options.FuzzerArguments:
  """Get arguments for a given fuzz target."""
  arguments = options.FuzzerArguments()
  rss_limit_mb = None
  timeout = None

  fuzzer_options = options.get_fuzz_target_options(fuzzer_path)

  if fuzzer_options:
    arguments = fuzzer_options.get_engine_arguments('libfuzzer')
    rss_limit_mb = arguments.get('rss_limit_mb', constructor=int)
    timeout = arguments.get('timeout', constructor=int)

  if timeout is None:
    arguments[constants.TIMEOUT_FLAGNAME] = constants.DEFAULT_TIMEOUT_LIMIT

  if not rss_limit_mb and (utils.is_chromium() or
                           utils.default_project_name() == 'google'):
    # TODO(metzman/alhijazi): Monitor if we are crashing the bots.
    arguments[constants.RSS_LIMIT_FLAGNAME] = 0
  elif not rss_limit_mb:
    arguments[constants.RSS_LIMIT_FLAGNAME] = constants.DEFAULT_RSS_LIMIT_MB
  else:
    # psutil gives the total amount of memory in bytes, but we're only dealing
    # with options that are counting memory space in MB, so we need to do the
    # conversion first.
    max_memory_limit_mb = (psutil.virtual_memory().total //
                           (1 << 20)) - constants.MEMORY_OVERHEAD
    # Custom rss_limit_mb value shouldn't be greater than the actual memory
    # allocated on the machine.
    if rss_limit_mb > max_memory_limit_mb:
      arguments[constants.RSS_LIMIT_FLAGNAME] = max_memory_limit_mb

  return arguments


class LibFuzzer(builtin.EngineFuzzer):
  """Builtin libFuzzer fuzzer."""

  def generate_arguments(self, fuzzer_path):
    """Generate arguments for fuzzer using .options file or default values."""
    return ' '.join(get_arguments(fuzzer_path).list())

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
from clusterfuzz._internal.bot.fuzzers import builtin
from clusterfuzz._internal.bot.fuzzers import options
from clusterfuzz._internal.bot.fuzzers.libFuzzer import constants


def get_grammar(fuzzer_path):
  """Get grammar for a given fuzz target. Return none if there isn't one."""
  fuzzer_options = options.get_fuzz_target_options(fuzzer_path)
  if fuzzer_options:
    grammar = fuzzer_options.get_grammar_options()
    if grammar:
      return grammar.get('grammar')

  return None


def get_arguments(fuzzer_path):
  """Get arguments for a given fuzz target."""
  arguments = []
  rss_limit_mb = None
  timeout = None

  fuzzer_options = options.get_fuzz_target_options(fuzzer_path)

  if fuzzer_options:
    libfuzzer_arguments = fuzzer_options.get_engine_arguments('libfuzzer')
    if libfuzzer_arguments:
      arguments.extend(libfuzzer_arguments.list())
      rss_limit_mb = libfuzzer_arguments.get('rss_limit_mb', constructor=int)
      timeout = libfuzzer_arguments.get('timeout', constructor=int)

  if not timeout:
    arguments.append(
        '%s%d' % (constants.TIMEOUT_FLAG, constants.DEFAULT_TIMEOUT_LIMIT))
  else:
    # Custom timeout value shouldn't be greater than the default timeout
    # limit.
    # TODO(mmoroz): Eventually, support timeout values greater than the
    # default.
    if timeout > constants.DEFAULT_TIMEOUT_LIMIT:
      arguments.remove('%s%d' % (constants.TIMEOUT_FLAG, timeout))
      arguments.append(
          '%s%d' % (constants.TIMEOUT_FLAG, constants.DEFAULT_TIMEOUT_LIMIT))

  if not rss_limit_mb:
    arguments.append(
        '%s%d' % (constants.RSS_LIMIT_FLAG, constants.DEFAULT_RSS_LIMIT_MB))
  else:
    # Custom rss_limit_mb value shouldn't be greater than the default value.
    if rss_limit_mb > constants.DEFAULT_RSS_LIMIT_MB:
      arguments.remove('%s%d' % (constants.RSS_LIMIT_FLAG, rss_limit_mb))
      arguments.append(
          '%s%d' % (constants.RSS_LIMIT_FLAG, constants.DEFAULT_RSS_LIMIT_MB))

  return arguments


class LibFuzzer(builtin.EngineFuzzer):
  """Builtin libFuzzer fuzzer."""

  def generate_arguments(self, fuzzer_path):
    """Generate arguments for fuzzer using .options file or default values."""
    return ' '.join(get_arguments(fuzzer_path))

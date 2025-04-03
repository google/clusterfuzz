# Copyright 2024 Google LLC
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
"""Run a task locally."""

from clusterfuzz._internal.bot.fuzzers import init
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.system import environment

# from local.butler.run_bot


def execute(args):
  """Build keywords."""
  environment.set_bot_environment()
  init.run()
  commands.process_command_impl('fuzz', 'lokihardt_jshitter', 'linux32_asan_d8_dbg',
                                True, True)
  pass

 
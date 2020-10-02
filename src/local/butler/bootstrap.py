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
"""Install all required dependencies for running an appengine, a bot, and a
  mapreduce locally."""

from local.butler import appengine
from local.butler import common


def execute(args):
  """Install all required dependencies for running tests, the appengine,
    and the bot."""
  is_reproduce_tool_setup = args.only_reproduce
  common.install_dependencies(is_reproduce_tool_setup=is_reproduce_tool_setup)

  # App engine setup is not needed for the reproduce tool.
  if not is_reproduce_tool_setup:
    appengine.symlink_dirs()

  print('Bootstrap successfully finished.')

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
"""Runs uworker_main on a uworker input URL."""

import os

from clusterfuzz._internal.bot.fuzzers import init
from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.system import environment


def execute(args):
  """Runs uworker_main on a uworker input URL."""
  del args
  environment.set_bot_environment()
  init.run()
  os.environ[
      'UWORKER_INPUT_DOWNLOAD_URL'] = '<PUT SIGNED UWORKER INPUT URL HERE>'

  utasks.uworker_bot_main()

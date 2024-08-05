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
"""Executes update task locally, so we can run it through a debugger."""

import os

from clusterfuzz._internal.bot.tasks import update_task
from clusterfuzz._internal.system import environment


def execute():
  """Build keywords."""
  environment.set_bot_environment()
  os.environ['USE_TEST_DEPLOYMENT'] = '1'
  update_task.update_source_code()

# Copyright 2025 Google LLC
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
"""Executes grouper task locally, so we can run it through a debugger."""

from clusterfuzz._internal.cron import grouper_experiment
from clusterfuzz._internal.system import environment

# PATH_TO_TCS=~/Data/groups TASK_LEASE_SECONDS=240 DEBUG_TASK=True ALLOW_UNPACK_OVER_HTTP=True
# UWORKER=True LOG_TO_CONSOLE=True BOT_TMPDIR=/tmp/bot TMPDIR=/tmp/tmp
# python butler.py run --config-dir=../clusterfuzz-config/configs/internal run_grouper --non-dry-run
def execute(args):  #pylint: disable=unused-argument
  environment.set_bot_environment()
  grouper_experiment.main()

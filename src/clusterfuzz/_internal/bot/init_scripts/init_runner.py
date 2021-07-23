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
"""Custom init runner."""

import os

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler

SCRIPT_DIR = os.path.join('bot', 'init')


def _extension(platform):
  """Get the init extension for a platform."""
  if platform == 'windows':
    return '.ps1'

  return '.bash'


def run():
  """Run custom platform specific init scripts."""
  platform = environment.platform().lower()
  script_path = os.path.join(environment.get_config_directory(), SCRIPT_DIR,
                             platform + _extension(platform))
  if not os.path.exists(script_path):
    return

  os.chmod(script_path, 0o750)
  if script_path.endswith('.ps1'):
    cmd = 'powershell.exe ' + script_path
  else:
    cmd = script_path

  try:
    process_handler.run_process(
        cmd,
        timeout=1800,
        need_shell=True,
        testcase_run=False,
        ignore_children=True)
  except Exception:
    logs.log_error('Failed to execute platform initialization script.')

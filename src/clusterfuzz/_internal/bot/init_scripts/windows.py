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
"""The initialization script for Windows. It is run before running a task."""

import os

from clusterfuzz._internal.bot.init_scripts import init_runner
from clusterfuzz._internal.system import shell

DEFAULT_FAIL_RETRIES = 5
DEFAULT_FAIL_WAIT = 5

TEMP_DIRECTORIES = [
    r'%TEMP%', r'%USERPROFILE%\AppVerifierLogs', r'%USERPROFILE%\Downloads',
    r'%WINDIR%\Temp',
    r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\sym',
    r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym'
]


def clean_temp_directories():
  """Clean temporary directories."""
  for temp_directory in TEMP_DIRECTORIES:
    temp_directory_full_path = os.path.abspath(
        os.path.expandvars(temp_directory))
    shell.remove_directory(
        temp_directory_full_path, recreate=True, ignore_errors=True)


def run():
  """Run the initialization for Windows."""
  init_runner.run()
  clean_temp_directories()

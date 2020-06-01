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
"""The initialization script for Mac. It is run before running a task."""

import os
import re
import shutil
import subprocess

from bot.init_scripts import init_runner

# Example: ('Path: /var/folders/bg/tn9j_qb532s4fz11rzz7m6sc0000gm/0'
#           '//com.apple.LaunchServices-134500.csstore')
LAUNCH_SERVICE_PATH_REGEX = re.compile('^Path: (.+)$')
LSREGISTER_CMD = ('/System/Library/Frameworks/CoreServices.framework'
                  '/Frameworks/LaunchServices.framework/Versions/A/Support'
                  '/lsregister -dump')


def _execute(cmd):
  """Execute command and return output as an iterator."""
  proc = subprocess.Popen(
      cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  try:
    for line in iter(proc.stdout.readline, b''):
      yield line.decode('utf-8')
  finally:
    proc.kill()


def get_launch_service_path():
  """Get launch service path from lsregister."""
  for line in _execute(LSREGISTER_CMD):
    m = LAUNCH_SERVICE_PATH_REGEX.match(line)
    if not m:
      continue

    return '/'.join(m.group(1).split('/')[:5])

  return None


def clear_launch_service_data():
  """See crbug.com/661221 for more info."""
  path = get_launch_service_path()
  if not path or not os.path.exists(path):
    return
  # Best effort removal. We use shutil instead of shell.remove_directory since
  # it's too noisy and there are many files that cannot be removed.
  shutil.rmtree(os.path.join(path, '0'), ignore_errors=True)
  shutil.rmtree(os.path.join(path, 'T'), ignore_errors=True)


def run():
  """Run the initialization for Mac."""
  init_runner.run()
  clear_launch_service_data()

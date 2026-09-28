# Copyright 2026 Google LLC
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
"""Tests for excluded modules imports."""
import subprocess
import sys
import unittest

_SUBPROCESS_CODE = '''
import sys
sys.path = {sys_path}

import clusterfuzz._internal.system.environment as env
env.is_running_on_app_engine = lambda: True

import server

excluded_modules = [
    'clusterfuzz._internal.bot', '_internal.bot',
    'clusterfuzz._internal.tests', '_internal.tests',
    'third_party'
]
for module in excluded_modules:
  # No need to match prefixes because python always imports the parent module.
  if module in sys.modules:
    print('SUBPROCESS_MARKER_STRING ' + module)
    sys.exit(1)
'''.format(sys_path=str(sys.path))


class ExcludedModulesTest(unittest.TestCase):
  """Test if server module imports excluded modules in .gcloudignore."""

  def test(self):
    """Spawns a subprocess to check for excluded modules imports."""
    # Uses the same working directory and env vars as the current process.
    result = subprocess.run(
        [sys.executable, '-c', _SUBPROCESS_CODE],
        check=False,
        capture_output=True,
        text=True)

    if result.returncode != 0:
      module = None
      cnt = 0

      for line in result.stdout.splitlines():
        if line.startswith('SUBPROCESS_MARKER_STRING'):
          # Module name does not have whitespace, so this is safe.
          module = line.split()[1]
          cnt += 1

      if cnt == 1:
        self.fail(
            f'Module {module} is excluded in .gcloudignore, but it was imported by server.'
        )
      else:  # Unexpected crash.
        print('stdout:\n' + result.stdout)
        print('stderr:\n' + result.stderr)
        msg = 'Subprocess execution failed: '
        msg += 'No output marker found' if cnt == 0 else 'Multiple output markers found'
        self.fail(msg)

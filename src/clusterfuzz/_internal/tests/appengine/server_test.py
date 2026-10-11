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
"""Tests for server module."""
import os
import subprocess
import sys
import unittest

from clusterfuzz._internal.tests.test_libs import helpers

# This regex is used to match modules excluded by .gcloudignore.
# The module must begin with either a full module path or an empty string,
# then must contain `name` and end immediately.
# For instance, this avoids abc.github, github.xyz matching against git,
# meanwhile it allows for clusterfuzz._internal.bot to match against _internal.bot.
# This also ignores submodules whose parent module was already detected
# from being detected as well.
_REGEX_MODULE = r'(.+\.|^){name}$'

_SUBPROCESS_CODE = '''
import re
import sys
sys.path = {sys_path}  # List of string.

import clusterfuzz._internal.system.environment as env
env.is_running_on_app_engine = lambda: True

import server

excluded_modules = {excluded_modules}  # List of string.
REGEX_MODULE = r'{REGEX_MODULE}'  # String.
return_code = 0

for excluded in excluded_modules:
  pattern = re.compile(REGEX_MODULE.format(name=re.escape(excluded)))
  for module in sys.modules:
    if pattern.match(module):
      print('SUBPROCESS_MARKER_STRING ' + module)
      return_code = 1

sys.exit(return_code)
'''


class ServerTest(unittest.TestCase):
  """Test server module is loaded."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.is_running_on_app_engine',
    ])
    self.mock.is_running_on_app_engine.return_value = True

  def test_load(self):
    # pylint: disable=import-outside-toplevel
    import server
    self.assertIsNotNone(server.handlers)
    self.assertIsNotNone(server.cron_routes)
    self.assertIsNotNone(server.app)

  def _get_gcloudignore_modules(self):
    """Parse .gcloudignore to figure out module names.

    It does not detect if some pattern actually matches a python module,
    it just treats every pattern as a possible module and assumes that,
    if they aren't, then the server will never import them as well.
    """

    excluded_modules = []
    file_path = os.path.abspath(
        os.path.join('src', 'appengine', '.gcloudignore'))
    with open(file_path) as f:
      for line in f:
        line = line.strip()
        if line.startswith('#') or not line:
          continue

        if line.startswith('./'):
          line = line[2:]
        if '.' in line:
          continue

        line = line.strip('/').replace('/', '.')
        excluded_modules.append(line)

    return excluded_modules

  def test_excluded_modules_import(self):
    """Check for imports of modules excluded by .gcloudignore."""
    excluded_modules = self._get_gcloudignore_modules()
    code = _SUBPROCESS_CODE.format(
        sys_path=str(sys.path),
        excluded_modules=str(excluded_modules),
        REGEX_MODULE=_REGEX_MODULE)

    # Uses the same working directory and env vars as the current process.
    result = subprocess.run(
        [sys.executable, '-c', code],
        check=False,
        capture_output=True,
        text=True)

    if result.returncode != 0:
      modules = []

      for line in result.stdout.splitlines():
        if line.startswith('SUBPROCESS_MARKER_STRING'):
          # Module name does not have whitespace, so this is safe.
          modules.append(line.split()[1])

      if modules:
        mods = ', '.join(modules)
        self.fail(
            f'Modules {mods} are excluded in .gcloudignore, but were imported by server.'
        )
      else:  # Unexpected crash.
        msg = 'Subprocess execution failed: no output marker found.\n'
        msg += 'STDOUT:\n' + result.stdout + '\nSTDERR:\n' + result.stderr
        self.fail(msg)

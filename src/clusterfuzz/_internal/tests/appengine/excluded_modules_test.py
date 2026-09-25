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
import os
import sys
import unittest

from clusterfuzz._internal.tests.test_libs import helpers


class ExcludedModulesTest(unittest.TestCase):
  """Test if server module imports excluded modules in .gcloudignore."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.is_running_on_app_engine',
    ])
    self.mock.is_running_on_app_engine.return_value = True

  def test(self):
    # pylint: disable=import-outside-toplevel,unused-import,missing-function-docstring

    excluded_modules = [
        'clusterfuzz._internal.bot', '_internal.bot',
        'clusterfuzz._internal.tests', '_internal.tests', 'third_party'
    ]
    base_path = os.path.abspath(os.path.join('src'))

    def must_pop_from_cache(name, module) -> bool:
      if not hasattr(module, '__file__') or module.__file__ is None:
        return False
      if name == 'clusterfuzz._internal.system.environment':
        # Do not remove the mocked is_running_on_app_engine
        return False
      return os.path.commonpath([module.__file__, base_path]) == base_path

    # Removes the modules from the cache if they were imported previously
    cached_modules = [
        name for name, module in sys.modules.items()
        if must_pop_from_cache(name, module)
    ]
    for module in cached_modules:
      sys.modules.pop(module)

    import server

    for module in excluded_modules:
      # Do not use assertNotIn because it prints the entire sys.modules in the error message
      if module in sys.modules:
        self.fail(
            f'Module {module} is excluded in .gcloudignore, but it was imported by server.'
        )

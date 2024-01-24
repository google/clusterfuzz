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
"""Tests for uworker_handle_errors."""

import unittest

from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.bot.tasks.utasks import uworker_handle_errors


class UworkerHandleErrorsTest(unittest.TestCase):
  """Tests for uworker_handle_erros."""

  def test_all_handled_erros_are_mapped(self):
    """Ensure all errors handled by a module are mapped in uworker_handle_errors."""
    all_handled_errors = uworker_handle_errors.get_all_handled_errors()
    excluded_modules = {
        'postprocess', 'uworker_main', 'blame', 'impact', 'unpack'
    }
    for command, module in commands._COMMAND_MODULE_MAP.items():  # pylint: disable=protected-access
      if command in excluded_modules:
        continue
      handled_errors_by_module = module.HANDLED_ERRORS
      for handled_error in handled_errors_by_module:
        self.assertIn(handled_error, all_handled_errors)

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
"""Tests for task_utils."""
import unittest

from clusterfuzz._internal.base import task_utils
from clusterfuzz._internal.bot.tasks import commands


class GetCommandFromModuleTest(unittest.TestCase):
  """Tests for get_command_from_module."""

  def test_get_command_from_module(self):
    # pylint: disable=protected-access
    """Tests that get_command_from_module returns the correct command."""
    for command, module in commands._COMMAND_MODULE_MAP.items():
      if command in {'postprocess', 'uworker_main'}:
        continue
      self.assertEqual(command,
                       task_utils.get_command_from_module(module.__name__))
    with self.assertRaises(ValueError):
      task_utils.get_command_from_module('postprocess')
    with self.assertRaises(ValueError):
      task_utils.get_command_from_module('uworker_main')


class IsTaskOptedIntoUworkerExecution(unittest.TestCase):

  def test_opt_in(self):
    self.assertTrue(task_utils.is_task_opted_into_uworker_execution('analyze'))

  def test_no_opt_in(self):
    self.assertFalse(task_utils.is_task_opted_into_uworker_execution('fuzz'))

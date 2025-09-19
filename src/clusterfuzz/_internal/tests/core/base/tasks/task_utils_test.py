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

from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.protos import uworker_msg_pb2


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


class GetTaskEventDataTest(unittest.TestCase):
  # pylint: disable=protected-access
  """Tests the helper methods for task execution event data."""

  def test_task_based_lists(self):
    """Asserts that the task names defined in type-based sets are correct."""
    all_task_commands = set(commands._COMMAND_MODULE_MAP.keys())
    self.assertTrue(
        task_utils._TESTCASE_BASED_TASKS.issubset(all_task_commands))
    self.assertTrue(task_utils._FUZZER_BASED_TASKS.issubset(all_task_commands))

  def test_get_task_event_data_preprocess(self):
    """Tests retrieving event data directly from task argument."""
    # Get one example of each task type.
    testcase_based = commands._COMMAND_MODULE_MAP.get('minimize')
    task_command = task_utils.get_command_from_module(testcase_based.__name__)
    self.assertEqual(
        task_utils.get_task_execution_event_data(task_command, '1', 'job'), {
            'task_job': 'job',
            'testcase_id': 1
        })

    fuzzer_based = commands._COMMAND_MODULE_MAP.get('fuzz')
    task_command = task_utils.get_command_from_module(fuzzer_based.__name__)
    self.assertEqual(
        task_utils.get_task_execution_event_data(task_command, 'fuzzer', 'job'),
        {
            'task_job': 'job',
            'task_fuzzer': 'fuzzer'
        })

  def test_get_task_event_data_postprocess(self):
    """Tests retrieving event data from uworker input."""
    # Get one example of each task type.
    testcase_based = commands._COMMAND_MODULE_MAP.get('minimize')
    task_command = task_utils.get_command_from_module(testcase_based.__name__)
    task_argument = uworker_msg_pb2.Input(testcase_id='1', job_type='job')
    self.assertEqual(
        task_utils.get_task_execution_event_data(task_command, task_argument,
                                                 'job'), {
                                                     'task_job': 'job',
                                                     'testcase_id': 1
                                                 })

    fuzzer_based = commands._COMMAND_MODULE_MAP.get('fuzz')
    task_command = task_utils.get_command_from_module(fuzzer_based.__name__)
    task_argument = uworker_msg_pb2.Input(fuzzer_name='fuzzer', job_type='job')
    self.assertEqual(
        task_utils.get_task_execution_event_data(task_command, task_argument,
                                                 'job'), {
                                                     'task_job': 'job',
                                                     'task_fuzzer': 'fuzzer'
                                                 })

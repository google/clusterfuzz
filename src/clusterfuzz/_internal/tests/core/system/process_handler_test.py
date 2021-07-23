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
"""Tests for process_handler."""

import unittest

import mock

from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class MockProcess(object):
  """Mock process."""

  def __init__(self, pid, name, cmdline):
    self._info = {
        'name': name,
        'pid': pid,
        'cmdline': cmdline,
    }

  def as_dict(self, attrs):  # pylint: disable=unused-argument
    return self._info


class TerminateProcessesMatchingNameTest(unittest.TestCase):
  """Tests terminate_processes_matching_names."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.process_handler.terminate_process',
        'psutil.process_iter',
    ])
    self.mock.process_iter.return_value = [
        MockProcess(1, 'process_1', ['/a/b/c', '-f1']),
        MockProcess(2, 'process_2', ['/d'])
    ]

  def test_process_1_with_terminate(self):
    process_handler.terminate_processes_matching_names('process_1')
    self.mock.terminate_process.assert_has_calls([
        mock.call(1, False),
    ])

  def test_process_1_with_kill(self):
    process_handler.terminate_processes_matching_names('process_1', kill=True)
    self.mock.terminate_process.assert_has_calls([
        mock.call(1, True),
    ])

  def test_process_2_with_terminate(self):
    process_handler.terminate_processes_matching_names('process_2')
    self.mock.terminate_process.assert_has_calls([
        mock.call(2, False),
    ])

  def test_process_2_with_kill(self):
    process_handler.terminate_processes_matching_names('process_2', kill=True)
    self.mock.terminate_process.assert_has_calls([
        mock.call(2, True),
    ])

  def test_no_process_terminate(self):
    process_handler.terminate_processes_matching_names('not_exist')
    self.assertEqual(0, self.mock.terminate_process.call_count)

  def test_no_process_kill(self):
    process_handler.terminate_processes_matching_names('not_exist', kill=True)
    self.assertEqual(0, self.mock.terminate_process.call_count)

  def test_no_process_terminate_with_partial_match(self):
    process_handler.terminate_processes_matching_names('process_')
    self.assertEqual(0, self.mock.terminate_process.call_count)

  def test_no_process_kill_with_partial_match(self):
    process_handler.terminate_processes_matching_names('process_', kill=True)
    self.assertEqual(0, self.mock.terminate_process.call_count)

  def test_process_1_no_terminate_with_wrong_case(self):
    process_handler.terminate_processes_matching_names('Process_1')
    self.assertEqual(0, self.mock.terminate_process.call_count)

  def test_process_1_no_kill_with_wrong_case(self):
    process_handler.terminate_processes_matching_names('Process_1', kill=True)
    self.assertEqual(0, self.mock.terminate_process.call_count)


class TerminateProcessesMatchingPathTest(unittest.TestCase):
  """Tests terminate_processes_matching_names."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.process_handler.terminate_process',
        'psutil.process_iter',
    ])
    self.mock.process_iter.return_value = [
        MockProcess(1, 'process_1', ['/a/b/c', '-f1']),
        MockProcess(2, 'process_2', ['/d'])
    ]

  def test_process_1_with_terminate(self):
    process_handler.terminate_processes_matching_cmd_line('c -f1')
    self.mock.terminate_process.assert_has_calls([
        mock.call(1, False),
    ])

  def test_process_1_with_kill(self):
    process_handler.terminate_processes_matching_cmd_line('/a/b/c', kill=True)
    self.mock.terminate_process.assert_has_calls([
        mock.call(1, True),
    ])

  def test_process_2_with_terminate(self):
    process_handler.terminate_processes_matching_cmd_line('/d')
    self.mock.terminate_process.assert_has_calls([
        mock.call(2, False),
    ])

  def test_process_2_with_kill(self):
    process_handler.terminate_processes_matching_cmd_line('/d', kill=True)
    self.mock.terminate_process.assert_has_calls([
        mock.call(2, True),
    ])

  def test_no_process_terminate(self):
    process_handler.terminate_processes_matching_cmd_line('not_exist')
    self.assertEqual(0, self.mock.terminate_process.call_count)

  def test_no_process_kill(self):
    process_handler.terminate_processes_matching_cmd_line(
        'not_exist', kill=True)
    self.assertEqual(0, self.mock.terminate_process.call_count)

  def test_process_1_no_terminate_with_wrong_case(self):
    process_handler.terminate_processes_matching_cmd_line('/a/b/C')
    self.assertEqual(0, self.mock.terminate_process.call_count)

  def test_process_1_no_kill_with_wrong_case(self):
    process_handler.terminate_processes_matching_cmd_line('/a/b/C', kill=True)
    self.assertEqual(0, self.mock.terminate_process.call_count)

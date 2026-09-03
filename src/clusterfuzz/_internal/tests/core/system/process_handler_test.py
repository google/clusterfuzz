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
from unittest import mock

from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class MockProcess:
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


class RunProcessAndroidTest(unittest.TestCase):
  """Tests run_process on Android platform."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.environment.platform',
        'clusterfuzz._internal.platforms.android.logger.clear_log',
        'clusterfuzz._internal.platforms.android.logger.log_output',
        'clusterfuzz._internal.platforms.android.adb.time_since_last_reboot',
        'clusterfuzz._internal.platforms.android.adb.run_command',
        'clusterfuzz._internal.platforms.android.adb.get_ps_output',
        'clusterfuzz._internal.platforms.android.app.get_package_name',
        'clusterfuzz._internal.platforms.android.app.stop',
        'clusterfuzz._internal.platforms.android.util.get_latest_pid_for_package',
        'clusterfuzz._internal.platforms.android.util.get_exit_info_for_pid',
        'clusterfuzz._internal.platforms.android.util.activity_crashed',
        'time.sleep',
    ])

    self.mock.platform.return_value = 'ANDROID'
    self.mock.get_package_name.return_value = 'com.example.app'
    self.mock.time_since_last_reboot.return_value = 100.0
    self.mock.log_output.return_value = ''
    self.mock.run_command.return_value = ''
    self.mock.get_ps_output.return_value = ''

  def test_run_process_android_activity_crashed(self):
    """Checks that run_process sets return_code from exit_info.reason and logs warning when an Android activity crash is detected."""
    exit_info = mock.Mock(reason=5, status=11)
    self.mock.get_latest_pid_for_package.return_value = 1234
    self.mock.get_exit_info_for_pid.return_value = exit_info
    self.mock.activity_crashed.return_value = True

    return_code, _, _ = process_handler.run_process(
        'am start -n com.example.app/.MainActivity')
    self.mock.activity_crashed.assert_called_once_with(exit_info)
    self.assertEqual(return_code, 5)

  def test_run_process_android_no_crash(self):
    """Checks that run_process returns 0 return_code when Android activity has not crashed."""
    self.mock.get_latest_pid_for_package.return_value = 1234
    self.mock.get_exit_info_for_pid.return_value = None
    self.mock.activity_crashed.return_value = False

    return_code, _, _ = process_handler.run_process(
        'am start -n com.example.app/.MainActivity')
    self.assertEqual(return_code, 0)

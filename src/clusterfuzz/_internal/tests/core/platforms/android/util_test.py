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
"""Tests process exit info parsing and activity crash utilities."""

import unittest

from clusterfuzz._internal.platforms.android import constants
from clusterfuzz._internal.platforms.android import util
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class GetLatestPidForPackageTest(unittest.TestCase):
  """Tests get_latest_pid_for_package."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.logger.log_activity_manager_output',
    ])

  def test_single_match(self):
    """Checks that get_latest_pid_for_package parses and returns PID for a matching package process start line."""
    self.mock.log_activity_manager_output.return_value = (
        'I/ActivityManager( 100): Start proc 1234:com.example.app/u0a123 '
        'for activity com.example.app/.MainActivity')
    pid = util.get_latest_pid_for_package('com.example.app')
    self.assertEqual(pid, 1234)

  def test_multiple_matches_returns_latest(self):
    """Checks that get_latest_pid_for_package returns the most recent PID when logcat contains multiple process start entries for the package."""
    self.mock.log_activity_manager_output.return_value = (
        'I/ActivityManager( 100): Start proc 1234:com.example.app/u0a123\n'
        'I/ActivityManager( 100): Start proc 5678:com.example.app/u0a123')
    pid = util.get_latest_pid_for_package('com.example.app')
    self.assertEqual(pid, 5678)

  def test_package_name_with_subprocess(self):
    """Checks that get_latest_pid_for_package matches subprocesses prefixed with the package name."""
    self.mock.log_activity_manager_output.return_value = (
        'I/ActivityManager( 100): Start proc 4321:com.example.app:sandboxed_process/u0a123'
    )
    pid = util.get_latest_pid_for_package('com.example.app')
    self.assertEqual(pid, 4321)

  def test_package_prefix_not_matched(self):
    """Checks that get_latest_pid_for_package does not match package names that only share a prefix."""
    self.mock.log_activity_manager_output.return_value = (
        'I/ActivityManager( 100): Start proc 9999:com.example.app2/u0a123')
    pid = util.get_latest_pid_for_package('com.example.app')
    self.assertIsNone(pid)

  def test_empty_logs_or_no_match(self):
    """Checks that get_latest_pid_for_package returns None when logcat is empty or contains no matching log lines."""
    self.mock.log_activity_manager_output.return_value = ''
    self.assertIsNone(util.get_latest_pid_for_package('com.example.app'))

    self.mock.log_activity_manager_output.return_value = (
        'I/ActivityManager( 100): Some unrelated log message')
    self.assertIsNone(util.get_latest_pid_for_package('com.example.app'))


# pylint: disable=protected-access
class ParseExitInfoFromDumpsysTest(unittest.TestCase):
  """Tests _parse_exit_info_from_dumpsys directly without mocking I/O."""

  def test_happy_path_parsed(self):
    """Checks that _parse_exit_info_from_dumpsys correctly parses dumpsys activity exit-info block for a matching target PID."""
    dumpsys_output = (
        'ApplicationExitInfo #0:\n'
        '  timestamp=1600000000 pid=4321 uid=10001 package=com.example.app\n'
        '  reason=5 (APP_CRASH(NATIVE)) subreason=0 (UNKNOWN) status=11\n')
    exit_info = util._parse_exit_info_from_dumpsys(dumpsys_output, 4321)
    self.assertEqual(
        exit_info,
        util.ProcessExitInfo(
            reason=constants.ExitReason.CRASH_NATIVE,
            reason_name='APP_CRASH(NATIVE)',
            subreason=0,
            subreason_name='UNKNOWN',
            status=constants.ExitStatus.SIGSEGV,
        ),
    )

  def test_missing_reason_names_in_parentheses(self):
    """Checks that _parse_exit_info_from_dumpsys parses numerical exit info when reason and subreason names are omitted in output."""
    dumpsys_output = ('ApplicationExitInfo #0:\n'
                      '  pid=4321 uid=10001\n'
                      '  reason=2 subreason=0 status=9\n')
    exit_info = util._parse_exit_info_from_dumpsys(dumpsys_output, 4321)
    self.assertEqual(
        exit_info,
        util.ProcessExitInfo(
            reason=constants.ExitReason.SIGNALED,
            reason_name='',
            subreason=0,
            subreason_name='',
            status=constants.ExitStatus.SIGKILL,
        ),
    )

  def test_pid_not_found(self):
    """Checks that _parse_exit_info_from_dumpsys returns None when the target PID is absent from dumpsys activity exit-info output."""
    dumpsys_output = (
        'ApplicationExitInfo #0:\n'
        '  pid=1111 uid=10001\n'
        '  reason=5 (APP_CRASH(NATIVE)) subreason=0 (UNKNOWN) status=11\n')
    exit_info = util._parse_exit_info_from_dumpsys(dumpsys_output, 4321)
    self.assertIsNone(exit_info)

  def test_dumpsys_output_empty(self):
    """Checks that _parse_exit_info_from_dumpsys returns None when dumpsys output is empty string or None."""
    self.assertIsNone(util._parse_exit_info_from_dumpsys('', 4321))
    self.assertIsNone(util._parse_exit_info_from_dumpsys(None, 4321))

  def test_malformed_reason_line(self):
    """Checks that _parse_exit_info_from_dumpsys returns None when pid matches but subsequent lines do not contain valid reason metadata."""
    dumpsys_output = ('ApplicationExitInfo #0:\n'
                      '  pid=4321 uid=10001\n'
                      '  invalid reason info block here\n'
                      '  another invalid line\n')
    exit_info = util._parse_exit_info_from_dumpsys(dumpsys_output, 4321)
    self.assertIsNone(exit_info)

  def test_unknown_exit_reason_or_status(self):
    """Checks that _parse_exit_info_from_dumpsys handles unknown reason or status integer codes gracefully."""
    dumpsys_output = (
        'ApplicationExitInfo #0:\n'
        '  pid=4321 uid=10001\n'
        '  reason=999 (UNKNOWN_FUTURE_REASON) subreason=0 (UNKNOWN) status=888\n'
    )
    exit_info = util._parse_exit_info_from_dumpsys(dumpsys_output, 4321)
    self.assertEqual(
        exit_info,
        util.ProcessExitInfo(
            reason=constants.ExitReason.UNKNOWN,
            reason_name='UNKNOWN_FUTURE_REASON',
            subreason=0,
            subreason_name='UNKNOWN',
            status=888,
        ),
    )


class GetExitInfoForPidTest(unittest.TestCase):
  """Tests get_exit_info_for_pid."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.adb.get_activity_exit_info',
    ])

  def test_fetches_and_parses(self):
    """Checks that get_exit_info_for_pid fetches output from adb and returns parsed ProcessExitInfo."""
    self.mock.get_activity_exit_info.return_value = (
        'ApplicationExitInfo #0:\n'
        '  timestamp=1600000000 pid=4321 uid=10001 package=com.example.app\n'
        '  reason=5 (APP_CRASH(NATIVE)) subreason=0 (UNKNOWN) status=11\n')
    exit_info = util.get_exit_info_for_pid('com.example.app', 4321)
    self.mock.get_activity_exit_info.assert_called_once_with('com.example.app')
    self.assertEqual(
        exit_info,
        util.ProcessExitInfo(
            reason=constants.ExitReason.CRASH_NATIVE,
            reason_name='APP_CRASH(NATIVE)',
            subreason=0,
            subreason_name='UNKNOWN',
            status=constants.ExitStatus.SIGSEGV,
        ),
    )

  def test_none_pid(self):
    """Checks that get_exit_info_for_pid returns None when target_pid is None."""
    self.assertIsNone(util.get_exit_info_for_pid('com.example.app', None))


class ActivityCrashedTest(unittest.TestCase):
  """Tests activity_crashed."""

  def test_crash_app_crash_native(self):
    """Checks that activity_crashed returns True for CRASH_NATIVE with status SIGSEGV."""
    exit_info = util.ProcessExitInfo(
        reason=constants.ExitReason.CRASH_NATIVE,
        reason_name='APP_CRASH(NATIVE)',
        subreason=0,
        subreason_name='',
        status=constants.ExitStatus.SIGSEGV,
    )
    self.assertTrue(util.activity_crashed(exit_info))

  def test_crash_signaled(self):
    """Checks that activity_crashed returns True for SIGNALED with status SIGKILL."""
    exit_info = util.ProcessExitInfo(
        reason=constants.ExitReason.SIGNALED,
        reason_name='SIGNALED',
        subreason=0,
        subreason_name='',
        status=constants.ExitStatus.SIGKILL,
    )
    self.assertTrue(util.activity_crashed(exit_info))

  def test_crash_anr(self):
    """Checks that activity_crashed returns True for CRASH."""
    exit_info = util.ProcessExitInfo(
        reason=constants.ExitReason.CRASH,
        reason_name='CRASH',
        subreason=0,
        subreason_name='',
        status=0,
    )
    self.assertTrue(util.activity_crashed(exit_info))

  def test_normal_exit_reason(self):
    """Checks that activity_crashed returns False for normal exit reason EXIT_SELF."""
    exit_info = util.ProcessExitInfo(
        reason=constants.ExitReason.EXIT_SELF,
        reason_name='EXIT_SELF',
        subreason=0,
        subreason_name='',
        status=0,
    )
    self.assertFalse(util.activity_crashed(exit_info))

  def test_crash_reason_untracked_status(self):
    """Checks that activity_crashed returns False for CRASH_NATIVE when status is not in crash signal list."""
    exit_info = util.ProcessExitInfo(
        reason=constants.ExitReason.CRASH_NATIVE,
        reason_name='APP_CRASH',
        subreason=0,
        subreason_name='',
        status=0,
    )
    self.assertFalse(util.activity_crashed(exit_info))

  def test_none_exit_info(self):
    """Checks that activity_crashed returns False when exit_info is None."""
    self.assertFalse(util.activity_crashed(None))


class ActivityCrashedByPackageTest(unittest.TestCase):
  """Tests activity_crashed_by_package."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.util.get_latest_pid_for_package',
        'clusterfuzz._internal.platforms.android.util.get_exit_info_for_pid',
    ])

  def test_fetch_crashed(self):
    """Checks that activity_crashed_by_package fetches PID and exit info dynamically and returns True for crash."""
    self.mock.get_latest_pid_for_package.return_value = 1234
    self.mock.get_exit_info_for_pid.return_value = util.ProcessExitInfo(
        reason=4, reason_name='ANR', subreason=0, subreason_name='', status=0)
    self.assertTrue(util.activity_crashed_by_package('com.example.app'))
    self.mock.get_latest_pid_for_package.assert_called_once_with(
        'com.example.app')
    self.mock.get_exit_info_for_pid.assert_called_once_with(
        'com.example.app', 1234)

  def test_no_pid(self):
    """Checks that activity_crashed_by_package returns False when no PID is found for package."""
    self.mock.get_latest_pid_for_package.return_value = None
    self.assertFalse(util.activity_crashed_by_package('com.example.app'))

  def test_no_exit_info(self):
    """Checks that activity_crashed_by_package returns False when PID is found but get_exit_info_for_pid returns None."""
    self.mock.get_latest_pid_for_package.return_value = 1234
    self.mock.get_exit_info_for_pid.return_value = None
    self.assertFalse(util.activity_crashed_by_package('com.example.app'))

  def test_empty_package(self):
    """Checks that activity_crashed_by_package returns False when app_package is empty."""
    self.assertFalse(util.activity_crashed_by_package(''))

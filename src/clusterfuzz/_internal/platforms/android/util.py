# Copyright 2022 Google LLC
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
"""Utility functions for Android device."""

from dataclasses import dataclass
import os
import re

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.system import environment

from . import adb
from . import constants
from . import logger

# Matching: "Start proc <PID>:<PROCESS_NAME>/"
_START_PROC_REGEX = r"Start proc (\d+):(\S+?)/"

# Matching: "reason=<REASON> (<REASON_NAME>) subreason=<SUBREASON>"
# "(<SUBREASON_NAME>) status=<STATUS>"
# e.g.: "reason=5 (APP_CRASH(NATIVE)) subreason=0 (UNKNOWN) status=11" or
# "reason=2 (SIGNALED) subreason=0 (UNKNOWN) status=9"
_REASON_STATUS_REGEX = (r"reason=(\d+)(?:\s*\((.*)\))?\s+subreason=(\d+)"
                        r"(?:\s*\((.*)\))?\s+status=(\d+)")


@dataclass(frozen=True)
class ProcessExitInfo:
  """DTO representing process exit metadata from dumpsys activity exit-info.

  For a full list of android exit info reasons and subreasons, see:
  https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/proto_logging/stats/enums/app_shared/app_enums.proto;l=270?q=content:subreason
  """

  reason: android.constants.ExitReason | int
  reason_name: str  # e.g., 'APP_CRASH(NATIVE)', 'SIGNALED'
  subreason: int
  subreason_name: str  # e.g., 'UNKNOWN', 'ISOLATED_NOT_NEEDED'
  status: android.constants.ExitStatus | int


def _to_enum(enum_cls, raw_value: int | str):
  """Converts raw_value to an Enum member, or returns None if invalid."""
  try:
    return enum_cls(int(raw_value))
  except (ValueError, TypeError):
    return None


def _parse_exit_info_from_dumpsys(dumpsys_output: str,
                                  target_pid: int) -> ProcessExitInfo | None:
  """Parses dumpsys activity exit-info output for target_pid.

  Args:
    dumpsys_output: Output text from `dumpsys activity exit-info`.
    target_pid: Process ID to extract exit metadata for.

  Returns:
    ProcessExitInfo object if metadata for target_pid is found and parsed,
    None otherwise.
  """
  if not dumpsys_output or target_pid is None:
    return None

  current_pid = None
  for line in dumpsys_output.splitlines():
    pid_match = re.search(r"\bpid=(\d+)", line)
    if pid_match:
      current_pid = int(pid_match.group(1))

    if current_pid is None or current_pid != target_pid:
      continue

    reason_match = re.search(_REASON_STATUS_REGEX, line)
    if not reason_match:
      continue

    reason, reason_name, subreason, subreason_name, status = (
        reason_match.groups())

    parsed_reason = _to_enum(constants.ExitReason, reason)
    if parsed_reason is None:
      logs.warning(f'[Android] Unexpected process exit reason code {reason} '
                   f'for PID {target_pid}.')
      parsed_reason = constants.ExitReason.UNKNOWN

    parsed_status = _to_enum(constants.ExitStatus, status)
    if parsed_status is None:
      logs.warning(f'[Android] Unexpected process exit status code {status} '
                   f'for PID {target_pid}.')
      parsed_status = int(status)

    return ProcessExitInfo(
        reason=parsed_reason,
        reason_name=reason_name or '',
        subreason=int(subreason),
        subreason_name=subreason_name or '',
        status=parsed_status,
    )

  return None


def get_device_path(local_path):
  """Returns device path for the given local path."""
  root_directory = environment.get_root_directory()
  return os.path.join(android.constants.DEVICE_FUZZING_DIR,
                      os.path.relpath(local_path, root_directory))


def get_local_path(device_path):
  """Returns local path for the given device path."""
  if not device_path.startswith(android.constants.DEVICE_FUZZING_DIR + '/'):
    logs.error('Bad device path: ' + device_path)
    return None

  root_directory = environment.get_root_directory()
  return os.path.join(
      root_directory,
      os.path.relpath(device_path, android.constants.DEVICE_FUZZING_DIR))


def is_testcase_deprecated(platform_id=None):
  """Whether or not the Android device is deprecated."""

  # Platform ID for Android is of the form as shown below
  # |android:{codename}_{sanitizer}:{build_version}|
  platform_id_fields = platform_id.split(':')
  if len(platform_id_fields) != 3:
    return False

  codename_fields = platform_id_fields[1].split('_')

  # Check if device is deprecated
  if codename_fields[0] in android.constants.DEPRECATED_DEVICE_LIST:
    return True

  # Check if branch is deprecated
  # Currently only "main" or "m" is active
  # All other branches including "master" have been deprecated
  branch = platform_id_fields[2]
  if (branch <= 'v' or branch == 'master') and branch != 'm':
    return True

  return False


def can_testcase_run_on_platform(testcase_platform_id, current_platform_id):
  """Whether or not the testcase can run on the current Android device."""

  del testcase_platform_id  # Unused argument for now

  # Platform ID for Android is of the form as shown below
  # |android:{codename}_{sanitizer}:{build_version}|
  current_platform_id_fields = current_platform_id.split(':')
  if len(current_platform_id_fields) != 3:
    return False

  # Deprecated testcase should run on any latest device and on main
  # So ignore device information and check for current version
  # If the current version is 'm' or main, run the test case
  if current_platform_id_fields[2] == 'm':
    return True

  # Check for the trunk stable versions - Z, A, B.
  # Source: go/release-version_trunk-stable#examples
  # If the current version is 'Z', 'A' or 'B', run the test case
  # Note: Use lowercase as platform_id is in lowercase
  android_trunk_stable_versions = ['z', 'a', 'b']
  if current_platform_id_fields[2].lower() in android_trunk_stable_versions:
    return True

  return False


def get_latest_pid_for_package(app_package: str) -> int | None:
  """Gets the latest PID for an application package from logcat.

  Args:
    app_package: Name of the target application package.

  Returns:
    PID of the package's latest process if found, None otherwise.
  """
  logcat_output = logger.log_activity_manager_output()
  if not logcat_output:
    logs.info(f'[Android][{app_package}] PID not found, no logcat output')
    return None

  for line in reversed(logcat_output.splitlines()):
    match = re.search(_START_PROC_REGEX, line)
    if not match:
      continue

    pid, process_name = match.groups()
    if process_name == app_package or process_name.startswith(
        f'{app_package}:'):
      return int(pid)
  return None


def get_exit_info_for_pid(app_package: str,
                          target_pid: int) -> ProcessExitInfo | None:
  """Fetches and parses dumpsys activity exit-info output for target_pid.

  Args:
    app_package: Name of the application package.
    target_pid: Process ID to extract exit metadata for.

  Returns:
    ProcessExitInfo object if metadata for target_pid is found and parsed,
    None otherwise.
  """
  if target_pid is None:
    logs.info(f'[Android][{app_package}] Exit info not found, PID not given')
    return None

  dumpsys_output = adb.get_activity_exit_info(app_package)
  return _parse_exit_info_from_dumpsys(dumpsys_output, target_pid)


def activity_crashed(exit_info: ProcessExitInfo | None) -> bool:
  """Evaluates whether process exit info corresponds to an activity crash.

  Args:
    exit_info: ProcessExitInfo instance or None.

  Returns:
    True if exit_info indicates an activity crash, False otherwise.
  """
  if not exit_info:
    logs.warning('[Android] Exit info empty, not checking for crashes.')
    return False

  if exit_info.reason in (constants.ExitReason.CRASH_NATIVE,
                          constants.ExitReason.SIGNALED):
    return exit_info.status in (
        constants.ExitStatus.SIGSEGV,
        constants.ExitStatus.SIGKILL,
        constants.ExitStatus.SIGABRT,
        constants.ExitStatus.SIGILL,
    )
  if exit_info.reason == constants.ExitReason.CRASH:
    return True
  return False


def activity_crashed_by_package(app_package: str) -> bool:
  """Checks whether the latest process for a package crashed.

  Args:
    app_package: Name of the application package to check.

  Returns:
    True if the package's latest process crashed, False otherwise.
  """
  if not app_package:
    logs.warning(f'[Android][{app_package}] App package not given, '
                 'not checking for crashes.')
    return False

  pid = get_latest_pid_for_package(app_package)

  exit_info = get_exit_info_for_pid(app_package, pid)
  return activity_crashed(exit_info)

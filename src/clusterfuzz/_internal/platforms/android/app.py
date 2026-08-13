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
"""Apps related functions."""

import os
import re
import time
from typing import Any
from typing import cast

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

from . import adb
from . import constants

AAPT_CMD_TIMEOUT: int = 60
CHROME_CACHE_DIRS: list[str] = [
    'app_chrome/*', 'app_tabs/*', 'app_textures/*', 'cache/*', 'files/*',
    'shared_prefs/*'
]
PACKAGES_THAT_CRASH_WITH_GESTURES: list[str] = [
    'com.android.printspooler',
    'com.android.settings',
]
PACKAGE_OPTIMIZATION_INTERVAL: int = 30
PACKAGE_OPTIMIZATION_TIMEOUT: int = 30 * 60


def disable_packages_that_crash_with_gestures() -> None:
  """Disable known packages that crash on gesture fuzzing."""
  for package in PACKAGES_THAT_CRASH_WITH_GESTURES:
    adb.run_shell_command(['pm', 'disable-user', package])


def get_launch_command(app_args: str, testcase_path: str,
                       testcase_file_url: str) -> str:
  """Get command to launch application with an optional testcase path."""
  application_launch_command = environment.get_value('APP_LAUNCH_COMMAND')
  if not application_launch_command:
    return ''

  package_name = get_package_name() or ''

  application_launch_command = application_launch_command.replace(
      '%APP_ARGS%', app_args)
  application_launch_command = application_launch_command.replace(
      '%DEVICE_TESTCASES_DIR%', constants.DEVICE_TESTCASES_DIR)
  application_launch_command = application_launch_command.replace(
      '%PKG_NAME%', package_name)
  application_launch_command = application_launch_command.replace(
      '%TESTCASE%', testcase_path)
  application_launch_command = application_launch_command.replace(
      '%TESTCASE_FILE_URL%', testcase_file_url)

  return application_launch_command


def get_package_name(apk_path: str | None = None) -> str | None:
  """Return package name."""
  # See if our environment is already set with this info.
  package_name = environment.get_value('PKG_NAME')
  if package_name:
    return package_name

  # See if we have the apk available to derive this info.
  if not apk_path:
    # Try getting apk path from APP_PATH.
    apk_path = environment.get_value('APP_PATH')
    if not apk_path:
      return None

  # Make sure that apk has the correct extension.
  if not apk_path.endswith('.apk'):
    return None

  # Try retrieving package name using aapt.
  aapt_binary_path = os.path.join(
      environment.get_platform_resources_directory(), 'aapt')
  aapt_command = '%s dump badging %s' % (aapt_binary_path, apk_path)
  output = adb.execute_command(aapt_command, timeout=AAPT_CMD_TIMEOUT)
  match = re.match('.*package: name=\'([^\']+)\'', cast(str, output), re.DOTALL)
  if not match:
    return None
  return match.group(1)


def install(package_apk_path: str, **kwargs: Any) -> Any:
  """Install a package from an apk path.

  Args:
    package_apk_path: Path to the apk file to install.
    **kwargs: Additional arguments to pass to the install command.
  """
  cmd = ['install', '-r']
  for key, value in kwargs.items():
    if not value:
      continue

    flag = '-' + key if len(key) == 1 else '--' + key.replace('_', '-')
    cmd.append(flag)
    if not isinstance(value, bool):
      cmd.append(str(value))

  cmd.append(package_apk_path)
  return adb.run_command(cmd)


def is_installed(package_name: str) -> bool:
  """Checks if the app is installed."""
  output = adb.run_shell_command(['pm', 'list', 'packages'])
  package_names = [
      line.split(':')[-1] for line in cast(str, output).splitlines()
  ]

  return package_name in package_names


def reset() -> None:
  """Reset to original clean state and kills pending instances."""
  package_name = get_package_name()
  if not package_name:
    return

  # Make sure package is actually installed.
  if not is_installed(package_name):
    return

  # Clean package state.
  adb.run_shell_command(['pm', 'clear', package_name])

  # Re-grant storage permissions.
  adb.run_shell_command(
      ['pm', 'grant', package_name, 'android.permission.READ_EXTERNAL_STORAGE'])
  adb.run_shell_command([
      'pm', 'grant', package_name, 'android.permission.WRITE_EXTERNAL_STORAGE'
  ])


def stop() -> None:
  """Stop application and cleanup state."""
  package_name = get_package_name()
  if not package_name:
    return

  # Device can get silently restarted in case of OOM. So, we would need to
  # restart our shell as root in order to kill the application.
  adb.run_as_root()

  adb.kill_processes_and_children_matching_name(package_name)

  # Chrome specific cleanup.
  if package_name.endswith('.chrome'):
    cache_dirs_absolute_paths = [
        '/data/data/%s/%s' % (package_name, i) for i in CHROME_CACHE_DIRS
    ]
    adb.run_shell_command(
        ['rm', '-rf', ' '.join(cache_dirs_absolute_paths)], root=True)


def uninstall(package_name: str) -> Any:
  """Uninstall a package given a name."""
  return adb.run_command(['uninstall', package_name])


def wait_until_optimization_complete() -> None:
  """Waits for package optimization to finish."""
  start_time = time.time()

  while time.time() - start_time < PACKAGE_OPTIMIZATION_TIMEOUT:
    ps_output = cast(str, adb.get_ps_output())
    package_optimization_finished = 'dex2oat' not in ps_output
    if package_optimization_finished:
      return

    logs.info('Waiting for package optimization to finish.')
    time.sleep(PACKAGE_OPTIMIZATION_INTERVAL)

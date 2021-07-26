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

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

from . import adb
from . import constants

AAPT_CMD_TIMEOUT = 60
CHROME_CACHE_DIRS = [
    'app_chrome/*', 'app_tabs/*', 'app_textures/*', 'cache/*', 'files/*',
    'shared_prefs/*'
]
PACKAGES_THAT_CRASH_WITH_GESTURES = [
    'com.android.printspooler',
    'com.android.settings',
]
PACKAGE_OPTIMIZATION_INTERVAL = 30
PACKAGE_OPTIMIZATION_TIMEOUT = 30 * 60


def disable_packages_that_crash_with_gestures():
  """Disable known packages that crash on gesture fuzzing."""
  for package in PACKAGES_THAT_CRASH_WITH_GESTURES:
    adb.run_shell_command(['pm', 'disable-user', package], log_error=False)


def get_launch_command(app_args, testcase_path, testcase_file_url):
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


def get_package_name(apk_path=None):
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
  match = re.match('.*package: name=\'([^\']+)\'', output, re.DOTALL)
  if not match:
    return None
  return match.group(1)


def install(package_apk_path):
  """Install a package from an apk path."""
  return adb.run_command(['install', '-r', package_apk_path])


def is_installed(package_name):
  """Checks if the app is installed."""
  output = adb.run_shell_command(['pm', 'list', 'packages'])
  package_names = [line.split(':')[-1] for line in output.splitlines()]

  return package_name in package_names


def reset():
  """Reset to original clean state and kills pending instances."""
  package_name = get_package_name()
  if not package_name:
    return

  # Make sure package is actually installed.
  if not is_installed(package_name):
    return

  # Before clearing package state, save the minidumps.
  save_crash_minidumps(package_name)

  # Clean package state.
  adb.run_shell_command(['pm', 'clear', package_name])

  # Re-grant storage permissions.
  adb.run_shell_command(
      ['pm', 'grant', package_name, 'android.permission.READ_EXTERNAL_STORAGE'])
  adb.run_shell_command([
      'pm', 'grant', package_name, 'android.permission.WRITE_EXTERNAL_STORAGE'
  ])


def save_crash_minidumps(package_name):
  """Retain crash minidumps before app reset (chrome only)."""
  if package_name != 'com.google.android.apps.chrome':
    return

  # Ignore errors when running this command. Adding directory list check is
  # another adb call and since this is called frequently, we need to avoid that
  # extra call.
  adb.run_shell_command(
      ['cp', '/data/data/cache/Crash\\ Reports/*', constants.CRASH_DUMPS_DIR],
      log_error=False,
      root=True)


def stop():
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
    save_crash_minidumps(package_name)
    adb.run_shell_command(
        ['rm', '-rf', ' '.join(cache_dirs_absolute_paths)], root=True)


def uninstall(package_name):
  """Uninstall a package given a name."""
  return adb.run_command(['uninstall', package_name])


def wait_until_optimization_complete():
  """Waits for package optimization to finish."""
  start_time = time.time()

  while time.time() - start_time < PACKAGE_OPTIMIZATION_TIMEOUT:
    package_optimization_finished = 'dex2oat' not in adb.get_ps_output()
    if package_optimization_finished:
      return

    logs.log('Waiting for package optimization to finish.')
    time.sleep(PACKAGE_OPTIMIZATION_INTERVAL)

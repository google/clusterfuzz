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
"""ADB shell related functions."""

import collections
import os
import re
import signal
import subprocess
import tempfile
import threading
import time

from base import persistent_cache
from base import utils
from datastore import data_types
from google_cloud_utils import compute_engine
from metrics import logs
from system import environment

ADB_TIMEOUT = 1200  # Should be lower than |REBOOT_TIMEOUT|.
AAPT_CMD_TIMEOUT = 60
BAD_STATE_WAIT = 900
BOOT_WAIT_INTERVAL = 30
CHROME_CACHE_DIRS = [
    'app_chrome/*', 'app_tabs/*', 'app_textures/*', 'cache/*', 'files/*',
    'shared_prefs/*'
]
CHROME_CRASH_DIR = 'cache/Crash\\ Reports'
DEVICE = collections.namedtuple('Device', ['serial', 'path'])
DEVICE_COVERAGE_DIR = '/data/local/tmp/c'
DEVICE_CRASH_DUMPS_DIR = '/sdcard/crash-reports'
DEVICE_DOWNLOAD_DIR = '/sdcard/Download'
DEVICE_HANG_STRING = None
DEVICE_NOT_FOUND_STRING = 'error: device not found'
DEVICE_OFFLINE_STRING = 'error: device offline'
DEVICE_TESTCASES_DIR = '/sdcard/fuzzer-testcases'
DEVICE_TMP_DIR = '/data/local/tmp'
FACTORY_RESET_WAIT = 60
FLASH_INTERVAL = 1 * 24 * 60 * 60
GCE_PREIMAGE_METADATA_KEY = 'cfg_sta_data_preimage_device'
MONKEY_PROCESS_NAME = 'monkey'
PACKAGE_OPTIMIZATION_INTERVAL = 30
PACKAGES_THAT_CRASH_WITH_GESTURES = [
    'com.android.music', 'com.android.printspooler', 'com.android.settings'
]
REBOOT_TIMEOUT = 3600
RECOVERY_CMD_TIMEOUT = 60
REMOTE_CONNECT_RETRIES = 25
REMOTE_CONNECT_SLEEP = 25
REMOTE_CONNECT_TIMEOUT = 10
REMOTE_REBOOT_TIMEOUT = 5
REMOTE_RECREATE_TIMEOUT = 5 * 60
RESTART_USB_WAIT = 20

# Output patterns to parse "lsusb" output.
LSUSB_BUS_RE = re.compile(r'Bus\s+(\d+)\s+Device\s+(\d+):.*')
LSUSB_SERIAL_RE = re.compile(r'\s+iSerial\s+\d\s+(.*)')

# MD5 paths and commands for file checksumming.
MD5_PATH_TO_COMMAND = {
    '/system/bin/md5sum':
        lambda path: run_adb_shell_command(['md5sum', '-b', path]),
    '/system/bin/md5':
        lambda path: run_adb_shell_command(['md5', path]).split(' ')[0]
}
# We want to be able to impose an order in which to check command
# existence: consider the situation where a new checksum command is
# implemented, with better performance, but the old checksum commands
# still exist for backwards compatibility. We probably want to use the
# new one, so we check for it first.
MD5_PATHS_TO_TRY_IN_ORDER = ['/system/bin/md5sum', '/system/bin/md5']

# This is a constant value defined in usbdevice_fs.h in Linux system.
USBDEVFS_RESET = ord('U') << 8 | 20


def bad_state_reached():
  """Wait when device is in a bad state and exit."""
  time.sleep(BAD_STATE_WAIT)
  persistent_cache.clear_values()
  logs.log_fatal_and_exit('Device in bad state.')


def change_se_linux_to_permissive_mode():
  """Switch SELinux to permissive mode for working around local file access and
  other issues."""
  run_adb_shell_command(['setenforce', '0'])


def reset_application_state():
  """Resets application to original clean state and kills pending instances."""
  package_name = get_package_name()
  if not package_name:
    return

  # Make sure package is actually installed.
  if not is_package_installed(package_name):
    return

  # Before clearing package state, save the minidumps.
  save_crash_minidumps(package_name)

  # Clean package state.
  run_adb_shell_command(['pm', 'clear', package_name])

  # Re-grant storage permissions.
  run_adb_shell_command(
      ['pm', 'grant', package_name, 'android.permission.READ_EXTERNAL_STORAGE'])
  run_adb_shell_command([
      'pm', 'grant', package_name, 'android.permission.WRITE_EXTERNAL_STORAGE'
  ])


def clear_notifications():
  """Clear all pending notifications."""
  run_adb_shell_command(['service', 'call', 'notification', '1'])


def connect_remote(num_retries=REMOTE_CONNECT_RETRIES, reconnect=False):
  """Connect to the remote device. Returns whether if we succeeded."""
  # Note: we use get_adb_command_line/execute_command explicitly as
  # run_adb_command could call this function for recovery.
  device_state = get_device_state()
  if not reconnect and device_state == 'device':
    # Already connected, nothing to do here. Note that this is not a very good
    # check for the health of the connection.
    return False

  # First try to disconnect from the device.
  device_serial = environment.get_value('ANDROID_SERIAL')
  disconnect_cmd = get_adb_command_line('disconnect %s' % device_serial)
  execute_command(
      disconnect_cmd, timeout=REMOTE_CONNECT_TIMEOUT, log_error=True)

  # Now try to connect, retrying if needed.
  connect_cmd = get_adb_command_line('connect %s' % device_serial)
  for i in xrange(num_retries + 1):
    output = execute_command(
        connect_cmd, timeout=REMOTE_CONNECT_TIMEOUT, log_error=False)
    if output and 'connected to ' in output:
      # We must check the device state again, as ADB connection establishment
      # is just a simple TCP connection establishment with no extra checks.
      if get_device_state() == 'device':
        logs.log('Reconnected to remote device after %d tries.' % (i + 1))
        return True
      else:
        # False connection, disconnect so ADB lets us connect again.
        execute_command(
            disconnect_cmd, timeout=REMOTE_CONNECT_TIMEOUT, log_error=True)

    time.sleep(REMOTE_CONNECT_SLEEP)

  logs.log_warn('Failed to reconnect to remote device.')
  return False


def copy_local_directory_to_remote(local_directory, remote_directory):
  """Copies local directory contents to remote directory."""
  create_directory_if_needed(remote_directory)
  run_adb_command(['push', '%s/*' % local_directory, remote_directory])


def copy_remote_directory_to_local(remote_directory, local_directory):
  """Copies local directory contents to remote directory."""
  run_adb_command(['pull', '%s/.' % remote_directory, local_directory])


def create_directory_if_needed(device_directory):
  """Creates a directory on the device if it doesn't already exist."""
  run_adb_shell_command(['mkdir', '-p', device_directory])


def directory_exists(directory_path):
  """Return whether a directory exists or not."""
  expected = '0'
  result = run_adb_shell_command(
      '\'test -d "%s"; echo $?\'' % directory_path, log_error=False)
  return result == expected


def disable_airplane_mode():
  """Disable airplane mode."""
  run_adb_shell_command(['settings', 'put', 'global', 'airplane_mode_on', '0'])
  run_adb_shell_command([
      'am', 'broadcast', '-a', 'android.intent.action.AIRPLANE_MODE', '--ez',
      'state', 'false'
  ])


def disable_packages_that_crash_with_gestures():
  """Disable packages that crash on gestures."""
  for package in PACKAGES_THAT_CRASH_WITH_GESTURES:
    run_adb_shell_command(['pm', 'disable-user', package], log_error=False)


def disable_wifi():
  """Disable wifi."""
  run_adb_shell_command(['svc', 'wifi', 'disable'])


def enable_wifi():
  """Enable wifi."""
  run_adb_shell_command(['svc', 'wifi', 'enable'])


def execute_command(cmd, timeout=None, log_error=True):
  """Spawns a subprocess to run the given shell command."""
  so = []
  output_dest = tempfile.TemporaryFile(bufsize=0)
  pipe = subprocess.Popen(
      cmd,
      executable='/bin/bash',
      stdout=output_dest,
      stderr=subprocess.STDOUT,
      shell=True,
      close_fds=True,
      preexec_fn=lambda: signal.signal(signal.SIGPIPE, signal.SIG_DFL))

  def run():
    """Thread target function that waits for subprocess to complete."""
    try:
      pipe.communicate()
      output_dest.seek(0)
      output = output_dest.read()
      output_dest.close()
      if output:
        so.append(output)
    except OSError:
      logs.log_warn('Failed to retrieve stdout from: %s' % cmd)
    if pipe.returncode:
      if log_error:
        logs.log_warn(
            '%s returned %d error code.' % (cmd, pipe.returncode),
            output=''.join(so).strip())

  thread = threading.Thread(target=run)
  thread.start()
  thread.join(timeout)
  if thread.isAlive():
    try:
      pipe.kill()
    except OSError:
      # Can't kill a dead process.
      pass

    return None

  output = ''.join(so)
  return output.strip()


def factory_reset():
  """Reset device to factory state."""
  # A device can be stuck in a boot loop due to a bad clang library update.
  # Reverting that can bring a device back to good state.
  revert_asan_device_setup_if_needed()

  run_as_root()
  run_adb_shell_command(
      ['am', 'broadcast', '-a', 'android.intent.action.MASTER_CLEAR'])

  # Wait until the reset is complete.
  time.sleep(FACTORY_RESET_WAIT)


def file_exists(file_path):
  """Return whether a file exists or not."""
  expected = '0'
  result = run_adb_shell_command(
      '\'test -f "%s"; echo $?\'' % file_path, log_error=False)
  return result == expected


def get_adb_command_line(adb_cmd):
  """Return adb command line for running an adb command."""
  device_serial = environment.get_value('ANDROID_SERIAL')
  adb_cmd_line = '%s -s %s %s' % (get_adb_path(), device_serial, adb_cmd)
  return adb_cmd_line


def get_adb_path():
  """Return path to ADB binary."""
  adb_path = environment.get_value('ADB_PATH')
  if adb_path:
    return adb_path

  return os.path.join(environment.get_platform_resources_directory(), 'adb')


def get_application_launch_command(app_args, testcase_path, testcase_file_url):
  """Launches application with an optional testcase path."""
  application_launch_command = environment.get_value('APP_LAUNCH_COMMAND')
  if not application_launch_command:
    return ''

  package_name = get_package_name() or ''

  application_launch_command = application_launch_command.replace(
      '%APP_ARGS%', app_args)
  application_launch_command = application_launch_command.replace(
      '%DEVICE_TESTCASES_DIR%', DEVICE_TESTCASES_DIR)
  application_launch_command = application_launch_command.replace(
      '%PKG_NAME%', package_name)
  application_launch_command = application_launch_command.replace(
      '%TESTCASE%', testcase_path)
  application_launch_command = application_launch_command.replace(
      '%TESTCASE_FILE_URL%', testcase_file_url)

  return application_launch_command


def get_device_path():
  """Return device path."""
  if environment.get_value('ANDROID_GCE'):
    return ''

  devices = get_devices()
  device_serial = environment.get_value('ANDROID_SERIAL')
  for device in devices:
    if device_serial == device.serial:
      return device.path

  return ''


def get_devices():
  """Returns a list of device objects containing a serial and USB path."""
  usb_list_cmd = 'lsusb -v'
  output = execute_command(
      usb_list_cmd, timeout=RECOVERY_CMD_TIMEOUT, log_error=True)
  if output is None:
    logs.log_error('Failed to populate usb devices using lsusb, '
                   'host restart might be needed.')
    bad_state_reached()

  devices = []
  path = None
  for line in output.splitlines():
    match = LSUSB_BUS_RE.match(line)
    if match:
      path = '/dev/bus/usb/%s/%s' % (match.group(1), match.group(2))
      continue

    match = LSUSB_SERIAL_RE.match(line)
    if path and match and match.group(1):
      serial = match.group(1)
      devices.append(DEVICE(serial, path))

  return devices


def get_device_state():
  """Return the device status."""
  state_cmd = get_adb_command_line('get-state')
  return execute_command(
      state_cmd, timeout=RECOVERY_CMD_TIMEOUT, log_error=True)


def get_fastboot_command_line(fastboot_cmd):
  """Return fastboot command line for running a fastboot command."""
  fastboot_cmd_line = '%s %s' % (get_fastboot_path(), fastboot_cmd)
  return fastboot_cmd_line


def get_fastboot_path():
  """Return path to fastboot binary."""
  return os.path.join(environment.get_platform_resources_directory(),
                      'fastboot')


def get_file_checksum(file_path):
  """Return file's md5 checksum."""
  # Get the correct md5 checksum command to run.
  if not hasattr(get_file_checksum, 'md5_command'):
    get_file_checksum.md5_command = None
    for md5_path in MD5_PATHS_TO_TRY_IN_ORDER:
      if file_exists(md5_path):
        get_file_checksum.md5_command = MD5_PATH_TO_COMMAND[md5_path]
        break

  # We should have a command to run: apply it, if the file exists.
  if get_file_checksum.md5_command is not None and file_exists(file_path):
    return get_file_checksum.md5_command(file_path)

  return None


def get_memory_usage_info():
  """Return memory stats."""
  return run_adb_shell_command(['ps'])


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
  if not apk_path.endswith(data_types.ANDROID_APP_EXTENSION):
    return None

  # Try retrieving package name using aapt.
  aapt_binary_path = os.path.join(
      environment.get_platform_resources_directory(), 'aapt')
  aapt_command = '%s dump badging %s' % (aapt_binary_path, apk_path)
  output = execute_command(aapt_command, timeout=AAPT_CMD_TIMEOUT)
  match = re.match('.*package: name=\'([^\']+)\'', output, re.DOTALL)
  if not match:
    return None

  package_name = match.group(1)
  return package_name


def get_process_and_child_pids(process_name):
  """Return process and child pids matching a process name."""
  pids = []
  ps_output = get_memory_usage_info()
  ps_output_lines = ps_output.splitlines()

  while True:
    old_pids_length = len(pids)
    for line in ps_output_lines:
      data = line.split()

      # Make sure we have a valid pid and parent pid.
      try:
        # PID is in the second column.
        line_process_pid = int(data[1])
        # Parent PID is in the third column.
        line_parent_pid = int(data[2])
      except:
        continue

      # If we have already processed this pid, no more work to do.
      if line_process_pid in pids:
        continue

      # Process name is in the last column.
      # Monkey framework instances (if any) are children of our process launch,
      # so include these in pid list.
      line_process_name = data[-1]
      if (process_name in line_process_name or
          MONKEY_PROCESS_NAME in line_process_name):
        if process_name == line_process_name:
          pids.insert(0, line_process_pid)
        else:
          pids.append(line_process_pid)
        continue

      # Add child pids to end.
      if line_parent_pid in pids:
        pids.append(line_process_pid)

    new_pids_length = len(pids)
    if old_pids_length == new_pids_length:
      break

  return pids


def get_property(property_name):
  """Return property's value."""
  return run_adb_shell_command(['getprop', property_name])


def hard_reset():
  """Perform a hard reset of the device."""
  if environment.get_value('ANDROID_GCE'):
    if reset_virtual_device():
      # We successfully recovered.
      return

    if recreate_virtual_device():
      # We successfully recovered.
      return

    # Nothing more we can do if this fails too.
    logs.log_warn('Unable to reset virtual device.')
    bad_state_reached()

  else:
    # For non-Nexus devices, need to set debug mode as low. See b/25423901.
    # Try hard-reset via sysrq-trigger (requires root).
    hard_reset_sysrq_cmd = get_adb_command_line(
        'shell echo b \\> /proc/sysrq-trigger')
    execute_command(
        hard_reset_sysrq_cmd, timeout=RECOVERY_CMD_TIMEOUT, log_error=True)

    # Try soft-reset now (does not require root).
    soft_reset_cmd = get_adb_command_line('reboot')
    execute_command(
        soft_reset_cmd, timeout=RECOVERY_CMD_TIMEOUT, log_error=True)


def is_package_installed(package_name):
  """Checks if the package appears in the list of packages."""
  output = run_adb_shell_command(['pm', 'list', 'packages'])
  package_names = [line.split(':')[-1] for line in output.splitlines()]

  return package_name in package_names


def install_package(package_apk_path):
  """Checks if the package appears in the list of packages."""
  return run_adb_command(['install', '-r', package_apk_path])


def uninstall_package(package_name):
  """Uninstall a package."""
  return run_adb_command(['uninstall', package_name])


def kill_processes_and_children_matching_name(process_name):
  """Kills process along with children matching names."""
  process_and_child_pids = get_process_and_child_pids(process_name)
  if not process_and_child_pids:
    return

  kill_command = ['kill', '-9'] + process_and_child_pids
  run_adb_shell_command(kill_command)


def read_data_from_file(file_path):
  """Return device's file content."""
  if not file_exists(file_path):
    return None

  return run_adb_shell_command(['cat', '"%s"' % file_path])


def reboot():
  """Reboots device."""
  is_remote_device = environment.get_value('ANDROID_GCE')
  log_error = False
  recover = True
  timeout = None
  if is_remote_device:
    # Hack for ADB over remote connections: reboot hangs adb, so we set a small
    # timeout. Also, disable attempting to recover from a reboot, otherwise
    # we'll attempt to reboot again and do unnecessary recovery since the
    # initial command timed out.
    recover = False
    timeout = REMOTE_REBOOT_TIMEOUT

  run_adb_command(
      'reboot', log_error=log_error, timeout=timeout, recover=recover)

  if is_remote_device:
    # Reboot also disconnects us, so we must reconnect.
    connect_remote(reconnect=True)


def recreate_virtual_device():
  """Recreate virtual device from image."""
  device_name = environment.get_value('BOT_NAME')
  failure_wait_interval = environment.get_value('FAIL_WAIT')
  project = environment.get_value('GCE_PROJECT')
  retry_limit = environment.get_value('FAIL_RETRIES')
  zone = environment.get_value('GCE_ZONE')

  # This is needed to populate the initial /data partition. We use a separate
  # disk for /data since the one in the provided images is only 2GB.
  preimage_metadata_value = environment.get_value('GCE_DATA_PREIMAGE_METADATA')
  if preimage_metadata_value:
    additional_metadata = {GCE_PREIMAGE_METADATA_KEY: preimage_metadata_value}
  else:
    additional_metadata = None

  for _ in xrange(retry_limit):
    if compute_engine.recreate_instance_with_disks(
        device_name,
        project,
        zone,
        additional_metadata=additional_metadata,
        wait_for_completion=True):
      # Instance recreation succeeeded. Try reconnecting after some wait.
      time.sleep(REMOTE_RECREATE_TIMEOUT)

      if connect_remote(reconnect=True, num_retries=REMOTE_CONNECT_RETRIES * 2):
        # We were able to successfully reconnect to device after recreation.
        return True

    time.sleep(utils.random_number(1, failure_wait_interval))

  logs.log_error('Failed to reimage device.')
  return False


def remount():
  """Remount /system as read/write."""
  run_as_root()
  run_adb_command('remount')
  wait_for_device()


def remove_directory(device_directory, recreate=False):
  """Deletes everything inside of a device directory."""
  run_adb_shell_command('rm -rf %s' % device_directory, root=True)
  if recreate:
    create_directory_if_needed(device_directory)


def reset_device_connection():
  """Reset the connection to the device (either through USB or a remote
  connection). Returns whether or not the reset succeeded."""
  if environment.get_value('ANDROID_GCE'):
    # Try disconnecting and then reconnecting.
    connect_remote(reconnect=True)
  else:
    # Try restarting usb.
    reset_usb()

  # Check device status.
  state = get_device_state()
  if state != 'device':
    logs.log_warn('Device state is %s, unable to recover using usb reset/'
                  'remote reconnect.' % str(state))
    return False

  return True


def reset_usb():
  """Reset USB bus for a device serial."""
  if environment.get_value('ANDROID_GCE'):
    # Nothing to do here.
    return

  # App Engine does not let us import this.
  import fcntl

  # We need to get latest device path since it could be changed in reboots or
  # adb root restarts.
  device_path = get_device_path()
  if not device_path:
    # Try pulling from cache (if available).
    device_path = environment.get_value('DEVICE_PATH')
  if not device_path:
    logs.log_warn('No device path found, unable to reset usb.')
    return

  try:
    with open(device_path, 'w') as f:
      fcntl.ioctl(f, USBDEVFS_RESET)
  except:
    logs.log_warn('Failed to reset usb.')
    return

  # Wait for usb to recover.
  time.sleep(RESTART_USB_WAIT)


def reset_virtual_device():
  """Reset virtual device."""
  device_name = environment.get_value('BOT_NAME')
  project = environment.get_value('GCE_PROJECT')
  zone = environment.get_value('GCE_ZONE')

  # We don't want /data to be preimaged on every reboot and lose existing data,
  # so remove the metadata.
  compute_engine.remove_metadata(
      device_name,
      project,
      zone,
      GCE_PREIMAGE_METADATA_KEY,
      wait_for_completion=True)

  if not compute_engine.reset_instance(
      device_name, project, zone, wait_for_completion=True):
    logs.log_error('Failed to restart device.')
    return False

  if connect_remote(reconnect=True):
    # We successfully recovered.
    return True

  logs.log_error('Failed to connect to device after restart.')
  return False


def revert_asan_device_setup_if_needed():
  """Reverts ASan device setup if installed."""
  if not environment.get_value('ASAN_DEVICE_SETUP'):
    return

  device_id = environment.get_value('ANDROID_SERIAL')
  device_argument = '--device %s' % device_id
  revert_argument = '--revert'
  asan_device_setup_script_path = os.path.join(
      environment.get_platform_resources_directory(), 'third_party',
      'asan_device_setup.sh')

  command = '%s %s %s' % (asan_device_setup_script_path, device_argument,
                          revert_argument)
  execute_command(command, timeout=RECOVERY_CMD_TIMEOUT)


def run_as_root():
  """Restart adbd and runs as root."""
  # Check if we are already running as root. If yes bail out.
  if get_property('service.adb.root') == '1':
    return

  wait_for_device()
  output = run_adb_command('root')

  if environment.get_value('ANDROID_GCE') and 'restarting adbd' in output:
    # root may restart the device's adbd, which requires a reconnect.
    connect_remote(reconnect=True)

  wait_for_device()


def run_adb_command(cmd,
                    log_output=False,
                    log_error=True,
                    timeout=None,
                    recover=True):
  """Run a command in adb shell."""
  if isinstance(cmd, list):
    cmd = ' '.join([str(i) for i in cmd])
  if log_output:
    logs.log('Running: adb %s' % cmd)
  if not timeout:
    timeout = environment.get_value('ADB_TIMEOUT')

  is_remote_device = environment.get_value('ANDROID_GCE')
  if is_remote_device and get_device_state() != 'device':
    # If the GCE device is not connected, reconnect.
    connect_remote(reconnect=True)

  output = execute_command(get_adb_command_line(cmd), timeout, log_error)
  if not recover:
    if log_output:
      logs.log('Output: (%s)' % output)
    return output

  if (output in [
      DEVICE_HANG_STRING, DEVICE_NOT_FOUND_STRING, DEVICE_OFFLINE_STRING
  ]):
    if reset_device_connection():
      # Device has successfully recovered, re-run command to get output.
      # Continue execution and validate output next for |None| condition.
      output = execute_command(get_adb_command_line(cmd), timeout, log_error)
    else:
      output = DEVICE_HANG_STRING

  if output is DEVICE_HANG_STRING:
    # Handle the case where our command execution hung. This is usually when
    # device goes into a bad state and only way to recover is to restart it.
    logs.log_warn('Adb is not responding, restarting device to recover.')
    hard_reset()

    # Wait until we've booted and try the command again.
    wait_until_fully_booted()
    output = execute_command(get_adb_command_line(cmd), timeout, log_error)

  if log_output:
    logs.log('Output: (%s)' % output)
  return output


def run_adb_shell_command(cmd,
                          log_output=False,
                          log_error=True,
                          root=False,
                          timeout=None,
                          recover=True):
  """Run adb shell command (with root if needed)."""

  def _escape_specials(command):
    return command.replace('\\', '\\\\').replace('"', '\\"')

  if isinstance(cmd, list):
    cmd = ' '.join([str(i) for i in cmd])

  if cmd[0] not in ['"', "'"]:
    cmd = '"{}"'.format(_escape_specials(cmd))

  if root:
    root_cmd_prefix = 'su root sh -c '

    # The arguments to adb shell need to be quoted, so if we're using
    # su root sh -c, quote the combined command
    full_cmd = 'shell \'{}{}\''.format(root_cmd_prefix, cmd)
  else:
    full_cmd = 'shell {}'.format(cmd)

  return run_adb_command(
      full_cmd,
      log_output=log_output,
      log_error=log_error,
      timeout=timeout,
      recover=recover)


def run_fastboot_command(cmd, log_output=True, log_error=True, timeout=None):
  """Run a command in fastboot shell."""
  if environment.get_value('ANDROID_GCE'):
    # We can't run fastboot commands on Android GCE instances.
    return None

  if isinstance(cmd, list):
    cmd = ' '.join([str(i) for i in cmd])
  if log_output:
    logs.log('Running: fastboot %s' % cmd)
  if not timeout:
    timeout = environment.get_value('ADB_TIMEOUT')

  output = execute_command(get_fastboot_command_line(cmd), timeout, log_error)
  return output


def set_property(property_name, property_value):
  """Set property's to a certain value."""
  property_value_quoted_string = '"%s"' % str(property_value)
  run_adb_shell_command(
      ['setprop', property_name, property_value_quoted_string])


def setup_adb():
  """Sets up ADB binary for use."""
  adb_binary_path = get_adb_path()

  # Make sure that ADB_PATH is set.
  if not environment.get_value('ADB_PATH'):
    environment.set_value('ADB_PATH', adb_binary_path)


def stop_application():
  """Stop application and cleanup application state."""
  package_name = get_package_name()
  if not package_name:
    return

  # Device can get silently restarted in case of OOM. So, we would need to
  # restart our shell as root in order to kill the application.
  run_as_root()

  kill_processes_and_children_matching_name(package_name)

  # Chrome specific cleanup.
  if package_name.endswith('.chrome'):
    cache_dirs_absolute_paths = [
        '/data/data/%s/%s' % (package_name, i) for i in CHROME_CACHE_DIRS
    ]
    save_crash_minidumps(package_name)
    run_adb_shell_command(
        ['rm', '-rf', ' '.join(cache_dirs_absolute_paths)], root=True)


def save_crash_minidumps(package_name):
  """Copy crash minidumps to retain."""
  # FIXME: remove once we can redirect minidump at generation phase.
  if package_name != 'com.google.android.apps.chrome':
    return

  crash_dir_absolute_path = '/data/data/%s/%s' % (package_name,
                                                  CHROME_CRASH_DIR)

  # Ignore errors when running this command. Adding directory list check is
  # another adb call and since this is called frequently, we need to avoid that
  # extra call.
  run_adb_shell_command(
      ['cp', '%s/*' % crash_dir_absolute_path, DEVICE_CRASH_DUMPS_DIR],
      log_error=False,
      root=True)


def start_shell():
  """Stops shell."""
  # Make sure we are running as root.
  run_as_root()

  run_adb_shell_command('start')
  wait_until_fully_booted()


def stop_shell():
  """Stops shell."""
  # Make sure we are running as root.
  run_as_root()

  if environment.get_value('ANDROID_GCE'):
    # Workaround for ethernet issues during stop/start: stop eth0 first.
    # See b/22854645.
    # If this happens too quickly one after the other, we could still get into a
    # bad (hanging) state. However, it shouldn't be a problem because
    # start_shell calls wait_until_fully_booted().
    run_adb_shell_command('stop dhcpcd_eth0')

  run_adb_shell_command('stop')


def time_since_last_reboot():
  """Return time in seconds since last reboot."""
  uptime_string = run_adb_shell_command(['cat', '/proc/uptime']).split(' ')[0]
  try:
    return float(uptime_string)
  except ValueError:
    # Sometimes, adb can just hang or return null output. In these cases, just
    # return infinity uptime value.
    return float('inf')


def update_key_in_sqlite_db(database_path, table_name, key_name, key_value):
  """Updates a key's value in sqlite db. The input is not sanitized, so make
  sure to use with trusted input key and value pairs only."""
  sql_command_string = ('"UPDATE %s SET value=\'%s\' WHERE name=\'%s\'"') % (
      table_name, str(key_value), key_name)
  run_adb_shell_command(['sqlite3', database_path, sql_command_string])


def wait_for_device():
  """Waits indefinitely for the device to come online."""
  if environment.get_value('ANDROID_GCE'):
    # wait-for-device will never return for remote GCE instances if we're not
    # already connected. Instead, try connecting if we're not connected.
    connect_remote(reconnect=False)
  else:
    run_adb_command('wait-for-device')


def wait_until_fully_booted():
  """Wait until device is fully booted or timeout expires."""

  def boot_completed():
    expected = '1'
    result = run_adb_shell_command(
        'getprop sys.boot_completed', log_error=False)
    return result == expected

  def drive_ready():
    expected = '0'
    result = run_adb_shell_command('\'test -d "/"; echo $?\'', log_error=False)
    return result == expected

  def package_manager_ready():
    expected = 'package:/system/framework/framework-res.apk'
    result = run_adb_shell_command('pm path android', log_error=False)
    if not result:
      return False

    # Ignore any extra messages before or after the result we want.
    return expected in result.splitlines()

  # Make sure we are not already recursing inside this function.
  if utils.is_recursive_call():
    return False

  # Wait until device is online.
  wait_for_device()

  start_time = time.time()

  is_boot_completed = False
  is_drive_ready = False
  is_package_manager_ready = False
  while time.time() - start_time < REBOOT_TIMEOUT:
    # TODO(mbarbella): Investigate potential optimizations.
    # The package manager check should also work for shell restarts.
    if not is_drive_ready:
      is_drive_ready = drive_ready()
    if not is_package_manager_ready:
      is_package_manager_ready = package_manager_ready()
    if not is_boot_completed:
      is_boot_completed = boot_completed()

    if is_drive_ready and is_package_manager_ready and is_boot_completed:
      return True

    time.sleep(BOOT_WAIT_INTERVAL)

  factory_reset()
  logs.log_fatal_and_exit(
      'Device failed to finish boot. Resetted to factory settings and exiting.')

  # Not reached.
  return False


def wait_until_package_optimization_complete():
  """Waits for package optimization to finish."""
  start_time = time.time()

  while time.time() - start_time < REBOOT_TIMEOUT:
    memory_output = get_memory_usage_info()
    package_optimization_finished = 'dex2oat' not in memory_output
    if package_optimization_finished:
      return

    logs.log('Waiting for package optimization to finish.')
    time.sleep(PACKAGE_OPTIMIZATION_INTERVAL)


def write_command_line_file(command_line, app_path):
  """Write command line file with command line argument for the application."""
  # Algorithm for filtering current command line.
  # 1. Add 'chrome ' to start.
  # 2. Remove apk from path.
  # 3. Strip for whitespaces at start and end.
  command_line_without_app_path = command_line.replace('%s ' % app_path, '')
  command_line_file_contents = 'chrome %s' % (
      command_line_without_app_path.strip())

  command_line_paths = [
      environment.get_value('COMMAND_LINE_PATH'),
      environment.get_value('COMMAND_LINE_PATH2')
  ]
  for command_line_path in command_line_paths:
    if not command_line_path:
      continue

    write_data_to_file(command_line_file_contents, command_line_path)


def write_data_to_file(contents, file_path):
  """Writes content to file."""
  # If this is a file in /system, we need to remount /system as read-write and
  # after file is written, revert it back to read-only.
  is_system_file = file_path.startswith('/system')
  if is_system_file:
    remount()

  # Write file with desired contents.
  run_adb_shell_command("\"echo '%s' | su root dd of=%s\"" % (contents.replace(
      '"', '\\"'), file_path))

  # Make command line file is readable.
  run_adb_shell_command('chmod 0644 %s' % file_path, root=True)

  if is_system_file:
    reboot()

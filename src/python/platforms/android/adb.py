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
import glob
import os
import re
import signal
import subprocess
import tempfile
import threading
import time

from base import persistent_cache
from base import utils
from metrics import logs
from system import environment
from system import shell

ADB_TIMEOUT = 1200  # Should be lower than |REBOOT_TIMEOUT|.
BAD_STATE_WAIT = 900
BOOT_WAIT_INTERVAL = 30
DEFAULT_DEVICE_MEMORY_MB = 2048
DEVICE = collections.namedtuple('Device', ['serial', 'path'])
DEVICE_HANG_STRING = None
DEVICE_NOT_FOUND_STRING = 'error: device \'{serial}\' not found'
DEVICE_OFFLINE_STRING = 'error: device offline'
FACTORY_RESET_WAIT = 60
KERNEL_LOG_FILES = [
    '/proc/last_kmsg',
    '/sys/fs/pstore/console-ramoops',
]
MONKEY_PROCESS_NAME = 'monkey'
REBOOT_TIMEOUT = 3600
RECOVERY_CMD_TIMEOUT = 60
STOP_CVD_WAIT = 20

# Output patterns to parse "lsusb" output.
LSUSB_BUS_RE = re.compile(r'Bus\s+(\d+)\s+Device\s+(\d+):.*')
LSUSB_SERIAL_RE = re.compile(r'\s+iSerial\s+\d\s+(.*)')

# This is a constant value defined in usbdevice_fs.h in Linux system.
USBDEVFS_RESET = ord('U') << 8 | 20


def bad_state_reached():
  """Wait when device is in a bad state and exit."""
  persistent_cache.clear_values()
  logs.log_fatal_and_exit(
      'Device in bad state.', wait_before_exit=BAD_STATE_WAIT)


def copy_local_directory_to_remote(local_directory, remote_directory):
  """Copies local directory contents to a device directory."""
  create_directory_if_needed(remote_directory)
  if os.listdir(local_directory):
    run_command(['push', '%s/.' % local_directory, remote_directory])


def copy_local_file_to_remote(local_file_path, remote_file_path):
  """Copies local file to a device file."""
  create_directory_if_needed(os.path.dirname(remote_file_path))
  run_command(['push', local_file_path, remote_file_path])


def copy_remote_directory_to_local(remote_directory, local_directory):
  """Copies local directory contents to a device directory."""
  run_command(['pull', '%s/.' % remote_directory, local_directory])


def copy_remote_file_to_local(remote_file_path, local_file_path):
  """Copies device file to a local file."""
  shell.create_directory(
      os.path.dirname(local_file_path), create_intermediates=True)
  run_command(['pull', remote_file_path, local_file_path])


def create_directory_if_needed(device_directory):
  """Creates a directory on the device if it doesn't already exist."""
  run_shell_command(['mkdir', '-p', device_directory])


def directory_exists(directory_path):
  """Return whether a directory exists or not."""
  expected = '0'
  result = run_shell_command(
      '\'test -d "%s"; echo $?\'' % directory_path, log_error=False)
  return result == expected


def execute_command(cmd, timeout=None, log_error=True):
  """Spawns a subprocess to run the given shell command."""
  so = []
  output_dest = tempfile.TemporaryFile()
  # pylint: disable=subprocess-popen-preexec-fn
  pipe = subprocess.Popen(
      cmd,
      executable='/bin/bash',
      stdout=output_dest,
      stderr=subprocess.STDOUT,
      shell=True,
      preexec_fn=lambda: signal.signal(signal.SIGPIPE, signal.SIG_DFL),
      bufsize=0)

  def run():
    """Thread target function that waits for subprocess to complete."""
    try:
      pipe.communicate()
      output_dest.seek(0)
      output = output_dest.read()
      output_dest.close()
      if output:
        so.append(output)
    except OSError as _:
      logs.log_warn('Failed to retrieve stdout from: %s' % cmd)
    if pipe.returncode:
      if log_error:
        logs.log_warn(
            '%s returned %d error code.' % (cmd, pipe.returncode),
            output=output)

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

  bytes_output = b''.join(so)
  return bytes_output.strip().decode('utf-8', errors='ignore')


def factory_reset():
  """Reset device to factory state."""
  if is_gce():
    # We cannot recover from this since there can be cases like userdata image
    # corruption in /data/data. Till the bug is fixed, we just need to wait
    # for reimage in next iteration.
    bad_state_reached()

  # A device can be stuck in a boot loop due to a bad clang library update.
  # Reverting that can bring a device back to good state.
  revert_asan_device_setup_if_needed()

  run_as_root()
  run_shell_command([
      'am', 'broadcast', '-a', 'android.intent.action.MASTER_CLEAR', '-n',
      'android/com.android.server.MasterClearReceiver'
  ])

  # Wait until the reset is complete.
  time.sleep(FACTORY_RESET_WAIT)


def file_exists(file_path):
  """Return whether a file exists or not."""
  expected = '0'
  result = run_shell_command(
      '\'test -f "%s"; echo $?\'' % file_path, log_error=False)
  return result == expected


def get_adb_command_line(adb_cmd):
  """Return adb command line for running an adb command."""
  device_serial = environment.get_value('ANDROID_SERIAL')
  adb_cmd_line = '%s -s %s %s' % (get_adb_path(), device_serial, adb_cmd)
  return adb_cmd_line


def get_adb_path():
  """Return path to ADB binary."""
  adb_path = environment.get_value('ADB')
  if adb_path:
    return adb_path

  return os.path.join(environment.get_platform_resources_directory(), 'adb')


def get_device_state():
  """Return the device status."""
  state_cmd = get_adb_command_line('get-state')
  return execute_command(state_cmd, timeout=RECOVERY_CMD_TIMEOUT)


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
  if not file_exists(file_path):
    return None

  return run_shell_command(['md5sum', '-b', file_path])


def get_file_size(file_path):
  """Return file's size."""
  if not file_exists(file_path):
    return None

  return int(run_shell_command(['stat', '-c%s', file_path]))


def get_kernel_log_content():
  """Return content of kernel logs."""
  kernel_log_content = ''
  for kernel_log_file in KERNEL_LOG_FILES:
    kernel_log_content += read_data_from_file(kernel_log_file) or ''

  return kernel_log_content


def get_ps_output():
  """Return ps output for all processes."""
  return run_shell_command(['ps', '-A'])


def get_process_and_child_pids(process_name):
  """Return process and child pids matching a process name."""
  pids = []
  ps_output_lines = get_ps_output().splitlines()

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
  return run_shell_command(['getprop', property_name])


def hard_reset():
  """Perform a hard reset of the device."""
  if is_gce():
    # There is no recovery step at this point for a gce bot, so just exit
    # and wait for reimage on next iteration.
    bad_state_reached()

  # For physical device.
  # Try hard-reset via sysrq-trigger (requires root).
  hard_reset_sysrq_cmd = get_adb_command_line(
      'shell echo b \\> /proc/sysrq-trigger')
  execute_command(hard_reset_sysrq_cmd, timeout=RECOVERY_CMD_TIMEOUT)

  # Try soft-reset now (does not require root).
  soft_reset_cmd = get_adb_command_line('reboot')
  execute_command(soft_reset_cmd, timeout=RECOVERY_CMD_TIMEOUT)


def is_gce():
  """Returns if we are running in GCE environment."""
  android_serial = environment.get_value('ANDROID_SERIAL')
  return android_serial.startswith('127.0.0.1:')


def kill_processes_and_children_matching_name(process_name):
  """Kills process along with children matching names."""
  process_and_child_pids = get_process_and_child_pids(process_name)
  if not process_and_child_pids:
    return

  kill_command = ['kill', '-9'] + process_and_child_pids
  run_shell_command(kill_command)


def read_data_from_file(file_path):
  """Return device's file content."""
  if not file_exists(file_path):
    return None

  return run_shell_command(['cat', '"%s"' % file_path])


def reboot():
  """Reboots device."""
  run_command('reboot')


def start_gce_device():
  """Start the gce device."""
  cvd_dir = environment.get_value('CVD_DIR')
  cvd_bin_dir = os.path.join(cvd_dir, 'bin')
  launch_cvd_path = os.path.join(cvd_bin_dir, 'launch_cvd')

  device_memory_mb = environment.get_value('DEVICE_MEMORY_MB',
                                           DEFAULT_DEVICE_MEMORY_MB)
  launch_cvd_command_line = (
      '{launch_cvd_path} -daemon -memory_mb {device_memory_mb}'.format(
          launch_cvd_path=launch_cvd_path, device_memory_mb=device_memory_mb))
  execute_command(launch_cvd_command_line)


def stop_gce_device():
  """Stops the gce device."""
  cvd_dir = environment.get_value('CVD_DIR')
  cvd_bin_dir = os.path.join(cvd_dir, 'bin')
  stop_cvd_path = os.path.join(cvd_bin_dir, 'stop_cvd')

  execute_command(stop_cvd_path, timeout=RECOVERY_CMD_TIMEOUT)
  time.sleep(STOP_CVD_WAIT)


def recreate_gce_device():
  """Recreate gce device, restoring from backup images."""
  logs.log('Reimaging gce device.')
  cvd_dir = environment.get_value('CVD_DIR')

  stop_gce_device()

  # Delete all existing images.
  image_dir = cvd_dir
  for image_file_path in glob.glob(os.path.join(image_dir, '*.img')):
    shell.remove_file(image_file_path)

  # Restore images from backup.
  backup_image_dir = os.path.join(cvd_dir, 'backup')
  for image_filename in os.listdir(backup_image_dir):
    image_src = os.path.join(backup_image_dir, image_filename)
    image_dest = os.path.join(image_dir, image_filename)
    shell.copy_file(image_src, image_dest)

  start_gce_device()


def remount():
  """Remount /system as read/write."""
  run_as_root()
  run_command('remount')
  wait_for_device()
  run_as_root()


def remove_directory(device_directory, recreate=False):
  """Delete everything inside of a device directory and recreate if needed."""
  run_shell_command('rm -rf %s' % device_directory, root=True)
  if recreate:
    create_directory_if_needed(device_directory)


def remove_file(file_path):
  """Remove file."""
  run_shell_command('rm -f %s' % file_path, root=True)


def reset_device_connection():
  """Reset the connection to the physical device through USB. Returns whether
  or not the reset succeeded."""
  if is_gce():
    stop_gce_device()
    start_gce_device()
  else:
    # Physical device. Try restarting usb.
    reset_usb()

  # Check device status.
  state = get_device_state()
  if state != 'device':
    logs.log_warn('Device state is %s, unable to recover using usb reset/'
                  'gce reconnect.' % str(state))
    return False

  return True


def get_device_path():
  """Gets a device path to be cached and used by reset_usb."""

  def _get_usb_devices():
    """Returns a list of device objects containing a serial and USB path."""
    usb_list_cmd = 'lsusb -v'
    output = execute_command(usb_list_cmd, timeout=RECOVERY_CMD_TIMEOUT)
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

  def _get_device_path_for_serial():
    """Return device path. Assumes a simple ANDROID_SERIAL."""
    devices = _get_usb_devices()
    for device in devices:
      if device_serial == device.serial:
        return device.path

    return None

  def _get_device_path_for_usb():
    """Returns a device path.

    Assumes ANDROID_SERIAL in the form "usb:<identifier>"."""
    # Android serial may reference a usb device rather than a serial number.
    device_id = device_serial[len('usb:'):]
    bus_number = int(
        open('/sys/bus/usb/devices/%s/busnum' % device_id).read().strip())
    device_number = int(
        open('/sys/bus/usb/devices/%s/devnum' % device_id).read().strip())
    return '/dev/bus/usb/%03d/%03d' % (bus_number, device_number)

  if is_gce():
    return None

  device_serial = environment.get_value('ANDROID_SERIAL')
  if device_serial.startswith('usb:'):
    return _get_device_path_for_usb()

  return _get_device_path_for_serial()


def reset_usb():
  """Reset USB bus for a device serial."""
  if is_gce():
    # Nothing to do here.
    return True

  # App Engine does not let us import this.
  import fcntl

  # We need to get latest device path since it could be changed in reboots or
  # adb root restarts.
  try:
    device_path = get_device_path()
  except IOError:
    # We may reach this state if the device is no longer available.
    device_path = None

  if not device_path:
    # Try pulling from cache (if available).
    device_path = environment.get_value('DEVICE_PATH')
  if not device_path:
    logs.log_warn('No device path found, unable to reset usb.')
    return False

  try:
    with open(device_path, 'w') as f:
      fcntl.ioctl(f, USBDEVFS_RESET)
  except:
    logs.log_warn('Failed to reset usb.')
    return False

  # Wait for usb to recover.
  wait_for_device(recover=False)
  return True


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
  run_command('root')
  wait_for_device()


def run_command(cmd,
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
    timeout = ADB_TIMEOUT

  output = execute_command(get_adb_command_line(cmd), timeout, log_error)
  if not recover:
    if log_output:
      logs.log('Output: (%s)' % output)
    return output

  device_not_found_string_with_serial = DEVICE_NOT_FOUND_STRING.format(
      serial=environment.get_value('ANDROID_SERIAL'))
  if (output in [
      DEVICE_HANG_STRING, DEVICE_OFFLINE_STRING,
      device_not_found_string_with_serial
  ]):
    logs.log_warn('Unable to query device, resetting device connection.')
    if reset_device_connection():
      # Device has successfully recovered, re-run command to get output.
      # Continue execution and validate output next for |None| condition.
      output = execute_command(get_adb_command_line(cmd), timeout, log_error)
    else:
      output = DEVICE_HANG_STRING

  if output is DEVICE_HANG_STRING:
    # Handle the case where our command execution hung. This is usually when
    # device goes into a bad state and only way to recover is to restart it.
    logs.log_warn('Unable to query device, restarting device to recover.')
    hard_reset()

    # Wait until we've booted and try the command again.
    wait_until_fully_booted()
    output = execute_command(get_adb_command_line(cmd), timeout, log_error)

  if log_output:
    logs.log('Output: (%s)' % output)
  return output


def run_shell_command(cmd,
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

  return run_command(
      full_cmd,
      log_output=log_output,
      log_error=log_error,
      timeout=timeout,
      recover=recover)


def run_fastboot_command(cmd, log_output=True, log_error=True, timeout=None):
  """Run a command in fastboot shell."""
  if is_gce():
    # We can't run fastboot commands on Android GCE instances.
    return None

  if isinstance(cmd, list):
    cmd = ' '.join([str(i) for i in cmd])
  if log_output:
    logs.log('Running: fastboot %s' % cmd)
  if not timeout:
    timeout = ADB_TIMEOUT

  output = execute_command(get_fastboot_command_line(cmd), timeout, log_error)
  return output


def setup_adb():
  """Sets up ADB binary for use."""
  adb_binary_path = get_adb_path()

  # Make sure that ADB env var is set.
  if not environment.get_value('ADB'):
    environment.set_value('ADB', adb_binary_path)


def start_shell():
  """Stops shell."""
  # Make sure we are running as root.
  run_as_root()

  run_shell_command('start')
  wait_until_fully_booted()


def stop_shell():
  """Stops shell."""
  # Make sure we are running as root.
  run_as_root()
  run_shell_command('stop')


def time_since_last_reboot():
  """Return time in seconds since last reboot."""
  uptime_string = run_shell_command(['cat', '/proc/uptime']).split(' ')[0]
  try:
    return float(uptime_string)
  except ValueError:
    # Sometimes, adb can just hang or return null output. In these cases, just
    # return infinity uptime value.
    return float('inf')


def wait_for_device(recover=True):
  """Waits indefinitely for the device to come online."""
  run_command('wait-for-device', timeout=RECOVERY_CMD_TIMEOUT, recover=recover)


def wait_until_fully_booted():
  """Wait until device is fully booted or timeout expires."""

  def boot_completed():
    expected = '1'
    result = run_shell_command('getprop sys.boot_completed', log_error=False)
    return result == expected

  def drive_ready():
    expected = '0'
    result = run_shell_command('\'test -d "/"; echo $?\'', log_error=False)
    return result == expected

  def package_manager_ready():
    expected = 'package:/system/framework/framework-res.apk'
    result = run_shell_command('pm path android', log_error=False)
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
      'Device failed to finish boot. Reset to factory settings and exited.')

  # Not reached.
  return False


def write_command_line_file(command_line, app_path):
  """Write command line file with command line argument for the application."""
  command_line_path = environment.get_value('COMMAND_LINE_PATH')
  if not command_line_path:
    return

  # Algorithm for filtering current command line.
  # 1. Remove |APP_PATH| from front.
  # 2. Add 'chrome ' to start.
  # 3. Strip for whitespaces at start and end.
  command_line_without_app_path = command_line.replace('%s ' % app_path, '')
  command_line_file_contents = 'chrome %s' % (
      command_line_without_app_path.strip())

  write_data_to_file(command_line_file_contents, command_line_path)


def write_data_to_file(contents, file_path):
  """Writes content to file."""
  # If this is a file in /system, we need to remount /system as read-write and
  # after file is written, revert it back to read-only.
  is_system_file = file_path.startswith('/system')
  if is_system_file:
    remount()

  # Write file with desired contents.
  run_shell_command("\"echo -n '%s' | su root dd of=%s\"" % (contents.replace(
      '"', '\\"'), file_path))

  # Make command line file is readable.
  run_shell_command('chmod 0644 %s' % file_path, root=True)

  if is_system_file:
    reboot()
    wait_until_fully_booted()

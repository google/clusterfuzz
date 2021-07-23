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
"""Functions for process management."""

import copy
import datetime
import os
import queue
import subprocess
import sys
import threading
import time

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.platforms import linux
from clusterfuzz._internal.platforms import windows
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

# FIXME: Find a better way to handle this case. These imports
# will fail and are not needed from App Engine.
try:
  import multiprocessing

  import mozprocess
  import psutil
except ImportError:
  pass

# On Android, we need to wait a little after a crash occurred to get the full
# logcat output. This makes sure we get all the stack frames since there is no
# effective end marker.
ANDROID_CRASH_LOGCAT_WAIT_TIME = 0.3

# Time in seconds it usually takes to analyze a crash. This is usually high
# in case of Android where it is required to do several adb shell calls.
CRASH_ANALYSIS_TIME = 1.5

# Test timeout if not specified.
DEFAULT_TEST_TIMEOUT = 10

# Time to wait for cleanup after process if finished.
PROCESS_CLEANUP_WAIT_TIME = 5

# LeakSanitizer needs additional time to process all leaks and dump stacks on
# process shutdown.
LSAN_ANALYSIS_TIME = 1

# Time to wait for thread cleanup (e.g. dumping coverage, etc).
THREAD_FINISH_WAIT_TIME = 5


class ProcessStatus(object):
  """Process exited notification."""

  def __init__(self):
    self.finished = False

  def __call__(self):
    self.finished = True


def start_process(process_handle):
  """Start the process using process handle and override list2cmdline for
  Windows."""
  is_win = environment.platform() == 'WINDOWS'
  if is_win:
    # Override list2cmdline on Windows to return first index of list as string.
    # This is to workaround a mozprocess bug since it passes command as list
    # and not as string.
    subprocess.list2cmdline_orig = subprocess.list2cmdline
    subprocess.list2cmdline = lambda s: s[0]
  try:
    process_handle.run()
  finally:
    if is_win:
      subprocess.list2cmdline = subprocess.list2cmdline_orig


def cleanup_defunct_processes():
  """Cleans up defunct processes."""
  # Defunct processes happen only on unix platforms.
  if environment.platform() != 'WINDOWS':
    while True:
      try:
        # Matches any defunct child process.
        p, _ = os.waitpid(-1, os.WNOHANG)
        if not p:
          break

        logs.log('Clearing defunct process %s.' % str(p))
      except:
        break


# Note: changes to this function may require changes to untrusted_runner.proto.
# This should only be used for running target black box applications which
# return text output.
def run_process(cmdline,
                current_working_directory=None,
                timeout=DEFAULT_TEST_TIMEOUT,
                need_shell=False,
                gestures=None,
                env_copy=None,
                testcase_run=True,
                ignore_children=True):
  """Executes a process with a given command line and other parameters."""
  if environment.is_trusted_host() and testcase_run:
    from clusterfuzz._internal.bot.untrusted_runner import remote_process_host
    return remote_process_host.run_process(
        cmdline, current_working_directory, timeout, need_shell, gestures,
        env_copy, testcase_run, ignore_children)

  if gestures is None:
    gestures = []

  if env_copy:
    os.environ.update(env_copy)

  # FIXME(mbarbella): Using LAUNCHER_PATH here is error prone. It forces us to
  # do certain operations before fuzzer setup (e.g. bad build check).
  launcher = environment.get_value('LAUNCHER_PATH')

  # This is used when running scripts on native linux OS and not on the device.
  # E.g. running a fuzzer to generate testcases or launcher script.
  plt = environment.platform()
  runs_on_device = environment.is_android(plt) or plt == 'FUCHSIA'
  if runs_on_device and (not testcase_run or launcher):
    plt = 'LINUX'

  is_android = environment.is_android(plt)

  # Lower down testcase timeout slightly to account for time for crash analysis.
  timeout -= CRASH_ANALYSIS_TIME

  # LeakSanitizer hack - give time for stdout/stderr processing.
  lsan = environment.get_value('LSAN', False)
  if lsan:
    timeout -= LSAN_ANALYSIS_TIME

  # Initialize variables.
  adb_output = None
  process_output = ''
  process_status = None
  return_code = 0
  process_poll_interval = environment.get_value('PROCESS_POLL_INTERVAL', 0.5)
  start_time = time.time()
  watch_for_process_exit = (
      environment.get_value('WATCH_FOR_PROCESS_EXIT') if is_android else True)
  window_list = []

  # Get gesture start time from last element in gesture list.
  gestures = copy.deepcopy(gestures)
  if gestures and gestures[-1].startswith('Trigger'):
    gesture_start_time = int(gestures[-1].split(':')[1])
    gestures.pop()
  else:
    gesture_start_time = timeout // 2

  if is_android:
    # Clear the log upfront.
    android.logger.clear_log()

    # Run the app.
    adb_output = android.adb.run_command(cmdline, timeout=timeout)
  else:
    cmd = shell.get_command(cmdline)

    process_output = mozprocess.processhandler.StoreOutput()
    process_status = ProcessStatus()
    try:
      process_handle = mozprocess.ProcessHandlerMixin(
          cmd,
          args=None,
          cwd=current_working_directory,
          shell=need_shell,
          processOutputLine=[process_output],
          onFinish=[process_status],
          ignore_children=ignore_children)
      start_process(process_handle)
    except:
      logs.log_error('Exception occurred when running command: %s.' % cmdline)
      return None, None, ''

  while True:
    time.sleep(process_poll_interval)

    # Run the gestures at gesture_start_time or in case we didn't find windows
    # in the last try.
    if (gestures and time.time() - start_time >= gesture_start_time and
        not window_list):
      # In case, we don't find any windows, we increment the gesture start time
      # so that the next check is after 1 second.
      gesture_start_time += 1

      if plt == 'LINUX':
        linux.gestures.run_gestures(gestures, process_handle.pid,
                                    process_status, start_time, timeout,
                                    window_list)
      elif plt == 'WINDOWS':
        windows.gestures.run_gestures(gestures, process_handle.pid,
                                      process_status, start_time, timeout,
                                      window_list)
      elif is_android:
        android.gestures.run_gestures(gestures, start_time, timeout)

        # TODO(mbarbella): We add a fake window here to prevent gestures on
        # Android from getting executed more than once.
        window_list = ['FAKE']

    if time.time() - start_time >= timeout:
      break

    # Collect the process output.
    output = (
        android.logger.log_output()
        if is_android else b'\n'.join(process_output.output))
    output = utils.decode_to_unicode(output)
    if crash_analyzer.is_memory_tool_crash(output):
      break

    # Check if we need to bail out on process exit.
    if watch_for_process_exit:
      # If |watch_for_process_exit| is set, then we already completed running
      # our app launch command. So, we can bail out.
      if is_android:
        break

      # On desktop, we bail out as soon as the process finishes.
      if process_status and process_status.finished:
        # Wait for process shutdown and set return code.
        process_handle.wait(timeout=PROCESS_CLEANUP_WAIT_TIME)
        break

  # Process output based on platform.
  if is_android:
    # Get current log output. If device is in reboot mode, logcat automatically
    # waits for device to be online.
    time.sleep(ANDROID_CRASH_LOGCAT_WAIT_TIME)
    output = android.logger.log_output()

    if android.constants.LOW_MEMORY_REGEX.search(output):
      # If the device is low on memory, we should force reboot and bail out to
      # prevent device from getting in a frozen state.
      logs.log('Device is low on memory, rebooting.', output=output)
      android.adb.hard_reset()
      android.adb.wait_for_device()

    elif android.adb.time_since_last_reboot() < time.time() - start_time:
      # Check if a reboot has happened, if yes, append log output before reboot
      # and kernel logs content to output.
      log_before_last_reboot = android.logger.log_output_before_last_reboot()
      kernel_log = android.adb.get_kernel_log_content()
      output = '%s%s%s%s%s' % (
          log_before_last_reboot, utils.get_line_seperator('Device rebooted'),
          output, utils.get_line_seperator('Kernel Log'), kernel_log)
      # Make sure to reset SE Linux Permissive Mode. This can be done cheaply
      # in ~0.15 sec and is needed especially between runs for kernel crashes.
      android.adb.run_as_root()
      android.settings.change_se_linux_to_permissive_mode()
      return_code = 1

    # Add output from adb to the front.
    if adb_output:
      output = '%s\n\n%s' % (adb_output, output)

    # Kill the application if it is still running. We do this at the end to
    # prevent this from adding noise to the logcat output.
    task_name = environment.get_value('TASK_NAME')
    child_process_termination_pattern = environment.get_value(
        'CHILD_PROCESS_TERMINATION_PATTERN')
    if task_name == 'fuzz' and child_process_termination_pattern:
      # In some cases, we do not want to terminate the application after each
      # run to avoid long startup times (e.g. for chrome). Terminate processes
      # matching a particular pattern for light cleanup in this case.
      android.adb.kill_processes_and_children_matching_name(
          child_process_termination_pattern)
    else:
      # There is no special termination behavior. Simply stop the application.
      android.app.stop()

  else:
    # Get the return code in case the process has finished already.
    # If the process hasn't finished, return_code will be None which is what
    # callers expect unless the output indicates a crash.
    return_code = process_handle.poll()

    # If the process is still running, then terminate it.
    if not process_status.finished:
      launcher_with_interpreter = shell.get_execute_command(
          launcher) if launcher else None
      if (launcher_with_interpreter and
          cmdline.startswith(launcher_with_interpreter)):
        # If this was a launcher script, we KILL all child processes created
        # except for APP_NAME.
        # It is expected that, if the launcher script terminated normally, it
        # cleans up all the child processes it created itself.
        terminate_root_and_child_processes(process_handle.pid)
      else:
        try:
          # kill() here actually sends SIGTERM on posix.
          process_handle.kill()
        except:
          pass

    if lsan:
      time.sleep(LSAN_ANALYSIS_TIME)

    output = b'\n'.join(process_output.output)
    output = utils.decode_to_unicode(output)

    # X Server hack when max client reached.
    if ('Maximum number of clients reached' in output or
        'Unable to get connection to X server' in output):
      logs.log_error('Unable to connect to X server, exiting.')
      os.system('sudo killall -9 Xvfb blackbox >/dev/null 2>&1')
      sys.exit(0)

  if testcase_run and (crash_analyzer.is_memory_tool_crash(output) or
                       crash_analyzer.is_check_failure_crash(output)):
    return_code = 1

  # If a crash is found, then we add the memory state as well.
  if return_code and is_android:
    ps_output = android.adb.get_ps_output()
    if ps_output:
      output += utils.get_line_seperator('Memory Statistics')
      output += ps_output

  if return_code:
    logs.log_warn(
        'Process (%s) ended with exit code (%s).' % (repr(cmdline),
                                                     str(return_code)),
        output=output)

  return return_code, round(time.time() - start_time, 1), output


def cleanup_stale_processes():
  """Kill stale processes left behind by a job."""
  terminate_multiprocessing_children()
  terminate_stale_application_instances()
  cleanup_defunct_processes()


def close_queue(queue_to_close):
  """Close the queue."""
  if environment.is_trusted_host():
    # We don't use multiprocessing.Queue on trusted hosts.
    return

  try:
    queue_to_close.close()
  except:
    logs.log_error('Unable to close queue.')


def get_process():
  """Return a multiprocessing process object (with bug fixes)."""
  if environment.is_trusted_host():
    # forking/multiprocessing is unsupported because of the RPC connection.
    return threading.Thread

  # FIXME(unassigned): Remove this hack after real bug is fixed.
  # pylint: disable=protected-access
  multiprocessing.current_process()._identity = ()

  return multiprocessing.Process


def get_runtime_snapshot():
  """Return a list of current processes and their command lines as string."""
  process_strings = []
  for process in psutil.process_iter():
    try:
      process_info = process.as_dict(attrs=['name', 'cmdline', 'pid', 'ppid'])
      process_string = '{name} ({pid}, {ppid})'.format(
          name=process_info['name'],
          pid=process_info['pid'],
          ppid=process_info['ppid'])
      process_cmd_line = process_info['cmdline']
      if process_cmd_line:
        process_string += ': {cmd_line}'.format(
            cmd_line=(' '.join(process_cmd_line)))
      process_strings.append(process_string)
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
      # Ignore the error, use whatever info is available for access.
      pass

  return '\n'.join(sorted(process_strings))


def get_queue():
  """Return a multiprocessing queue object."""
  if environment.is_trusted_host():
    # We don't use multiprocessing.Process on trusted hosts. No need to use
    # multiprocessing.Queue.
    return queue.Queue()

  try:
    result_queue = multiprocessing.Queue()
  except:
    # FIXME: Invalid cross-device link error. Happens sometimes with
    # chroot jobs even though /dev/shm and /run/shm are mounted.
    logs.log_error('Unable to get multiprocessing queue.')
    return None

  return result_queue


def terminate_hung_threads(threads):
  """Terminate hung threads."""
  start_time = time.time()
  while time.time() - start_time < THREAD_FINISH_WAIT_TIME:
    if not any([thread.is_alive() for thread in threads]):
      # No threads are alive, so we're done.
      return
    time.sleep(0.1)

  logs.log_warn('Hang detected.', snapshot=get_runtime_snapshot())

  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import host

    # Bail out on trusted hosts since we're using threads and can't clean up.
    host.host_exit_no_return()

  # Terminate all threads that are still alive.
  try:
    [thread.terminate() for thread in threads if thread.is_alive()]
  except:
    pass


def terminate_root_and_child_processes(root_pid):
  """Terminate the root process along with any children it spawned."""
  app_name = environment.get_value('APP_NAME')
  direct_children = utils.get_process_ids(root_pid, recursive=False)

  for child_pid in direct_children:
    # utils.get_process_ids also returns the parent pid.
    if child_pid == root_pid:
      continue

    try:
      child = psutil.Process(child_pid)
    except Exception:
      # Process doesn't exist anymore.
      continue

    if child.name() == app_name:
      # Send SIGTERM to the root APP_NAME process only, and none of its children
      # so that coverage data will be dumped properly (e.g. the browser process
      # of chrome).
      # TODO(ochang): Figure out how windows coverage is dumped since there is
      # no equivalent of SIGTERM.
      terminate_process(child_pid, kill=False)
      continue

    child_and_grand_children_pids = utils.get_process_ids(
        child_pid, recursive=True)
    for pid in child_and_grand_children_pids:
      terminate_process(pid, kill=True)

  terminate_process(root_pid, kill=True)


def terminate_multiprocessing_children():
  """Terminate all children created with multiprocessing module."""
  child_list = multiprocessing.active_children()
  for child in child_list:
    try:
      child.terminate()
    except:
      # Unable to terminate multiprocessing child or was not needed.
      pass


def terminate_stale_application_instances():
  """Kill stale instances of the application running for this command."""
  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import remote_process_host
    remote_process_host.terminate_stale_application_instances()
    return

  # Stale instance cleanup is sometimes disabled for local testing.
  if not environment.get_value('KILL_STALE_INSTANCES', True):
    return

  additional_process_to_kill = environment.get_value(
      'ADDITIONAL_PROCESSES_TO_KILL')
  builds_directory = environment.get_value('BUILDS_DIR')
  llvm_symbolizer_filename = environment.get_executable_filename(
      'llvm-symbolizer')
  platform = environment.platform()
  start_time = time.time()

  processes_to_kill = []
  # Avoid killing the test binary when running the reproduce tool. It is
  # commonly in-use on the side on developer workstations.
  if not environment.get_value('REPRODUCE_TOOL'):
    app_name = environment.get_value('APP_NAME')
    processes_to_kill += [app_name]

  if additional_process_to_kill:
    processes_to_kill += additional_process_to_kill.split(' ')
  processes_to_kill = [x for x in processes_to_kill if x]

  if environment.is_android(platform):
    # Cleanup any stale adb connections.
    device_serial = environment.get_value('ANDROID_SERIAL')
    adb_search_string = 'adb -s %s' % device_serial

    # Terminate llvm symbolizer processes matching exact path. This is important
    # for Android where multiple device instances run on same host.
    llvm_symbolizer_path = environment.get_llvm_symbolizer_path()

    terminate_processes_matching_cmd_line(
        [adb_search_string, llvm_symbolizer_path], kill=True)

    # Make sure device is online and rooted.
    android.adb.run_as_root()

    # Make sure to reset SE Linux Permissive Mode (might be lost in reboot).
    android.settings.change_se_linux_to_permissive_mode()

    # Make sure that device forwarder is running (might be lost in reboot or
    # process crash).
    android.device.setup_host_and_device_forwarder_if_needed()

    # Make sure that package optimization is complete (might be triggered due to
    # unexpected circumstances).
    android.app.wait_until_optimization_complete()

    # Reset application state, which kills its pending instances and re-grants
    # the storage permissions.
    android.app.reset()

  elif platform == 'WINDOWS':
    processes_to_kill += [
        'cdb.exe',
        'handle.exe',
        'msdt.exe',
        'openwith.exe',
        'WerFault.exe',
        llvm_symbolizer_filename,
    ]
    terminate_processes_matching_names(processes_to_kill, kill=True)
    terminate_processes_matching_cmd_line(builds_directory, kill=True)

    # Artifical sleep to let the processes get terminated.
    time.sleep(1)

  else:
    # Handle Linux and Mac platforms.
    processes_to_kill += [
        'addr2line',
        'atos',
        'chrome-devel-sandbox',
        'gdb',
        'nacl_helper',
        'xdotool',
        llvm_symbolizer_filename,
    ]
    terminate_processes_matching_names(processes_to_kill, kill=True)
    terminate_processes_matching_cmd_line(builds_directory, kill=True)

  duration = int(time.time() - start_time)
  if duration >= 5:
    logs.log('Process kill took longer than usual - %s.' % str(
        datetime.timedelta(seconds=duration)))


def terminate_process(process_id, kill=False):
  """Terminates a process by its process id."""
  try:
    process = psutil.Process(process_id)

    if kill:
      process.kill()
    else:
      process.terminate()

  except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
    logs.log_warn('Failed to terminate process.')


def terminate_processes_matching_names(match_strings, kill=False):
  """Terminates processes matching particular names (case sensitive)."""
  if isinstance(match_strings, str):
    match_strings = [match_strings]

  for process in psutil.process_iter():
    try:
      process_info = process.as_dict(attrs=['name', 'pid'])
      process_name = process_info['name']
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
      continue

    if any(x == process_name for x in match_strings):
      terminate_process(process_info['pid'], kill)


def terminate_processes_matching_cmd_line(match_strings,
                                          kill=False,
                                          exclude_strings=None):
  """Terminates processes matching particular command line (case sensitive)."""
  if exclude_strings is None:
    # By default, do not terminate processes containing butler.py. This is
    # important so that the reproduce tool does not terminate itself, as the
    # rest of its command line may contain strings we usually terminate such
    # as paths to build directories.
    exclude_strings = ['butler.py', 'reproduce.sh']

  if isinstance(match_strings, str):
    match_strings = [match_strings]

  for process in psutil.process_iter():
    try:
      process_info = process.as_dict(attrs=['cmdline', 'pid'])
      process_cmd_line = process_info['cmdline']
      if not process_cmd_line:
        continue
      process_path = ' '.join(process_cmd_line)
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
      continue

    if any(x in process_path for x in match_strings):
      if not any([x in process_path for x in exclude_strings]):
        terminate_process(process_info['pid'], kill)

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
"""Process handling utilities."""

from distutils import spawn
import os
import subprocess
import tempfile
import threading
import time

import psutil

from base import utils
from metrics import logs
from system import environment


def _end_process(terminate_function, process_result):
  """Ends a running process.

  Ignores exceptions.

  Args:
    process: A subprocess.Popen object.
    terminate_function: The function to terminate the process.
    process_result: A ProcessResult object where timeout information will be
        written to.
  """
  try:
    terminate_function()
  except OSError:
    logs.log('Process already killed.')

  process_result.timed_out = True


def _wait_process(process,
                  timeout,
                  input_data=None,
                  terminate_before_kill=False,
                  terminate_wait_time=None):
  """Waits until either the process exits or times out.

  Args:
    process: A subprocess.Popen object.
    timeout: Maximum number of seconds to wait for before sending a signal.
    input_data: Input to be sent to the process.
    terminate_before_kill: A bool indicating that SIGTERM should be sent to
        the process first before SIGKILL (to let the SIGTERM handler run).
    terminate_wait_time: Maximum number of seconds to wait for the SIGTERM
        handler.

  Returns:
    A ProcessResult.
  """
  result = ProcessResult()
  is_windows = environment.platform() == 'WINDOWS'

  # On Windows, terminate() just calls Win32 API function TerminateProcess()
  # which is equivalent to process kill. So, skip terminate_before_kill.
  if terminate_before_kill and not is_windows:
    first_timeout_function = process.terminate

    # Use a second timer to send the process kill.
    second_timer = threading.Timer(timeout + terminate_wait_time, _end_process,
                                   [process.kill, result])
  else:
    first_timeout_function = process.kill
    second_timer = None

  first_timer = threading.Timer(timeout, _end_process,
                                [first_timeout_function, result])

  output = None
  start_time = time.time()

  try:
    first_timer.start()
    if second_timer:
      second_timer.start()

    output = process.communicate(input_data)[0]
  finally:
    first_timer.cancel()

    if second_timer:
      second_timer.cancel()

  result.return_code = process.poll()
  result.output = output
  result.time_executed = time.time() - start_time
  return result


def kill_process_tree(root_pid):
  """Kill process tree."""
  try:
    parent = psutil.Process(root_pid)
    children = parent.children(recursive=True)
  except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
    logs.log_warn('Failed to find or access process.')
    return

  for child in children:
    try:
      child.kill()
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
      logs.log_warn('Failed to kill process child.')

  try:
    parent.kill()
  except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
    logs.log_warn('Failed to kill process.')


class ChildProcess(object):
  """A class representing a process that's running."""

  def __init__(self, popen, command, max_stdout_len=None, stdout_file=None):
    self._popen = popen
    self._command = command
    self._max_stdout_len = max_stdout_len
    self._stdout_file = stdout_file

  @property
  def command(self):
    return self._command

  @property
  def popen(self):
    return self._popen

  def communicate(self, input=None):  # pylint: disable=redefined-builtin
    """subprocess.Popen.communicate."""
    stdout, stderr = self._popen.communicate(input)
    if not self._max_stdout_len:
      return stdout, stderr

    with self._stdout_file:
      return utils.read_from_handle_truncated(self._stdout_file,
                                              self._max_stdout_len), stderr

  def poll(self):
    """subprocess.Popen.poll."""
    return self._popen.poll()

  def kill(self):
    """Kills running process and all of its associated children."""
    kill_process_tree(self._popen.pid)

  def terminate(self):
    """subprocess.Popen.terminate."""
    try:
      self._popen.terminate()
    except OSError:
      logs.log_warn('Failed to terminate process.')


class ProcessResult(object):
  """Object representing result of a process execution.

  Returned by ProcessRunner.run_and_wait().

  Attributes:
    command: A list of arguments representing the command line that was run.
    return_code: Exit code of the process.
    output: Process output.
    time_executed: Number of seconds process ran for.
    timed_out: Whether or not the process timed out.
  """

  def __init__(self,
               command=None,
               return_code=None,
               output=None,
               time_executed=None,
               timed_out=False):
    """Inits the ProcessResult."""
    self.command = command
    self.return_code = return_code
    self.output = output
    self.time_executed = time_executed
    self.timed_out = timed_out


class ProcessRunner(object):
  """Generic process runner class.

  Attributes:
    executable_path: Path to the executable to be run.
    default_args: An optional sequence of arguments that are always passed to
        the executable when run.
  """

  def __init__(self, executable_path, default_args=None):
    """Inits ProcessRunner."""
    self._executable_path = executable_path
    self._default_args = []

    if default_args:
      self.default_args.extend(default_args)

  @property
  def executable_path(self):
    return self._executable_path

  @property
  def default_args(self):
    return self._default_args

  def get_command(self, additional_args=None):
    """Returns the command line for running the executable.

    Args:
      additional_args: A sequence of additional arguments to be passed to the
          executable.

    Returns:
      A list containing the command arguments to be passed to subprocess.Popen.
    """
    command = [self._executable_path]
    command.extend(self._default_args)

    if additional_args:
      command.extend(additional_args)

    return command

  def run(self,
          additional_args=None,
          max_stdout_len=None,
          extra_env=None,
          stdin=subprocess.PIPE,
          stdout=subprocess.PIPE,
          stderr=subprocess.STDOUT,
          **popen_args):
    """Runs the executable.

    Does not block the caller.

    Args:
      additional_args: A sequence of additional arguments to be passed to the
          executable.
      max_stdout_len: Optional. Maximum number of bytes to collect in stdout.
      extra_env: Optional. A dictionary containing environment variables and
        their values. These will be set in the environment of the new process.
      stdin: Optional. Passed to subprocess.Popen, defaults to subprocess.PIPE,
      stdout: Optional. Passed to subprocess.Popen, defaults to subprocess.PIPE
      stderr: Optional. Passed to subprocess.Popen, defaults to
          subprocess.STDOUT
      **popen_args: Additional arguments that are passed to subprocess.Popen.

    Returns:
      A subprocess.Popen object for the process.
    """
    # TODO: Rename popen_args to popen_kwargs.
    command = self.get_command(additional_args)
    if stdout == subprocess.PIPE and max_stdout_len:
      stdout = tempfile.TemporaryFile()

    env = popen_args.pop('env', os.environ.copy())
    if extra_env is not None:
      env.update(extra_env)

    return ChildProcess(
        subprocess.Popen(
            command,
            env=env,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            **popen_args),
        command,
        max_stdout_len=max_stdout_len,
        stdout_file=stdout)

  # Note: changes to this function may require changes to
  # untrusted_runner.proto.
  def run_and_wait(self,
                   additional_args=None,
                   timeout=None,
                   terminate_before_kill=False,
                   terminate_wait_time=None,
                   input_data=None,
                   max_stdout_len=None,
                   extra_env=None,
                   stdin=subprocess.PIPE,
                   stdout=subprocess.PIPE,
                   stderr=subprocess.STDOUT,
                   **popen_args):
    """Runs the executable.

    Blocks the caller until the process exits.

    Args:
      additional_args: A sequence of additional arguments to be passed to the
          executable.
      timeout: Maximum number of seconds to run the process for.
      terminate_before_kill: A bool indicating that SIGTERM should be sent to
          the process first before SIGKILL (to let the SIGTERM handler run).
      terminate_wait_time: Maximum number of seconds to wait for the SIGTERM
          handler.
      input_data: Optional. A string to be passed as input to the process.
      max_stdout_len: Optional. Maximum number of bytes to collect in stdout.
      extra_env: Optional. A dictionary containing environment variables and
           their values. These will be added to the environment of the new
           process.
      stdout: Optional. Passed to subprocess.Popen, defaults to subprocess.PIPE
      stderr: Optional. Passed to subprocess.Popen, defaults to
          subprocess.STDOUT
      **popen_args: Additional arguments that are passed to subprocess.Popen.

    Returns:
      A tuple of (return code, output, time process ran for, or None on timeout)
    """
    process = self.run(
        additional_args,
        max_stdout_len=max_stdout_len,
        extra_env=extra_env,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        **popen_args)

    start_time = time.time()

    if not timeout:
      output = process.communicate(input_data)[0]
      return ProcessResult(process.command, process.poll(), output,
                           time.time() - start_time, False)

    result = _wait_process(
        process,
        timeout=timeout,
        input_data=input_data,
        terminate_before_kill=terminate_before_kill,
        terminate_wait_time=terminate_wait_time)
    result.command = process.command

    return result


class UnicodeProcessRunnerMixin(object):
  """Mixin for process runner subclasses to output unicode output."""

  def run_and_wait(self, *args, **kwargs):  # pylint: disable=arguments-differ
    """Overridden run_and_wait which always decodes the output."""
    result = ProcessRunner.run_and_wait(self, *args, **kwargs)
    if result.output is not None:
      result.output = utils.decode_to_unicode(result.output)

    return result


class UnicodeProcessRunner(UnicodeProcessRunnerMixin, ProcessRunner):
  """ProcessRunner which always returns unicode output."""


class UnshareProcessRunnerMixin(object):
  """ProcessRunner mixin which unshares."""

  def get_command(self, additional_args=None):
    """Overridden get_command."""
    if environment.platform() != 'LINUX':
      raise RuntimeError('UnshareProcessRunner only supported on Linux')

    unshare_path = spawn.find_executable('unshare')
    if not unshare_path:
      raise RuntimeError('unshare not found')

    command = [unshare_path]
    command.extend([
        '-n',  # Enter network namespace.
    ])

    command.append(self._executable_path)
    command.extend(self._default_args)

    if additional_args:
      command.extend(additional_args)

    return command


class UnshareProcessRunner(UnshareProcessRunnerMixin, ProcessRunner):
  """ProcessRunner which unshares."""

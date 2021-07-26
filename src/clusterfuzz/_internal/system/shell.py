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
"""Shell related functions."""

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from clusterfuzz._internal.base import persistent_cache
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

try:
  import psutil
except ImportError:
  psutil = None

_DEFAULT_LOW_DISK_SPACE_THRESHOLD = 5 * 1024 * 1024 * 1024  # 5 GB.
_TRUSTED_HOST_LOW_DISK_SPACE_THRESHOLD = 2 * 1024 * 1024  # 2 GB.
FILE_COPY_BUFFER_SIZE = 10 * 1024 * 1024  # 10 MB.
HANDLE_OUTPUT_FILE_TYPE_REGEX = re.compile(
    br'.*pid:\s*(\d+)\s*type:\s*File\s*([a-fA-F0-9]+):\s*(.*)')

_system_temp_dir = None


def _low_disk_space_threshold():
  """Get the low disk space threshold."""
  if environment.is_trusted_host(ensure_connected=False):
    # Trusted hosts can run with less free space as they do not store builds or
    # corpora.
    return _TRUSTED_HOST_LOW_DISK_SPACE_THRESHOLD

  return _DEFAULT_LOW_DISK_SPACE_THRESHOLD


def copy_file(source_file_path, destination_file_path):
  """Faster version of shutil.copy with buffer size."""
  if not os.path.exists(source_file_path):
    logs.log_error('Source file %s for copy not found.' % source_file_path)
    return False

  error_occurred = False
  try:
    with open(source_file_path, 'rb') as source_file_handle:
      with open(destination_file_path, 'wb') as destination_file_handle:
        shutil.copyfileobj(source_file_handle, destination_file_handle,
                           FILE_COPY_BUFFER_SIZE)
  except:
    error_occurred = True

  # Make sure that the destination file actually exists.
  error_occurred |= not os.path.exists(destination_file_path)

  if error_occurred:
    logs.log_warn('Failed to copy source file %s to destination file %s.' %
                  (source_file_path, destination_file_path))
    return False

  return True


def clear_build_directory():
  """Clears the build directory."""
  remove_directory(environment.get_value('BUILDS_DIR'), recreate=True)


def clear_build_urls_directory():
  """Clears the build url directory."""
  remove_directory(environment.get_value('BUILD_URLS_DIR'), recreate=True)

  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    file_host.clear_build_urls_directory()


def clear_crash_stacktraces_directory():
  """Clears the crash stacktraces directory."""
  remove_directory(
      environment.get_value('CRASH_STACKTRACES_DIR'), recreate=True)


def clear_common_data_bundles_directory():
  """Clear the common data bundle directory."""
  remove_directory(environment.get_value('FUZZ_DATA'), recreate=True)


def clear_data_bundles_directory():
  """Clears the data bundles directory."""
  remove_directory(environment.get_value('DATA_BUNDLES_DIR'), recreate=True)


def clear_mutator_plugins_directory():
  """Clears the mutator plugins directory."""
  remove_directory(environment.get_value('MUTATOR_PLUGINS_DIR'), recreate=True)


def clear_data_directories():
  """Clear all data directories."""
  clear_build_directory()
  clear_build_urls_directory()
  clear_crash_stacktraces_directory()
  clear_common_data_bundles_directory()
  clear_data_bundles_directory()
  clear_fuzzers_directories()
  clear_temp_directory()
  clear_testcase_directories()
  clear_mutator_plugins_directory()

  persistent_cache.clear_values(clear_all=True)


def clear_data_directories_on_low_disk_space():
  """Clear all data directories on low disk space. This should ideally never
  happen, but when it does, we do this to keep the bot working in sane state."""
  free_disk_space = get_free_disk_space()
  if free_disk_space is None:
    # Can't determine free disk space, bail out.
    return

  if free_disk_space >= _low_disk_space_threshold():
    return

  logs.log_warn(
      'Low disk space detected, clearing all data directories to free up space.'
  )
  clear_data_directories()


def clear_device_temp_directories():
  """Clear device specific temp directories."""
  if environment.is_android() and environment.get_value('ANDROID_SERIAL'):
    from clusterfuzz._internal.platforms import android
    android.device.clear_temp_directories()


def clear_fuzzers_directories():
  """Clears the fuzzers directory."""
  remove_directory(environment.get_value('FUZZERS_DIR'), recreate=True)


def clear_temp_directory(clear_user_profile_directories=True):
  """Clear the temporary directories."""
  temp_directory = environment.get_value('BOT_TMPDIR')
  remove_directory(temp_directory, recreate=True)

  test_temp_directory = environment.get_value('TEST_TMPDIR')
  if test_temp_directory != temp_directory:
    remove_directory(test_temp_directory, recreate=True)

  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    file_host.clear_temp_directory()

  if not clear_user_profile_directories:
    return

  user_profile_root_directory = environment.get_value('USER_PROFILE_ROOT_DIR')
  if not user_profile_root_directory:
    return

  remove_directory(user_profile_root_directory, recreate=True)


@environment.local_noop
def clear_system_temp_directory():
  """Clear system specific temp directory."""

  def _delete_object(path, delete_func):
    """Delete a object with its delete function, ignoring any error."""
    try:
      delete_func(path)
    except:
      pass

  if environment.get_value('SKIP_SYSTEM_TEMP_CLEANUP'):
    # This provides a way to avoid clearing system temporary directory when it
    # can interfere with other processes on the system.
    return

  # Cache system temp directory to avoid iterating through the system dir list
  # on every gettempdir call. Also, it helps to avoid a case where temp dir
  # fills up the disk and gets ignored by gettempdir.
  global _system_temp_dir
  if not _system_temp_dir:
    _system_temp_dir = tempfile.gettempdir()

  # Use a custom cleanup rather than using |remove_directory| since it
  # recreates the directory and can mess up permissions and symlinks.
  for root, dirs, files in walk(_system_temp_dir, topdown=False):
    for name in files:
      _delete_object(os.path.join(root, name), os.remove)

    for name in dirs:
      _delete_object(os.path.join(root, name), os.rmdir)
  logs.log('Cleared system temp directory: %s' % _system_temp_dir)


def clear_testcase_directories():
  """Clears the testcase directories."""
  remove_directory(environment.get_value('FUZZ_INPUTS'), recreate=True)
  remove_directory(environment.get_value('FUZZ_INPUTS_DISK'), recreate=True)

  if environment.is_android() and environment.get_value('ANDROID_SERIAL'):
    from clusterfuzz._internal.platforms import android
    android.device.clear_testcase_directory()
  if environment.platform() == 'FUCHSIA':
    from clusterfuzz._internal.platforms import fuchsia
    fuchsia.device.clear_testcase_directory()
  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    file_host.clear_testcase_directories()


def close_open_file_handles_if_needed(path):
  """Try to close all open file handle for a specific path."""
  if environment.platform() != 'WINDOWS':
    # Handle closing is only applicable on Windows platform.
    return

  resources_directory = environment.get_platform_resources_directory()
  handle_executable_path = os.path.join(resources_directory, 'handle.exe')
  handle_output = execute_command(
      '%s -accepteula "%s"' % (handle_executable_path, path))
  for line in handle_output.splitlines():
    match = HANDLE_OUTPUT_FILE_TYPE_REGEX.match(line)
    if not match:
      continue

    process_id = match.group(1).decode('utf-8')
    file_handle_id = match.group(2).decode('utf-8')
    file_path = match.group(3).decode('utf-8')

    logs.log(
        'Closing file handle id %s for path %s.' % (file_handle_id, file_path))
    execute_command('%s -accepteula -c %s -p %s -y' %
                    (handle_executable_path, file_handle_id, process_id))


def create_directory(directory, create_intermediates=False, recreate=False):
  """Creates |directory|. Create intermediate directories if
  |create_intermediates|. Ignore if it already exists and |recreate| is
   False."""
  if os.path.exists(directory):
    if recreate:
      remove_directory(directory)
    else:
      return True

  try:
    if create_intermediates:
      os.makedirs(directory)
    else:
      os.mkdir(directory)
  except:
    logs.log_error('Unable to create directory %s.' % directory)
    return False

  return True


def execute_command(shell_command):
  """Run a command, returning its output."""
  try:
    process_handle = subprocess.Popen(
        shell_command,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    output, _ = process_handle.communicate()
  except:
    logs.log_error('Error while executing command %s.' % shell_command)
    return ''

  return output


def get_command(command_line):
  """Get the command to pass to subprocess."""
  if environment.platform() == 'WINDOWS':
    return command_line

  return shlex.split(command_line, posix=True)


def get_command_line_from_argument_list(argument_list):
  """Convert a list of arguments to a string."""
  return subprocess.list2cmdline(argument_list)


def get_directory_file_count(directory_path):
  """Returns number of files within a directory (recursively)."""
  file_count = 0
  for (root, _, files) in walk(directory_path):
    for filename in files:
      file_path = os.path.join(root, filename)
      if not os.path.isfile(file_path):
        continue
      file_count += 1

  return file_count


def get_directory_size(directory_path):
  """Returns size of a directory (in bytes)."""
  directory_size = 0
  for (root, _, files) in walk(directory_path):
    for filename in files:
      file_path = os.path.join(root, filename)
      directory_size += os.path.getsize(file_path)

  return directory_size


def get_files_list(directory_path):
  """Returns a list of files in a directory (recursively)."""
  files_list = []
  for (root, _, files) in walk(directory_path):
    for filename in files:
      file_path = os.path.join(root, filename)
      if not os.path.isfile(file_path):
        continue
      files_list.append(file_path)

  return files_list


def get_free_disk_space(path='/'):
  """Return free disk space."""
  if not os.path.exists(path):
    return None

  return psutil.disk_usage(path).free


def get_interpreter(file_to_execute):
  """Gives the interpreter needed to execute |file_to_execute|."""
  interpreters = {
      '.bash': 'bash',
      '.class': 'java',
      '.js': 'node',
      '.pl': 'perl',
      '.py': sys.executable,
      '.pyc': sys.executable,
      '.sh': 'sh'
  }

  try:
    interpreter = interpreters[os.path.splitext(file_to_execute)[1]]
  except KeyError:
    return None

  return interpreter


def get_execute_command(file_to_execute):
  """Return command to execute |file_to_execute|."""
  interpreter_path = get_interpreter(file_to_execute)

  # Hack for Java scripts.
  file_to_execute = file_to_execute.replace('.class', '')

  if interpreter_path:
    command = '%s %s' % (interpreter_path, file_to_execute)
  else:
    # Handle executables that don't need an interpreter.
    command = file_to_execute
  return command


def move(src, dst):
  """Wrapper around shutil.move(src, dst). If shutil.move throws an shutil.Error
  the exception is caught, an error is logged, and False is returned."""
  try:
    shutil.move(src, dst)
    return True
  except shutil.Error:
    logs.log_error('Failed to move %s to %s' % (src, dst))
    return False


def remove_empty_files(root_path):
  """Removes empty files in a path recursively"""
  for directory, _, filenames in walk(root_path):
    for filename in filenames:
      path = os.path.join(directory, filename)
      if os.path.getsize(path) > 0:
        continue

      try:
        os.remove(path)
      except:
        logs.log_error('Unable to remove the empty file: %s (%s).' %
                       (path, sys.exc_info()[0]))


def remove_empty_directories(path):
  """Removes empty folder in a path recursively."""
  if not os.path.isdir(path):
    return

  # Remove empty sub-folders.
  files = os.listdir(path)
  for filename in files:
    absolute_path = os.path.join(path, filename)
    if os.path.isdir(absolute_path):
      remove_empty_directories(absolute_path)

  # If folder is empty, delete it.
  files = os.listdir(path)
  if not files:
    try:
      os.rmdir(path)
    except:
      logs.log_error('Unable to remove empty folder %s.' % path)


def remove_file(file_path):
  """Removes a file, ignoring any error if it occurs."""
  try:
    if os.path.exists(file_path):
      os.remove(file_path)
  except:
    pass


def remove_directory(directory, recreate=False, ignore_errors=False):
  """Removes a directory tree."""
  # Log errors as warnings if |ignore_errors| is set.
  log_error_func = logs.log_warn if ignore_errors else logs.log_error

  def clear_read_only(func, path, _):
    """Clear the read-only bit and reattempt the removal again.
    This is needed on Windows."""

    try:
      os.chmod(path, 0o750)
    except:
      # If this is tmpfs, we will probably fail.
      pass

    try:
      func(path)
    except:
      # Log errors for all cases except device or resource busy errors, as such
      # errors are expected in cases when mounts are used.
      error_message = str(sys.exc_info()[1])
      if 'Device or resource busy' not in error_message:
        logs.log_warn(
            'Failed to remove directory %s failed because %s with %s failed. %s'
            % (directory, func, path, error_message))

  # Try the os-specific deletion commands first. This helps to overcome issues
  # with unicode filename handling.
  if os.path.exists(directory):
    if environment.platform() == 'WINDOWS':
      os.system('rd /s /q "%s" > nul 2>&1' % directory)
    else:
      os.system('rm -rf "%s" > /dev/null 2>&1' % directory)

  if os.path.exists(directory):
    # If the directory still exists after using native OS delete commands, then
    # try closing open file handles and then try removing it with read only
    # bit removed (Windows only).
    close_open_file_handles_if_needed(directory)
    shutil.rmtree(directory, onerror=clear_read_only)

  if os.path.exists(directory):
    # 1. If directory is a mount point, then directory itself won't be
    #    removed. So, check the list of files inside it.
    # 2. If directory is a regular directory, then it should have not
    #    existed.
    if not os.path.ismount(directory) or os.listdir(directory):
      # Directory could not be cleared. Bail out.
      log_error_func('Failed to clear directory %s.' % directory)
      return False

    return True

  if not recreate:
    return True

  try:
    os.makedirs(directory)
  except:
    log_error_func('Unable to re-create directory %s.' % directory)
    return False

  return True


def walk(directory, **kwargs):
  """Wrapper around walk to resolve compatibility issues."""
  return os.walk(directory, **kwargs)


# Copy of shutil.which from Python 3.3 (unavailable in Python 2.7).
# pylint: disable=bad-inline-option,g-inconsistent-quotes,redefined-builtin
# yapf: disable
def which(cmd, mode=os.F_OK | os.X_OK, path=None):
  """Given a command, mode, and a PATH string, return the path which
  conforms to the given mode on the PATH, or None if there is no such
  file.
  `mode` defaults to os.F_OK | os.X_OK. `path` defaults to the result
  of os.environ.get("PATH"), or can be overridden with a custom search
  path.
  Note: This function was backported from the Python 3 source code.
  """

  # Check that a given file can be accessed with the correct mode.
  # Additionally check that `file` is not a directory, as on Windows
  # directories pass the os.access check.

  def _access_check(fn, mode):
    return (
        os.path.exists(fn) and os.access(fn, mode) and not os.path.isdir(fn)
    )

  # If we're given a path with a directory part, look it up directly
  # rather than referring to PATH directories. This includes checking
  # relative to the current directory, e.g. ./script
  if os.path.dirname(cmd):
    if _access_check(cmd, mode):
      return cmd

    return None

  if path is None:
    path = os.environ.get("PATH", os.defpath)
  if not path:
    return None

  path = path.split(os.pathsep)

  if sys.platform == "win32":
    # The current directory takes precedence on Windows.
    if os.curdir not in path:
      path.insert(0, os.curdir)

    # PATHEXT is necessary to check on Windows.
    pathext = os.environ.get("PATHEXT", "").split(os.pathsep)
    # See if the given file matches any of the expected path
    # extensions. This will allow us to short circuit when given
    # "python.exe". If it does match, only test that one, otherwise we
    # have to try others.
    if any(cmd.lower().endswith(ext.lower()) for ext in pathext):
      files = [cmd]
    else:
      files = [cmd + ext for ext in pathext]
  else:
    # On other platforms you don't have things like PATHEXT to tell you
    # what file suffixes are executable, so just pass on cmd as-is.
    files = [cmd]

  seen = set()
  for dir in path:
    normdir = os.path.normcase(dir)
    if normdir not in seen:
      seen.add(normdir)
      for thefile in files:
        name = os.path.join(dir, thefile)
        if _access_check(name, mode):
          return name

  return None
# pylint: enable=bad-inline-option,g-inconsistent-quotes,redefined-builtin
# yapf: enable

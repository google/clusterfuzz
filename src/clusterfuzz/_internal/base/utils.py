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
"""Common utility functions."""

import ast
import datetime
import functools
import gc
import hashlib
import inspect
import os
import random
import sys
import time
import urllib.parse
import urllib.request
import weakref

import requests

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import retry
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

try:
  import psutil
except ImportError:
  psutil = None

# FIXME: Binary extensions list is still very basic.
BINARY_EXTENSIONS = [
    # Media formats.
    '.mp3',
    '.ogg',
    '.mp4',
    '.webm',
    # Image Formats.
    '.png',
    '.jpg',
    '.gif',
    # Misc.
    '.pdf',
    '.swf',
]
FUZZ_PREFIX = 'fuzz-'
TEXT_EXTENSIONS = [
    '.css', '.js', '.htm', '.html', '.svg', '.xhtml', '.xht', '.xml', '.xsl'
]
URL_REQUEST_RETRIES = 5
URL_REQUEST_FAIL_WAIT = 1
WINDOWS_PREFIX_PATH = '\\\\?\\'

# Thread pool for use in function timeouts.
THREAD_POOL = None

LOCAL_SOURCE_MANIFEST = os.path.join('src', 'appengine', 'resources',
                                     'clusterfuzz-source.manifest')


def utcnow():
  """Return datetime.datetime.utcnow(). We need this method because we can't
    mock built-in methods."""
  return datetime.datetime.utcnow()  # pragma: no cover.


def current_date_time():
  """Returns current date and time."""
  return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')


def utc_date_to_timestamp(date):
  """Converts a (UTC) datetime.date to a UNIX timestamp."""
  return (date - datetime.date(1970, 1, 1)).total_seconds()


def utc_datetime_to_timestamp(dt):
  """Converts a (UTC) datetime.date to a UNIX timestamp."""
  return (dt - datetime.datetime.utcfromtimestamp(0)).total_seconds()


def decode_to_unicode(obj):
  """Decode object to unicode encoding."""
  if not hasattr(obj, 'decode'):
    return obj

  return obj.decode('utf-8', errors='ignore')


def encode_as_unicode(obj):
  """Encode a string as unicode, or leave bytes as they are."""
  if not hasattr(obj, 'encode'):
    return obj

  return obj.encode('utf-8')


@retry.wrap(
    retries=URL_REQUEST_RETRIES,
    delay=URL_REQUEST_FAIL_WAIT,
    function='base.utils.fetch_url')
def fetch_url(url):
  """Fetch url content."""
  operations_timeout = environment.get_value('URL_BLOCKING_OPERATIONS_TIMEOUT')

  response = requests.get(url, timeout=operations_timeout)
  if response.status_code == 404:
    return None

  response.raise_for_status()
  return response.text


def fields_match(string_1,
                 string_2,
                 field_separator=':',
                 allow_empty_fields=True):
  """Match fields of two strings, separated by a |field_separator|. Empty fields
  can be ignored via |allow_empty_fields| flag."""
  if string_1 is None or string_2 is None:
    return False
  if string_1 == string_2:
    return True

  string_1_fields = string_1.split(field_separator)
  string_2_fields = string_2.split(field_separator)

  if not allow_empty_fields and len(string_1_fields) != len(string_2_fields):
    return False

  min_fields_length = min(len(string_1_fields), len(string_2_fields))
  for i in range(min_fields_length):
    if string_1_fields[i] != string_2_fields[i]:
      return False

  return True


def file_path_to_file_url(path):
  """Return a path as a file scheme url."""
  if not path:
    return ''

  path = path.lstrip(WINDOWS_PREFIX_PATH)
  return urllib.parse.urljoin('file:', urllib.request.pathname2url(path))


def filter_file_list(file_list):
  """Filters file list by removing duplicates, non-existent files
  and directories."""
  filtered_file_list = []
  for file_path in file_list:
    if not os.path.exists(file_path):
      continue

    if os.path.isdir(file_path):
      continue

    # Do a os specific case normalization before comparison.
    if (os.path.normcase(file_path) in list(
        map(os.path.normcase, filtered_file_list))):
      continue

    filtered_file_list.append(file_path)

  if len(filtered_file_list) != len(file_list):
    logs.log('Filtered file list (%s) from (%s).' % (str(filtered_file_list),
                                                     str(file_list)))

  return filtered_file_list


def find_binary_path(app_directory, binary_file_subpath):
  """Find the path to a binary given the app directory and the file name.

  This is necessary as cov files are created in the root app directory, and we
  need a way to find the corresponding binary to symbolize addresses."""
  binary_path = os.path.join(app_directory, binary_file_subpath)
  if os.path.exists(binary_path):
    # Common case: the binary exists in the root directory.
    return binary_path

  # Match the longest file sub-path suffix.
  binary_file_subpath_with_sep = binary_file_subpath
  if not binary_file_subpath_with_sep.startswith(os.sep):
    binary_file_subpath_with_sep = os.sep + binary_file_subpath_with_sep
  for root, _, filenames in os.walk(app_directory):
    for filename in filenames:
      file_path = os.path.join(root, filename)
      if file_path.endswith(binary_file_subpath_with_sep):
        return file_path

  # Otherwise, do a search for the filename.
  binary_filename = os.path.basename(binary_file_subpath)
  for root, _, filenames in os.walk(app_directory):
    for filename in filenames:
      if filename == binary_filename:
        file_path = os.path.join(root, filename)
        return file_path

  return None


def get_application_id():
  """Return application id. Code simplified based off original implementation in
  AppEngine SDK get_identity.get_application_id."""
  app_id = environment.get_value('APPLICATION_ID')
  if app_id is None:
    return None

  psep = app_id.find('~')
  if psep > 0:
    app_id = app_id[psep + 1:]

  return app_id


def service_account_email():
  """Get the service account name."""
  # TODO(ochang): Detect GCE and return the GCE service account instead.
  email_id = get_application_id()
  if ':' in email_id:
    domain, application_id = email_id.split(':')
    email_id = application_id + '.' + domain

  return email_id + '@appspot.gserviceaccount.com'


def get_bot_testcases_file_path(input_directory):
  """Returns path to bot-specific fuzzed testcases."""
  # Using |FUZZ_INPUTS| prevents putting high load on nfs servers for cases
  # when |input_directory| is a cloud storage data bundle. We can't rely
  # on |FUZZ_INPUTS| always since it might not be available during local fuzzer
  # testing, so use |input_directory| if it is not defined.
  local_testcases_directory = environment.get_value('FUZZ_INPUTS')
  bot_testcases_directory = (
      local_testcases_directory
      if local_testcases_directory else input_directory)

  bot_name = environment.get_value('BOT_NAME')
  bot_testcases_filename = '.%s_testcases' % bot_name
  bot_testcases_file_path = os.path.join(bot_testcases_directory,
                                         bot_testcases_filename)

  return bot_testcases_file_path


def get_crash_stacktrace_output(application_command_line,
                                symbolized_stacktrace,
                                unsymbolized_stacktrace=None,
                                build_type=None):
  """Return output string with symbolized and unsymbolized stacktraces
  combined."""

  def _guess_build_type(application_command_line):
    if 'stable' in application_command_line:
      return 'stable'
    if 'beta' in application_command_line:
      return 'beta'
    if sub_string_exists_in(['debug', 'dbg'], application_command_line):
      return 'debug'
    return 'release'

  separator = '-' * 40
  if not build_type:
    build_type = _guess_build_type(application_command_line)

  crash_stacktraces_output = environment.get_environment_settings_as_string()
  if application_command_line:
    crash_stacktraces_output += (
        '[Command line] %s\n\n' % application_command_line)
  crash_stacktraces_output += ('+%s%s Build Stacktrace%s+\n%s' % (
      separator, build_type.capitalize(), separator, symbolized_stacktrace))

  # No unsymbolized stack available. Bail out.
  if not unsymbolized_stacktrace:
    return crash_stacktraces_output

  unsymbolized_stacktrace_diff = get_unique_lines_in_unsymbolized_stack(
      symbolized_stacktrace, unsymbolized_stacktrace)
  if unsymbolized_stacktrace_diff:
    crash_stacktraces_output += (
        '\n\n+%s%s Build Unsymbolized Stacktrace (diff)%s+\n\n%s' %
        (separator, build_type.capitalize(), separator,
         unsymbolized_stacktrace_diff))
  return crash_stacktraces_output


def get_directory_hash_for_path(file_path):
  """Return the directory hash for a file path (excludes file name)."""
  root_directory = environment.get_value('ROOT_DIR')

  directory_path = os.path.dirname(file_path)
  normalized_directory_path = remove_prefix(directory_path,
                                            root_directory + os.sep)
  normalized_directory_path = normalized_directory_path.replace('\\', '/')
  return string_hash(normalized_directory_path)


def get_file_contents_with_fatal_error_on_failure(path):
  """Return the contents of the specified file, or None on error."""
  try:
    with open(path, 'rb') as file_handle:
      data = file_handle.read()
    return data
  except IOError:
    logs.log_error('Unable to read file `%s\'' % path)

  raise errors.BadStateError


def get_line_seperator(label=''):
  """Return a line separator with an optional label."""
  separator = '-' * 40
  result = '\n\n%s%s%s\n\n' % (separator, label, separator)
  return result


def get_normalized_relative_path(file_path, directory_path):
  """Return normalized relative path for file w.r.t to a directory."""
  normalized_relative_file_path = remove_prefix(file_path,
                                                directory_path + os.sep)
  normalized_relative_file_path = (
      normalized_relative_file_path.replace('\\', '/'))
  return normalized_relative_file_path


def get_path_without_ext(path):
  """Return a path excluding the extension."""
  return os.path.splitext(path)[0]


def get_process_ids(process_id, recursive=True):
  """Return list of pids for a process and its descendants."""
  # Try to find the running process.
  if not psutil.pid_exists(process_id):
    return []

  pids = [process_id]

  try:
    psutil_handle = psutil.Process(process_id)
    children = psutil_handle.children(recursive=recursive)
    for child in children:
      pids.append(child.pid)
  except psutil.NoSuchProcess:
    # Avoid too much logging when the process already died.
    return []

  except (psutil.AccessDenied, OSError):
    logs.log_warn('Failed to get process children.')
    return []

  return pids


def get_line_count_string(line_count):
  """Return string representation for size."""
  if line_count == 0:
    return 'empty'
  if line_count == 1:
    return '1 line'
  return '%d lines' % line_count


def get_size_string(size):
  """Return string representation for size."""
  if size < 1 << 10:
    return '%d B' % size
  if size < 1 << 20:
    return '%d KB' % (size >> 10)
  if size < 1 << 30:
    return '%d MB' % (size >> 20)
  return '%d GB' % (size >> 30)


def get_unique_lines_in_unsymbolized_stack(symbolized_stacktrace,
                                           unsymbolized_stacktrace):
  """Return unique lines in unsymbolized stacktrace that are not in the
  symbolized stacktrace."""
  if symbolized_stacktrace == unsymbolized_stacktrace:
    return ''

  symbolized_stacktrace_lines = symbolized_stacktrace.splitlines()
  unsymbolized_stacktrace_lines = unsymbolized_stacktrace.splitlines()
  stripped_symbolized_stacktrace_lines = set()
  for line in symbolized_stacktrace_lines:
    stripped_symbolized_stacktrace_lines.add(line.strip())

  index = 0
  last_index = len(unsymbolized_stacktrace_lines) - 1
  start = -1
  end = -1
  while index <= last_index:
    if (unsymbolized_stacktrace_lines[index].strip() not in
        stripped_symbolized_stacktrace_lines):
      if start == -1:
        start = index
        end = index + 1
      else:
        end = index

    index += 1

  if start == -1:
    # Nothing unique found, return empty string.
    return ''

  line_gap = 2
  start = max(0, start - line_gap)
  end = min(end + line_gap, last_index + 1)
  result = '\n'.join(unsymbolized_stacktrace_lines[start:end])
  return result


def indent_string(string, chars):
  """Indents a string by x number of characters."""

  indented_string = ''
  for line in string.splitlines():
    indented_string += '%s%s\n' % ((' ' * chars), line)

  # Strip the ending '\n' and return result.
  return indented_string[0:-1]


def is_binary_file(file_path, bytes_to_read=1024):
  """Return true if the file looks like a binary file."""
  file_extension = os.path.splitext(file_path)[1].lower()
  if file_extension in BINARY_EXTENSIONS:
    return True
  if file_extension in TEXT_EXTENSIONS:
    return False

  text_characters = list(map(chr, list(range(32, 128)))) + ['\r', '\n', '\t']
  try:
    with open(file_path, 'rb') as file_handle:
      data = file_handle.read(bytes_to_read)
  except:
    logs.log_error('Could not read file %s in is_binary_file.' % file_path)
    return None

  binary_data = [char for char in data if char not in text_characters]

  return len(binary_data) > len(data) * 0.1


def is_recursive_call():
  """Returns true if the caller function is called recursively."""
  try:
    stack_frames = inspect.stack()
    caller_name = stack_frames[1][3]
    for stack_frame_index in range(2, len(stack_frames)):
      if caller_name == stack_frames[stack_frame_index][3]:
        return True
  except:
    pass

  return False


def is_valid_testcase_file(file_path,
                           check_if_exists=True,
                           size_limit=None,
                           allowed_extensions=None):
  """Return true if the file looks like a testcase file."""
  filename = os.path.basename(file_path)
  if filename.startswith('.') or filename.startswith(FUZZ_PREFIX):
    return False

  if allowed_extensions:
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension not in allowed_extensions:
      return False

  directories_to_ignore = ['.git', '.hg', '.svn']
  for directory_to_ignore in directories_to_ignore:
    directory_string = '%s%s%s' % (os.sep, directory_to_ignore, os.sep)
    if directory_string in file_path:
      return False

  if (check_if_exists or size_limit) and not os.path.exists(file_path):
    return False

  if size_limit and os.path.getsize(file_path) > size_limit:
    return False

  return True


def maximum_parallel_processes_allowed():
  """Return maximum number of parallel processes allowed. Adjust it based
  on thread multiplier."""
  if environment.is_trusted_host():
    # gRPC only supports 1 thread/process.
    return 1

  max_parallel_process_count = environment.get_value('MAX_FUZZ_THREADS', 1)
  thread_multiplier = environment.get_value('THREAD_MULTIPLIER', 1)

  max_parallel_process_count *= thread_multiplier
  return int(max_parallel_process_count)


def normalize_path(path):
  """Normalize path. This is needed on windows because windows' paths are
    case-insensitive."""
  return os.path.normcase(os.path.normpath(path))


def python_gc():
  """Call python's garbage collector."""
  # gc_collect isn't perfectly synchronous, because it may
  # break reference cycles that then take time to fully
  # finalize. Call it thrice and hope for the best.
  for _ in range(3):
    gc.collect()


def random_element_from_list(element_list):
  """Returns a random element from list."""
  return element_list[random.SystemRandom().randint(0, len(element_list) - 1)]


def random_number(start, end):
  """Returns a random number between start and end."""
  return random.SystemRandom().randint(start, end)


# pylint: disable=inconsistent-return-statements
def random_weighted_choice(element_list, weight_attribute='weight'):
  """Returns a random element from list taking its weight into account."""
  total = sum(getattr(e, weight_attribute) for e in element_list)
  random_pick = random.SystemRandom().uniform(0, total)
  temp = 0
  for element in element_list:
    element_weight = getattr(element, weight_attribute)
    if element_weight == 0:
      continue
    if temp + element_weight >= random_pick:
      return element
    temp += element_weight

  assert False, 'Failed to make a random weighted choice.'


def read_data_from_file(file_path, eval_data=True, default=None):
  """Returns eval-ed data from file."""
  if not os.path.exists(file_path):
    return default

  failure_wait_interval = environment.get_value('FAIL_WAIT')
  file_content = None
  retry_limit = environment.get_value('FAIL_RETRIES')
  for _ in range(retry_limit):
    try:
      with open(file_path, 'rb') as file_handle:
        file_content = file_handle.read()
    except:
      file_content = None
      logs.log_warn('Error occurred while reading %s, retrying.' % file_path)
      time.sleep(random.uniform(1, failure_wait_interval))
      continue

  if file_content is None:
    logs.log_error('Failed to read data from file %s.' % file_path)
    return None

  if not eval_data:
    return file_content

  if not file_content:
    return default

  try:
    return ast.literal_eval(file_content.decode('utf-8'))
  except (SyntaxError, TypeError):
    return None


def remove_prefix(string, prefix):
  """Strips the prefix from a string."""
  if string.startswith(prefix):
    return string[len(prefix):]

  return string


def remove_sub_strings(string, substrings):
  """Strips substrings from a given string."""
  result = string
  for substring in substrings:
    result = result.replace(substring, '')

  return result


def restart_machine():
  """Restart machine."""
  if environment.platform() == 'WINDOWS':
    os.system('shutdown /f /r /t 0')
  else:
    # POSIX platforms.
    os.system('sudo shutdown -r now')


def search_bytes_in_file(search_bytes, file_handle):
  """Helper to search for bytes in a large binary file without memory
  issues.
  """
  # TODO(aarya): This is too brittle and will fail if we have a very large
  # line.
  for line in file_handle:
    if search_bytes in line:
      return True

  return False


def string_hash(obj):
  """Returns a SHA-1 hash of the object. Not used for security purposes."""
  return hashlib.sha1(str(obj).encode('utf-8')).hexdigest()


def entity_hash(obj):
  """Returns a deterministic hash of a ndb entity.

  If an entity has been recently modified, put() must be called on it before
  this function will pick up the changes.
  """
  hasher = hashlib.sha1()
  entity_dict = obj.to_dict()
  for key in sorted(entity_dict.keys()):
    hasher.update(str(entity_dict[key]).encode('utf-8'))

  return hasher.hexdigest()


def string_is_true(value):
  """Check to see if a string has a value that should be treated as True."""
  return value and value != 'false' and value != 'False' and value != '0'


def strip_from_left(string, prefix):
  """Strip a prefix from start from string."""
  if not string.startswith(prefix):
    return string
  return string[len(prefix):]


def strip_from_right(string, suffix):
  """Strip a suffix from end of string."""
  if not string.endswith(suffix):
    return string
  return string[:len(string) - len(suffix)]


def sub_string_exists_in(substring_list, string):
  """Return true if one of the substring in the list is found in |string|."""
  for substring in substring_list:
    if substring in string:
      return True

  return False


def time_difference_string(timestamp):
  """Return time difference as a string."""
  if not timestamp:
    return ''

  delta = int((datetime.datetime.utcnow() - timestamp).total_seconds())
  d_minutes = delta // 60
  d_hours = d_minutes // 60
  d_days = d_hours // 24

  if d_days > 6:
    return '%s' % str(timestamp).split()[0]
  if d_days > 1:
    return '%s days ago' % d_days  # starts at 2 days.
  if d_hours > 1:
    return '%s hours ago' % d_hours  # starts at 2 hours.
  if d_minutes > 1:
    return '%s minutes ago' % d_minutes
  if d_minutes > 0:
    return '1 minute ago'
  if delta > -30:
    return 'moments ago'

  # Only say something is in the future if it is more than just clock skew.
  return 'in the future'


def timeout(duration):
  """Timeout decorator for functions."""

  def decorator(func):
    """Decorates the given function."""
    if environment.is_running_on_app_engine():
      # multiprocessing doesn't work on App Engine.
      return func

    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
      """Wrapper."""
      # FIXME: Weird exceptions in imports, might be something relating to our
      # reload module. Needs further investigation, try this as a temporary fix.
      import multiprocessing.pool
      import threading

      # Fix for Python < 2.7.2.
      if not hasattr(threading.current_thread(), '_children'):
        # pylint: disable=protected-access
        threading.current_thread()._children = weakref.WeakKeyDictionary()

      global THREAD_POOL
      if THREAD_POOL is None:
        THREAD_POOL = multiprocessing.pool.ThreadPool(processes=3)

      try:
        from clusterfuzz._internal.datastore import \
            ndb_init  # Avoid circular import.
        async_result = THREAD_POOL.apply_async(
            ndb_init.thread_wrapper(func), args=args, kwds=kwargs)
        return async_result.get(timeout=duration)
      except multiprocessing.TimeoutError:
        # Sleep for some minutes in order to wait for flushing metrics.
        time.sleep(120)

        # If we don't exit here, we will cause threads to pile up and leading to
        # out-of-memory. Safe to just exit here.
        logs.log_fatal_and_exit(
            ('Exception occurred in function {0}: args: {1}, kwargs: {2}'
             ' exception: {3}').format(func, args, kwargs,
                                       sys.exc_info()[1]))

    return _wrapper

  return decorator


def wait_until_timeout(threads, thread_timeout):
  """Wait for all threads to finish unless the given timeout is reached.

  If no thread is alive, it waits much shorter than the given timeout.

  Return True if timeout is exceeded, and return False otherwise.
  """
  thread_alive_check_interval = environment.get_value(
      'THREAD_ALIVE_CHECK_INTERVAL')
  if not thread_alive_check_interval:
    time.sleep(thread_timeout)
    return False

  wait_timeout = time.time() + thread_timeout
  while time.time() < wait_timeout:
    time.sleep(thread_alive_check_interval)

    thread_alive = False
    for thread in threads:
      if thread.is_alive():
        thread_alive = True
        break

    if not thread_alive:
      return False

  return True


def write_data_to_file(content, file_path, append=False):
  """Writes data to file."""
  failure_wait_interval = environment.get_value('FAIL_WAIT')
  file_mode = 'ab' if append else 'wb'
  retry_limit = environment.get_value('FAIL_RETRIES')

  # TODO(mbarbella): One extra iteration is allowed for the type conversion hack
  # included here. Once this function is converted to only accept bytes-like
  # objects, it should be adjusted back to the normal retry limit.
  for _ in range(retry_limit + 1):
    try:
      with open(file_path, file_mode) as file_handle:
        file_handle.write(content)
    except TypeError:
      # If we saw a TypeError, content was not bytes-like. Convert it.
      content = str(content).encode('utf-8')
      continue
    except EnvironmentError:
      # An EnvironmentError signals a problem writing the file. Retry in case
      # it was a spurious error.
      logs.log_warn('Error occurred while writing %s, retrying.' % file_path)
      time.sleep(random.uniform(1, failure_wait_interval))
      continue

    # Successfully written data file.
    return

  logs.log_error('Failed to write data to file %s.' % file_path)


@memoize.wrap(memoize.FifoInMemory(1))
def default_backup_bucket():
  """Return the default backup bucket for this instance of ClusterFuzz."""
  # Do not use |BACKUP_BUCKET| environment variable as that is the overridden
  # backup bucket from job type and is not the default backup bucket.
  return local_config.ProjectConfig().get('env.BACKUP_BUCKET')


@memoize.wrap(memoize.FifoInMemory(1))
def default_project_name():
  """Return the default project name for this instance of ClusterFuzz."""
  # Do not use |PROJECT_NAME| environment variable as that is the overridden
  # project name from job type and is not the default project name.
  return local_config.ProjectConfig().get('env.PROJECT_NAME')


def current_project():
  """Return the project for the current job, or the default project."""
  return environment.get_value('PROJECT_NAME', default_project_name())


def current_source_version():
  """Return the current source revision."""
  # For test use.
  source_version_override = environment.get_value('SOURCE_VERSION_OVERRIDE')
  if source_version_override:
    return source_version_override

  root_directory = environment.get_value('ROOT_DIR')
  local_manifest_path = os.path.join(root_directory, LOCAL_SOURCE_MANIFEST)
  if os.path.exists(local_manifest_path):
    return read_data_from_file(
        local_manifest_path, eval_data=False).strip().decode('utf-8')

  return None


def read_from_handle_truncated(file_handle, max_len):
  """Read from file handle, limiting output to |max_len| by removing output in
  the middle."""
  file_handle.seek(0, os.SEEK_END)
  file_size = file_handle.tell()
  file_handle.seek(0, os.SEEK_SET)

  if file_size <= max_len:
    return file_handle.read()

  # Read first and last |half_max_len| bytes.
  half_max_len = max_len // 2
  start = file_handle.read(half_max_len)
  file_handle.seek(file_size - half_max_len, os.SEEK_SET)
  end = file_handle.read(half_max_len)

  truncated_marker = b'\n...truncated %d bytes...\n' % (file_size - max_len)

  return start + truncated_marker + end


def normalize_email(email):
  """Normalize an email address."""
  # TODO(ochang): Investigate whether if it makes sense to replace
  # @googlemail.com with @gmail.com.
  return email.lower()


def emails_equal(first, second):
  """Return whether or not the 2 emails are equal after being normalized."""
  if not first or not second:
    return False

  return normalize_email(first) == normalize_email(second)


def parse_delimited(value_or_handle, delimiter, strip=False,
                    remove_empty=False):
  """Parse a delimter separated value."""
  if hasattr(value_or_handle, 'read'):
    results = value_or_handle.read().split(delimiter)
  else:
    results = value_or_handle.split(delimiter)

  if not strip and not remove_empty:
    return results

  processed_results = []
  for result in results:
    if strip:
      result = result.strip()

    if remove_empty and not result:
      continue

    processed_results.append(result)

  return processed_results


def is_oss_fuzz():
  """If this is an instance of OSS-Fuzz."""
  return default_project_name() == 'oss-fuzz'


def is_chromium():
  """If this is an instance of chromium fuzzing."""
  return default_project_name() == 'chromium'


def file_hash(file_path):
  """Returns the SHA-1 hash of |file_path| contents."""
  chunk_size = 51200  # Read in 50 KB chunks.
  digest = hashlib.sha1()
  with open(file_path, 'rb') as file_handle:
    chunk = file_handle.read(chunk_size)
    while chunk:
      digest.update(chunk)
      chunk = file_handle.read(chunk_size)

  return digest.hexdigest()


def cpu_count():
  """Get the CPU count."""
  # Does not import on App Engine.
  import multiprocessing

  return environment.get_value('CPU_COUNT_OVERRIDE',
                               multiprocessing.cpu_count())

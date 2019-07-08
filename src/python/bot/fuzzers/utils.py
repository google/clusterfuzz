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
"""Fuzzer utils."""

import os
import re
import stat
import tempfile

from base import utils
from metrics import logs
from system import environment
from system import shell

ALLOWED_FUZZ_TARGET_EXTENSIONS = ['', '.exe']
FUZZ_TARGET_SEARCH_STRING = 'LLVMFuzzerTestOneInput'
VALID_TARGET_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')


def is_lpm_fuzz_target(fuzzer_path):
  """Creates a file handle from |fuzzer_path| passes it to
  is_lpm_fuzz_target_handle and returns the result."""
  with open(fuzzer_path) as file_handle:
    return is_lpm_fuzz_target_handle(file_handle)


def is_lpm_fuzz_target_handle(fuzzer_handle):
  """Returns True if |fuzzer_handle| is a libprotobuf-mutator based fuzz
  target."""
  return utils.search_string_in_file('TestOneProtoInput', fuzzer_handle)


def is_fuzz_target_local(file_path, file_handle=None):
  """Returns whether |file_path| is a fuzz target binary (local path)."""
  filename, file_extension = os.path.splitext(os.path.basename(file_path))
  if not VALID_TARGET_NAME.match(filename):
    # Check fuzz target has a valid name (without any special chars).
    return False

  if file_extension not in ALLOWED_FUZZ_TARGET_EXTENSIONS:
    # Ignore files with disallowed extensions (to prevent opening e.g. .zips).
    return False

  if not file_handle and not os.path.exists(file_path):
    # Ignore non-existant files for cases when we don't have a file handle.
    return False

  if os.path.exists(file_path) and not stat.S_ISREG(os.stat(file_path).st_mode):
    # Don't read special files (eg: /dev/urandom).
    logs.log_warn('Tried to read from non-regular file: %s.' % file_path)
    return False

  class LocalFileHandle(object):
    """A context manager that opens a file handle on entry if needed and closes
    or rewinds the handle on exit."""

    def __init__(self):
      self.handle = None
      self.initial_position = None

    def __enter__(self):
      """Sets self.handle to |file_handle| if it is not None, otherwise set it
      to a new handle to |file_path|."""
      self.handle = file_handle or open(file_path, 'rb')
      self.initial_position = self.handle.tell()
      return self

    def __exit__(self, exc_type, exc_val, exc_tb):
      """Closes self.handle if we own it, otherwise rewinds it so it can be read
      from again."""
      if file_handle:
        self.handle.seek(self.initial_position)
      else:
        self.handle.close()

  with LocalFileHandle() as local_file_handle:
    if environment.is_afl_job():
      return not is_lpm_fuzz_target_handle(local_file_handle.handle)

  if filename.endswith('_fuzzer'):
    return True

  # TODO(aarya): Remove this optimization if it does not show up significant
  # savings in profiling results.
  fuzz_target_name_regex = environment.get_value('FUZZER_NAME_REGEX')
  if fuzz_target_name_regex:
    return bool(re.match(fuzz_target_name_regex, filename))

  with LocalFileHandle() as local_file_handle:
    # TODO(metzman): Bound this call so we don't read forever if something went
    # wrong.
    return utils.search_string_in_file(FUZZ_TARGET_SEARCH_STRING,
                                       local_file_handle.handle)


def get_fuzz_targets_local(path):
  """Get list of fuzz targets paths (local)."""
  fuzz_target_paths = []

  for root, _, files in os.walk(path):
    for filename in files:
      file_path = os.path.join(root, filename)
      if is_fuzz_target_local(file_path):
        fuzz_target_paths.append(file_path)

  return fuzz_target_paths


def get_fuzz_targets(path):
  """Get list of fuzz targets paths."""
  if environment.is_trusted_host():
    from bot.untrusted_runner import file_host
    return file_host.get_fuzz_targets(path)
  return get_fuzz_targets_local(path)


def extract_argument(arguments, prefix, remove=True):
  """Extract argument from arguments."""
  for argument in arguments[:]:
    if argument.startswith(prefix):
      if remove:
        arguments.remove(argument)
      return argument[len(prefix):]

  return None


def get_build_revision():
  """Get build revision."""
  try:
    build_revision = int(environment.get_value('APP_REVISION'))
  except (ValueError, TypeError):
    build_revision = -1

  return build_revision


def get_supporting_file(fuzz_target_path, extension_or_suffix):
  """Get supporting file for a fuzz target with the provided extension."""
  return utils.get_path_without_ext(fuzz_target_path) + extension_or_suffix


def get_temp_dir():
  """Return the temp dir."""
  temp_dirname = 'temp-' + str(os.getpid())
  temp_directory = os.path.join(
      environment.get_value('FUZZ_INPUTS_DISK'), temp_dirname)
  shell.create_directory(temp_directory)
  return temp_directory


def get_file_from_untrusted_worker(worker_file_path):
  """Gets file from an untrusted worker to local. Local file stays in the temp
  folder until the end of task or can be explicitly deleted by the caller."""
  from bot.untrusted_runner import file_host

  with tempfile.NamedTemporaryFile(delete=False, dir=get_temp_dir()) as f:
    local_file_path = f.name

  file_host.copy_file_from_worker(worker_file_path, local_file_path)
  return local_file_path


def cleanup():
  """Clean up temporary metadata."""
  shell.remove_directory(get_temp_dir())

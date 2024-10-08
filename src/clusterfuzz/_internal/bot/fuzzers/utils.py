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

import functools
import os
import re
import stat
import tempfile
from typing import Callable
from typing import Optional

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

ALLOWED_FUZZ_TARGET_EXTENSIONS = ['', '.exe', '.par']
FUZZ_TARGET_SEARCH_BYTES = [b'LLVMFuzzerTestOneInput', b'LLVMFuzzerRunDriver']
VALID_TARGET_NAME_REGEX = re.compile(r'^[a-zA-Z0-9@_.-]+$')
BLOCKLISTED_TARGET_NAME_REGEX = re.compile(r'^(jazzer_driver.*)$')
EXTRA_BUILD_DIR = '__extra_build'


def is_fuzz_target(file_path, file_opener: Optional[Callable] = None):
  """Returns whether |file_path| is a fuzz target binary (local path)."""
  if '@' in file_path:
    # GFT targets often have periods in the name that get misinterpreted as an
    # extension.
    filename = os.path.basename(file_path)
    file_extension = ''
  else:
    filename, file_extension = os.path.splitext(os.path.basename(file_path))

  if not VALID_TARGET_NAME_REGEX.match(filename):
    # Check fuzz target has a valid name (without any special chars).
    return False

  if BLOCKLISTED_TARGET_NAME_REGEX.match(filename):
    # Check fuzz target an explicitly disallowed name (e.g. binaries used for
    # jazzer-based targets).
    return False

  if file_extension not in ALLOWED_FUZZ_TARGET_EXTENSIONS:
    # Ignore files with disallowed extensions (to prevent opening e.g. .zips).
    return False

  if not file_opener and not os.path.exists(file_path):
    # Ignore non-existent files for cases when we don't have a file handle.
    return False

  if (filename.endswith('_fuzzer') or filename.endswith('_fuzztest') or
      filename.endswith('_fuzz_test')):
    return True

  # TODO(aarya): Remove this optimization if it does not show up significant
  # savings in profiling results.
  fuzz_target_name_regex = environment.get_value('FUZZER_NAME_REGEX')
  if fuzz_target_name_regex:
    return bool(re.match(fuzz_target_name_regex, filename))

  if os.path.exists(file_path) and not stat.S_ISREG(os.stat(file_path).st_mode):
    # Don't read special files (eg: /dev/urandom).
    logs.warning('Tried to read from non-regular file: %s.' % file_path)
    return False

  # Either use the file opener or open the file ourselves.
  if not file_opener:
    file_opener = functools.partial(open, mode='rb')
  try:
    with file_opener(file_path) as file_handle:
      result = False
      for pattern in FUZZ_TARGET_SEARCH_BYTES:
        # TODO(metzman): Bound this call so we don't read forever if something
        # went wrong.
        file_handle.seek(0)
        result = utils.search_bytes_in_file(pattern, file_handle)
        if result:
          break

      file_handle.close()

      return result
  except Exception as e:
    # In case we could not open the file, we consider it's not a fuzzer.
    logs.warning(f'Could not open {file_path}: {e}')
    return False


def get_fuzz_targets_local(path):
  """Get list of fuzz targets paths (local)."""
  fuzz_target_paths = []

  for root, _, files in shell.walk(path):
    for filename in files:
      if os.path.basename(root) == EXTRA_BUILD_DIR:
        # Ignore extra binaries.
        continue

      file_path = os.path.join(root, filename)
      if is_fuzz_target(file_path):
        fuzz_target_paths.append(file_path)

  return fuzz_target_paths


def get_fuzz_targets(path):
  """Get list of fuzz targets paths."""
  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import file_host
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
  base_fuzz_target_path = fuzz_target_path

  # Strip any known extensions.
  for ext in ALLOWED_FUZZ_TARGET_EXTENSIONS:
    if not ext:
      continue

    if base_fuzz_target_path.endswith(ext):
      base_fuzz_target_path = base_fuzz_target_path[:-len(ext)]
      break

  return base_fuzz_target_path + extension_or_suffix


def get_temp_dir(use_fuzz_inputs_disk=True):
  """Return the temp dir."""
  temp_dirname = 'temp-' + str(os.getpid())
  if use_fuzz_inputs_disk:
    prefix = environment.get_value('FUZZ_INPUTS_DISK', tempfile.gettempdir())
  else:
    prefix = tempfile.gettempdir()
  temp_directory = os.path.join(prefix, temp_dirname)
  shell.create_directory(temp_directory)
  return temp_directory


def get_file_from_untrusted_worker(worker_file_path):
  """Gets file from an untrusted worker to local. Local file stays in the temp
  folder until the end of task or can be explicitly deleted by the caller."""
  from clusterfuzz._internal.bot.untrusted_runner import file_host

  with tempfile.NamedTemporaryFile(delete=False, dir=get_temp_dir()) as f:
    local_file_path = f.name

  file_host.copy_file_from_worker(worker_file_path, local_file_path)
  return local_file_path


def cleanup():
  """Clean up temporary metadata."""
  shell.remove_directory(get_temp_dir())


def normalize_target_name(target_path):
  """Normalize target path, removing file extensions."""
  target_name = os.path.basename(target_path)
  if '@' in target_name:
    # GFT target names often have periods in their name.
    return target_name

  return os.path.splitext(target_name)[0]

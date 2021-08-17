# Copyright 2021 Google LLC
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
"""Helper functions for managing and interacting with Fuchsia devices
via undercoat."""

import os
import shutil
import tempfile

from clusterfuzz._internal.base import persistent_cache
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process

# In order to properly clean up any stale instances, we keep track of handles in
# the persistent cache. We assume that only one instance of a bot will be
# accessing this cache at a time.
HANDLE_CACHE_KEY = 'undercoat-handles'


def add_running_handle(handle):
  """Record a handle as potentially needing to be cleaned up on restart."""
  new_handle_list = list(set(get_running_handles()) | set([handle]))
  persistent_cache.set_value(
      HANDLE_CACHE_KEY, new_handle_list, persist_across_reboots=True)


def remove_running_handle(handle):
  """Remove a handle from the tracked set."""
  new_handle_list = list(set(get_running_handles()) - set([handle]))
  persistent_cache.set_value(
      HANDLE_CACHE_KEY, new_handle_list, persist_across_reboots=True)


def get_running_handles():
  """Get a list of potentially stale handles from previous runs."""
  return persistent_cache.get_value(HANDLE_CACHE_KEY, default_value=[])


def get_temp_dir():
  """Define a tempdir for undercoat to store its data in.

  This tempdir needs to be of a scope that persists across invocations of the
  bot, to ensure proper cleanup of stale handles/data."""
  temp_dir = os.path.join(environment.get_value('ROOT_DIR'), 'bot', 'undercoat')
  os.makedirs(temp_dir, exist_ok=True)

  return temp_dir


class UndercoatError(Exception):
  """Error for errors while running undercoat."""


def undercoat_api_command(*args):
  """Make an API call to the undercoat binary."""
  logs.log(f'Running undercoat command {args}')
  bundle_dir = environment.get_value('FUCHSIA_RESOURCES_DIR')
  undercoat_path = os.path.join(bundle_dir, 'undercoat', 'undercoat')
  undercoat = new_process.ProcessRunner(undercoat_path, args)
  # The undercoat log is sent to stderr, which we capture to a tempfile
  with tempfile.TemporaryFile() as undercoat_log:
    result = undercoat.run_and_wait(
        stderr=undercoat_log, extra_env={'TMPDIR': get_temp_dir()})
    result.output = result.output.decode('utf-8')

    if result.return_code != 0:
      # Dump the undercoat log to assist in debugging
      log_data = utils.read_from_handle_truncated(undercoat_log, 1024 * 1024)
      logs.log_warn('Log output from undercoat: ' + log_data.decode('utf-8'))

      # The API error message is returned on stdout
      raise UndercoatError(
          'Error running undercoat command %s: %s' % (args, result.output))

  return result


def undercoat_instance_command(command, handle, *args, abort_on_error=True):
  """Helper for the subset of undercoat commands that operate on an instance."""
  try:
    return undercoat_api_command(command, '-handle', handle, *args)
  except UndercoatError:
    if abort_on_error:
      # Try to print extra logs and shut down
      # TODO(eep): Should we be attempting to automatically restart?
      dump_instance_logs(handle)
      stop_instance(handle)
    raise


def get_version():
  """Get undercoat API version as (major, minor, patch) tuple."""
  version = undercoat_api_command('version').output

  if not version.startswith('v'):
    raise UndercoatError('Invalid version reported: %s' % version)

  parts = version[1:].split('.')
  if len(parts) != 3:
    raise UndercoatError('Invalid version reported: %s' % version)

  try:
    return tuple(int(part) for part in parts)
  except ValueError as e:
    raise UndercoatError('Invalid version reported: %s' % version) from e


def validate_api_version():
  """Check that the undercoat API version is supported. Raises an error if it is
  not."""
  major, minor, patch = get_version()
  if major > 0:
    raise UndercoatError(
        'Unsupported API version: %d.%d.%d' % (major, minor, patch))


def dump_instance_logs(handle):
  """Dump logs from an undercoat instance."""
  qemu_log = undercoat_instance_command(
      'get_logs', handle, abort_on_error=False).output
  logs.log_warn(qemu_log)


def start_instance():
  """Start an instance via undercoat."""
  handle = undercoat_api_command('start_instance').output.strip()
  logs.log('Started undercoat instance with handle %s' % handle)

  # Immediately save the handle in case we crash before stop_instance()
  # is called
  add_running_handle(handle)

  return handle


def stop_all():
  """Attempt to stop any running undercoat instances that may have not been
  cleanly shut down."""
  for handle in get_running_handles():
    try:
      undercoat_instance_command('stop_instance', handle, abort_on_error=False)
    except UndercoatError:
      pass

    # Even if we failed to stop_instance above, there's no point in trying
    # again later
    remove_running_handle(handle)

  # At this point, all handles/data should have been cleaned up, but if any is
  # remaining then we clear it out here
  shutil.rmtree(get_temp_dir())


def stop_instance(handle):
  """Stop a running undercoat instance."""
  result = undercoat_instance_command(
      'stop_instance', handle, abort_on_error=False)

  # Mark the corresponding handle as having been cleanly shut down
  remove_running_handle(handle)

  return result


def list_fuzzers(handle):
  """Start an instance via undercoat."""
  return undercoat_instance_command('list_fuzzers', handle).output.split('\n')


def prepare_fuzzer(handle, fuzzer):
  """Prepare a fuzzer of the given name for use, via undercoat."""
  return undercoat_instance_command('prepare_fuzzer', handle, '-fuzzer', fuzzer)


def run_fuzzer(handle, fuzzer, outdir, args):
  """Run a fuzzer of the given name, via undercoat."""
  # TODO(fxbug.dev/47490): Pass back raw return code from libFuzzer?
  undercoat_args = ['-fuzzer', fuzzer]
  if outdir:
    undercoat_args += ['-artifact-dir', outdir]
  args = undercoat_args + ['--'] + args
  return undercoat_instance_command('run_fuzzer', handle, *args)


def put_data(handle, fuzzer, src, dst):
  """Put files for a fuzzer onto an instance, via undercoat.
  If src is a directory, it will be copied recursively. Standard globs are
  supported."""
  return undercoat_instance_command('put_data', handle, '-fuzzer', fuzzer,
                                    '-src', src, '-dst', dst).output


def get_data(handle, fuzzer, src, dst):
  """Get files from a fuzzer on an instance, via undercoat.
  If src is a directory, it will be copied recursively. Standard globs are
  supported."""
  try:
    return undercoat_instance_command(
        'get_data',
        handle,
        '-fuzzer',
        fuzzer,
        '-src',
        src,
        '-dst',
        dst,
        abort_on_error=False).output
  except UndercoatError:
    return None

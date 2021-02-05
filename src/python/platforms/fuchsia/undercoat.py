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
import sys
import tempfile

from metrics import logs
from system import environment
from system import new_process
from system import shell

# In order to properly clean up any stale instances, we need to keep track of
# handles in a way that persists between runs
UNDERCOAT_HANDLE_DIR = os.path.join(tempfile.gettempdir(), 'undercoat-handles')


def get_all_handles():
  """Returns pairs of (filename, handle) for instances that have been started
  but not yet shut down. The filenames themselves hold no meaning, but are
  needed to delete the handle references."""

  for handle_file in shell.get_files_list(UNDERCOAT_HANDLE_DIR):
    with open(handle_file, 'r') as f:
      handle = f.read().strip()
    yield handle_file, handle


class UndercoatError(Exception):
  """Error for errors while running undercoat."""


def undercoat_api_command(*args):
  """Make an API call to the undercoat binary."""
  bundle_dir = environment.get_value('FUCHSIA_RESOURCES_DIR')
  undercoat_path = os.path.join(bundle_dir, 'undercoat/undercoat')
  undercoat = new_process.ProcessRunner(undercoat_path, args)
  # TODO(eep): Is there a more useful way to connect stderr to the
  # logging system?
  result = undercoat.run_and_wait(stderr=sys.stderr)
  result.output = result.output.decode('utf-8')

  if result.return_code != 0:
    raise UndercoatError(
        'Error running undercoat command %s: %s' % (args, result.output))

  return result


def undercoat_instance_command(command, handle, *args):
  """Helper for the subset of undercoat commands that operate on an instance."""
  try:
    return undercoat_api_command(command, '-handle', handle, *args)
  except UndercoatError:
    # Try to print extra logs and shut down
    # TODO(eep): Should we be attempting to automatically restart?
    dump_instance_logs(handle)
    stop_instance(handle)
    raise


def dump_instance_logs(handle):
  """Dump logs from an undercoat instance."""
  # Avoids using undercoat_instance_command in order to avoid recursion on error
  qemu_log = undercoat_api_command('get_logs', '-handle', handle).output
  logs.log_warn(qemu_log)


def start_instance():
  """Start an instance via undercoat."""
  handle = undercoat_api_command('start_instance').output.strip()
  logs.log('Started undercoat instance with handle %s' % handle)

  # Immediately save the handle in case we crash before stop_instance()
  # is called
  shell.create_directory(UNDERCOAT_HANDLE_DIR)
  with tempfile.NamedTemporaryFile(
      dir=UNDERCOAT_HANDLE_DIR, mode='w', delete=False) as f:
    f.write(handle)

  return handle


def stop_all():
  """Attempt to stop any running undercoat instances that may have not been
  cleanly shut down."""
  for handle_file, handle in get_all_handles():
    try:
      undercoat_instance_command('stop_instance', handle)
    except UndercoatError:
      pass

    # Even if we failed to stop_instance above, there's no point in trying
    # again later
    shell.remove_file(handle_file)


def stop_instance(handle):
  """Stop a running undercoat instance."""
  # Avoids using undercoat_instance_command in order to avoid recursion on error
  result = undercoat_api_command('stop_instance', '-handle', handle)

  # Remove the corresponding handle file now that we've cleanly shut down
  handle_file = next((f for f, h in get_all_handles() if h == handle), None)
  if handle_file:
    shell.remove_file(handle_file)

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
  """Put files for a fuzzer onto an instance, via undercoat."""
  return undercoat_instance_command('put_data', handle, '-fuzzer', fuzzer,
                                    '-src', src, '-dst', dst).output


def get_data(handle, fuzzer, src, dst):
  """Get files from a fuzzer on an instance, via undercoat."""
  return undercoat_instance_command('get_data', handle, '-fuzzer', fuzzer,
                                    '-src', src, '-dst', dst).output

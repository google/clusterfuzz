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
"""Functions for running gsutil."""

import os
import shutil

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process

# Default timeout for a GSUtil sync.
FILES_SYNC_TIMEOUT = 5 * 60 * 60


def use_gcloud_for_command(command):
  """Returns whether to use gcloud storage for the given command."""
  return bool(environment.get_value(f'USE_GCLOUD_STORAGE_{command.upper()}'))


def get_gcloud_path():
  """Get path to gcloud executable."""
  gcloud_executable = 'gcloud'
  if environment.platform() == 'WINDOWS':
    gcloud_executable += '.cmd'

  # Try searching the binary in path.
  gcloud_absolute_path = shutil.which(gcloud_executable)
  if gcloud_absolute_path:
    return gcloud_absolute_path

  logs.error('Cannot locate gcloud in PATH.')
  return None


def get_gsutil_path():
  """Get path to gsutil executable.

  Returns:
    Path to gsutil executable on the system.
  """
  gsutil_executable = 'gsutil'
  if environment.platform() == 'WINDOWS':
    gsutil_executable += '.cmd'

  gsutil_directory = environment.get_value('GSUTIL_PATH')
  if not gsutil_directory:
    # Try searching the binary in path.
    gsutil_absolute_path = shutil.which(gsutil_executable)
    if gsutil_absolute_path:
      return gsutil_absolute_path

    logs.error('Cannot locate gsutil in PATH, set GSUTIL_PATH to directory '
               'containing gsutil binary.')
    return None

  gsutil_absolute_path = os.path.join(gsutil_directory, gsutil_executable)
  return gsutil_absolute_path


def _multiprocessing_args():
  """Get multiprocessing args for gsutil."""
  if utils.cpu_count() == 1:
    # GSUtil's default thread count is 5 as it assumes the common configuration
    # is many CPUs (GSUtil uses num_cpu processes).
    return ['-o', 'GSUtil:parallel_thread_count=16']

  return []


def _filter_path(path, write=False):
  """Filters path if needed. In local development environment, this uses local
  paths from an emulated GCS instead of real GCS. `write` indicates whether if
  `path` is a GCS write destination and that intermediate paths should be
  automatically created."""
  if not path.startswith(storage.GS_PREFIX):
    # Only applicable to GCS paths.
    return path

  local_buckets_path = environment.get_value('LOCAL_GCS_BUCKETS_PATH')
  if not local_buckets_path:
    return path

  if write:
    local_path = storage.FileSystemProvider(
        local_buckets_path).convert_path_for_write(path)
  else:
    local_path = storage.FileSystemProvider(local_buckets_path).convert_path(
        path)

  return local_path


class GSUtilRunner:
  """GSUtil/gcloud storage runner."""

  def __init__(self, process_runner=new_process.ProcessRunner):
    self._process_runner = process_runner

  def _get_runner_and_args(self, use_gcloud_storage, quiet=False):
    """Get the process runner and default arguments."""
    if use_gcloud_storage:
      executable_path = get_gcloud_path()
      default_args = ['storage']
      runner = self._process_runner(
          executable_path=executable_path, default_args=default_args)
      additional_args = []
    else:
      executable_path = get_gsutil_path()
      default_args = ['-m']
      default_args.extend(_multiprocessing_args())
      runner = self._process_runner(
          executable_path=executable_path, default_args=default_args)

      # gcloud storage does not have a -q flag, it is a global gcloud flag
      # --quiet, but that suppresses all output, which is not what we want.
      # gsutil's -q suppresses the "Copying..." summary, which is desired.
      additional_args = ['-q'] if quiet else []

    return runner, additional_args

  def run_gsutil(self, arguments, use_gcloud_storage, quiet=False, **kwargs):
    """Run GSUtil or gcloud storage."""
    runner, additional_args = self._get_runner_and_args(use_gcloud_storage,
                                                        quiet)
    arguments = additional_args + arguments

    env = os.environ.copy()
    if not use_gcloud_storage and 'PYTHONPATH' in env:
      # GSUtil may be on Python 3, and our PYTHONPATH breaks it because we're on
      # Python 2.
      env.pop('PYTHONPATH')

    return runner.run_and_wait(arguments, env=env, **kwargs)

  def rsync(self,
            source,
            destination,
            timeout=FILES_SYNC_TIMEOUT,
            delete=True,
            exclusion_pattern=None):
    """Rsync with gsutil or gcloud storage."""
    use_gcloud = use_gcloud_for_command('rsync')
    if use_gcloud:
      command = ['rsync']
      # gcloud storage rsync is recursive by default.
      if delete:
        command.append('--delete-unmatched-destination-objects')
      if exclusion_pattern:
        command.extend(['--exclude', exclusion_pattern])
    else:
      command = ['rsync', '-r']
      if delete:
        command.append('-d')
      if exclusion_pattern:
        command.extend(['-x', exclusion_pattern])

    command.extend([
        _filter_path(source, write=True),
        _filter_path(destination, write=True),
    ])

    return self.run_gsutil(command, use_gcloud, timeout=timeout, quiet=True)

  def download_file(self, gcs_url, file_path, timeout=None):
    """Download a file from GCS."""
    use_gcloud = use_gcloud_for_command('cp')
    command = ['cp', _filter_path(gcs_url), file_path]
    result = self.run_gsutil(command, use_gcloud, timeout=timeout)
    if result.return_code:
      logs.error('GSUtilRunner.download_file failed:\nCommand: %s\n'
                 'Url: %s\n'
                 'Output %s' % (result.command, gcs_url, result.output))

    return result.return_code == 0

  def upload_file(self,
                  file_path,
                  gcs_url,
                  timeout=None,
                  gzip=False,
                  metadata=None):
    """Upload a single file to a given GCS url."""
    if not file_path or not gcs_url:
      return False

    use_gcloud = use_gcloud_for_command('cp')
    if use_gcloud:
      # For gcloud, setting metadata is a separate step after uploading.
      cp_command = ['cp']
      if gzip:
        cp_command.append('--gzip-in-flight-all')

      cp_command.extend([file_path, _filter_path(gcs_url, write=True)])
      result = self.run_gsutil(cp_command, use_gcloud, timeout=timeout)

      if result.return_code != 0:
        logs.error('GSUtilRunner.upload_file (cp step) failed:\nCommand: %s\n'
                   'Filename: %s\n'
                   'Output: %s' % (result.command, file_path, result.output))
        return False

      if metadata:
        update_command = [
            'objects', 'update',
            _filter_path(gcs_url, write=True)
        ]
        # The metadata dict is assumed to contain only custom metadata keys,
        # not standard headers like 'Content-Type'.
        metadata_args = [f'{k}={v}' for k, v in metadata.items()]
        update_command.append('--update-custom-metadata')
        # pylint: disable=line-too-long
        update_command.append(','.join(metadata_args))

        result = self.run_gsutil(update_command, use_gcloud, timeout=timeout)
        if result.return_code != 0:
          logs.error(
              'GSUtilRunner.upload_file (update metadata step) failed:\nCommand: %s\n'
              'Filename: %s\n'
              'Output: %s' % (result.command, file_path, result.output))
          return False

      return True

    # gsutil can set metadata during cp.
    command = []
    if metadata:
      for key, value in metadata.items():
        # gsutil uses headers for metadata. For custom metadata, the
        # convention is 'x-goog-meta-'. The caller is responsible for this.
        # pylint: disable=line-too-long
        command.extend(['-h', f'{key}:{value}'])

    command.append('cp')
    if gzip:
      command.append('-Z')

    command.extend([file_path, _filter_path(gcs_url, write=True)])
    result = self.run_gsutil(command, use_gcloud, timeout=timeout)

    if result.return_code:
      logs.error('GSUtilRunner.upload_file failed:\nCommand: %s\n'
                 'Filename: %s\n'
                 'Output: %s' % (result.command, file_path, result.output))
      return False

    return True

  def upload_files_to_url(self, file_paths, gcs_url, timeout=None):
    """Upload files to the given GCS url."""
    if not file_paths or not gcs_url:
      return False

    use_gcloud = use_gcloud_for_command('cp')
    if use_gcloud:
      command = [
          'cp', '--read-paths-from-stdin',
          _filter_path(gcs_url, write=True)
      ]
    else:
      command = ['cp', '-I', _filter_path(gcs_url, write=True)]

    filenames_buffer = '\n'.join(file_paths)

    result = self.run_gsutil(
        command,
        use_gcloud,
        input_data=filenames_buffer.encode('utf-8'),
        timeout=timeout)

    # Check result of command execution, log output if command failed.
    if result.return_code:
      logs.error(
          'GSUtilRunner.upload_files_to_url failed:\nCommand: %s\n'
          'Filenames:%s\n'
          'Output: %s' % (result.command, filenames_buffer, result.output))

    return result.return_code == 0

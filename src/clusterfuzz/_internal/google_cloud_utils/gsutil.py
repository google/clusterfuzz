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
"""Functions for running gcloud storage."""

import os
import shutil

from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process

# Default timeout for a rsync.
FILES_SYNC_TIMEOUT = 5 * 60 * 60


def get_gcloud_path():
  """Get path to gcloud executable."""
  gcloud_executable = 'gcloud'
  if environment.platform() == 'WINDOWS':
    gcloud_executable += '.cmd'

  gcloud_storage_dir = environment.get_value('GCLOUD_PATH')
  if not gcloud_storage_dir:
    # Fallback to older GSUTIL_PATH, if needed.
    gcloud_storage_dir = environment.get_value('GSUTIL_PATH')

  if gcloud_storage_dir:
    return os.path.join(gcloud_storage_dir, gcloud_executable)

  # Try searching the binary in path.
  gcloud_absolute_path = shutil.which(gcloud_executable)
  if gcloud_absolute_path:
    return gcloud_absolute_path

  logs.error('Cannot locate gcloud in PATH, set GCLOUD_PATH to directory '
             'containing gcloud binary.')
  return None


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


class GCloudStorageRunner:
  """Gcloud storage runner."""

  def __init__(self, process_runner=new_process.ProcessRunner):
    """Initialize a gcloud process runner.

    For gcloud storage, all operations run in parallel by default, so no need
    to add -m. Also, as gcloud storage handles the distribution of threads
    dynamically, it is smart enough to not underwhelm the thread pool,
    so we don't need to set the thread count for a single cpu.
    """
    self.gcloud_runner = process_runner(
        executable_path=get_gcloud_path(), default_args=['storage'])

  def run_gcloud_storage(self, arguments, quiet=True, verbose=True, **kwargs):
    """Run a gcloud storage command."""

    # Enable user intended output to console. Useful for logging as this is
    # stored at result from subprocess.
    additional_args = (['--user-output-enabled']
                       if verbose else ['--no-user-output-enabled'])
    # Disable all interactive prompts.
    additional_args += ['-q'] if quiet else []

    cmd = arguments[0] if arguments else 'unknown'
    arguments = additional_args + arguments

    # Get some info for logging.
    tool_name = 'gcloud storage'
    arg_str = ' '.join(arguments)
    try:
      cwd = os.getcwd()
    except OSError:
      cwd = 'unknown'

    logs.info(
        f'Running {cmd} with {tool_name}.',
        tool_name=tool_name,
        cmd=cmd,
        cwd=cwd,
        arguments=arg_str)
    print(f'Running {cmd} with {tool_name}. cwd={cwd}, args={arg_str}')
    try:
      result = self.gcloud_runner.run_and_wait(arguments, **kwargs)
      logs.info(
          f'Finished running {cmd} with {tool_name}.',
          tool_name=tool_name,
          cmd=cmd,
          cwd=cwd,
          arguments=arg_str,
          return_code=result.return_code,
          timed_out=result.timed_out,
          output=result.output)
      print(f'Finished Running {cmd} with {tool_name}. cwd={cwd}, '
            f'args={arg_str}, return_code={result.return_code}, '
            f'timed_out={result.timed_out}, output={result.output}')
      return result
    except Exception as e:
      logs.error(
          f'Failed to run {cmd} with {tool_name}.',
          tool_name=tool_name,
          cmd=cmd,
          cwd=cwd,
          arguments=arg_str)
      print(f'Failed to run {cmd} with {tool_name}. cwd={cwd}, '
            f'args={arg_str}, exception={e}')
      raise

  def rsync(self,
            source,
            destination,
            timeout=FILES_SYNC_TIMEOUT,
            delete=True,
            exclusion_pattern=None,
            recursive=True):
    """Synchronize content of two buckets/dirs using gcloud rsync.
    
    For instance, to download corpus files from a GCS url.

    Args:
      source: Source to rsync from.
      destination: Destination to rsync to.
      timeout: Timeout for gcloud storage.
      delete: Whether to delete files on destination that don't exist in source.
      exclusion_pattern: Regex for objects to no be included in rsync.
      recursive: Whether to recursevely sync the content from the directories.

    Returns:
      Result from the process that executed the gcloud command.
    """
    rsync_command = [
        'rsync',
        _filter_path(source, write=True),
        _filter_path(destination, write=True)
    ]

    if recursive:
      rsync_command.append('--recursive')
    if delete:
      rsync_command.append('--delete-unmatched-destination-objects')
    if exclusion_pattern:
      rsync_command.extend(['--exclude', exclusion_pattern])

    return self.run_gcloud_storage(
        rsync_command, timeout=timeout, verbose=False)

  def download_file(self, gcs_url, file_path, timeout=None):
    """Download a file from GCS."""
    command = ['cp', _filter_path(gcs_url), file_path]
    result = self.run_gcloud_storage(command, timeout=timeout)
    if result.return_code:
      logs.error('GCloudStorageRunner.download_file failed:\n'
                 f'Command: {result.command}\n'
                 f'Url: {gcs_url}\n'
                 f'Output {result.output}')

    return result.return_code == 0

  def upload_file(self,
                  file_path,
                  gcs_url,
                  timeout=None,
                  gzip=False,
                  metadata=None,
                  custom_metadata=None):
    """Upload a single file to a GCS url and updates its metadata if needed."""
    if not file_path or not gcs_url:
      return False

    cp_command = ['cp']
    if gzip:
      cp_command.append('--gzip-local-all')
    cp_command.extend([file_path, _filter_path(gcs_url, write=True)])

    result = self.run_gcloud_storage(cp_command, timeout=timeout)
    if result.return_code != 0:
      logs.error('GCloudStorageRunner.upload_file (cp step) failed:\n'
                 f'Command: {result.command}\n'
                 f'Filename: {file_path}\n'
                 f'Output: {result.output}')
      return False

    # For gcloud, setting metadata is a separate step after uploading.
    metadata_args = []
    if metadata:
      # Metadata dict assumes only standard headers like 'content-type'.
      metadata_args.extend([f'--{k}={v}' for k, v in metadata.items()])

    if custom_metadata:
      # Custom metadata dict is assumed to contain only custom metadata keys.
      custom_metadata_args = ','.join(
          [f'{k}={v}' for k, v in custom_metadata.items()])
      metadata_args.append(f'--update-custom-metadata={custom_metadata_args}')

    if metadata_args:
      update_command = ['objects', 'update', _filter_path(gcs_url, write=True)]
      update_command.extend(metadata_args)
      result = self.run_gcloud_storage(update_command, timeout=timeout)
      if result.return_code != 0:
        logs.error(
            'GCloudStorageRunner.upload_file (update metadata step) failed:\n'
            f'Command: {result.command}\n'
            f'Filename: {file_path}\n'
            f'Output: {result.output}')
        return False

    return True

  def upload_files_to_url(self, file_paths, gcs_url, timeout=None):
    """Upload files to the given GCS url.

    Args:
      file_paths: A sequence of file paths to upload.
      gcs_url: GCS URL to upload files to.
      timeout: Timeout for gcloud storage.

    Returns:
      Result from the process that executed the gcloud command.
    """
    if not file_paths or not gcs_url:
      return False

    command = [
        'cp', '--read-paths-from-stdin',
        _filter_path(gcs_url, write=True)
    ]
    filenames_buffer = '\n'.join(file_paths)

    result = self.run_gcloud_storage(
        command, input_data=filenames_buffer.encode('utf-8'), timeout=timeout)
    # Check result of command execution, log output if command failed.
    if result.return_code:
      logs.error('GCloudStorageRunner.upload_files_to_url failed:\n'
                 f'Command: {result.command}\n'
                 f'Filenames: {filenames_buffer}\n'
                 f'Output: {result.output}')

    return result.return_code == 0

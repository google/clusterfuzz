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
import six

from base import utils
from google_cloud_utils import storage
from metrics import logs
from system import environment
from system import new_process
from system import shell

# Default timeout for a GSUtil sync.
FILES_SYNC_TIMEOUT = 5 * 60 * 60


def _get_gsutil_path():
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
    gsutil_absolute_path = shell.which(gsutil_executable)
    if gsutil_absolute_path:
      return gsutil_absolute_path

    logs.log_error('Cannot locate gsutil in PATH, set GSUTIL_PATH to directory '
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


class GSUtilRunner(object):
  """GSUtil runner."""

  def __init__(self, _process_runner=new_process.ProcessRunner):
    default_gsutil_args = ['-m']
    default_gsutil_args.extend(_multiprocessing_args())

    self.gsutil_runner = _process_runner(
        _get_gsutil_path(), default_args=default_gsutil_args)

  def run_gsutil(self, arguments, quiet=False, **kwargs):
    """Run GSUtil."""
    if quiet:
      arguments = ['-q'] + arguments

    env = os.environ.copy()
    if 'PYTHONPATH' in env:
      # GSUtil may be on Python 3, and our PYTHONPATH breaks it because we're on
      # Python 2.
      env.pop('PYTHONPATH')

    return self.gsutil_runner.run_and_wait(arguments, env=env, **kwargs)

  def rsync(self,
            source,
            destination,
            timeout=FILES_SYNC_TIMEOUT,
            delete=True,
            exclusion_pattern=None):
    """Download corpus files from a GCS url.

    Args:
      source: Source to sync from.
      destination: Destination to sync to.
      timeout: Timeout for GSUtil.
      delete: Whether or not to delete files on disk that don't exist locally.

    Returns:
      A bool indicating whether or not the command succeeded.
    """
    # Use 'gsutil -m rsync -r' to download files from GCS bucket.
    sync_corpus_command = ['rsync', '-r']
    if delete:
      sync_corpus_command.append('-d')
    if exclusion_pattern:
      sync_corpus_command.extend(['-x', exclusion_pattern])

    sync_corpus_command.extend([
        _filter_path(source, write=True),
        _filter_path(destination, write=True),
    ])

    return self.run_gsutil(sync_corpus_command, timeout=timeout, quiet=True)

  def download_file(self, gcs_url, file_path, timeout=None):
    """Download a file from GCS."""
    command = ['cp', _filter_path(gcs_url), file_path]
    result = self.run_gsutil(command, timeout=timeout)
    if result.return_code:
      logs.log_error('GSUtilRunner.download_file failed:\nCommand: %s\n'
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

    command = []
    if metadata:
      for key, value in six.iteritems(metadata):
        command.extend(['-h', key + ':' + value])

    command.append('cp')
    if gzip:
      command.append('-Z')

    command.extend([file_path, _filter_path(gcs_url, write=True)])
    result = self.run_gsutil(command, timeout=timeout)

    # Check result of command execution, log output if command failed.
    if result.return_code:
      logs.log_error('GSUtilRunner.upload_file failed:\nCommand: %s\n'
                     'Filename: %s\n'
                     'Output: %s' % (result.command, file_path, result.output))

    return result.return_code == 0

  def upload_files_to_url(self, file_paths, gcs_url, timeout=None):
    """Upload files to the given GCS url.

    Args:
      file_paths: A sequence of file paths to upload.
      gcs_url: GCS URL to upload files to.
      timeout: Timeout for gsutil.

    Returns:
      A bool indicating whether or not the command succeeded.
    """
    if not file_paths or not gcs_url:
      return False

    # Use 'gsutil -m cp -I' to upload given files.
    sync_corpus_command = ['cp', '-I', _filter_path(gcs_url, write=True)]
    filenames_buffer = '\n'.join(file_paths)

    result = self.run_gsutil(
        sync_corpus_command,
        input_data=filenames_buffer.encode('utf-8'),
        timeout=timeout)

    # Check result of command execution, log output if command failed.
    if result.return_code:
      logs.log_error(
          'GSUtilRunner.upload_files_to_url failed:\nCommand: %s\n'
          'Filenames:%s\n'
          'Output: %s' % (result.command, filenames_buffer, result.output))

    return result.return_code == 0

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
from clusterfuzz._internal.system import environment, new_process

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
    gsutil_absolute_path = shutil.which(gsutil_executable)
    if gsutil_absolute_path:
      return gsutil_absolute_path

    logs.error('Cannot locate gsutil in PATH, set GSUTIL_PATH to directory '
               'containing gsutil binary.')
    return None

  gsutil_absolute_path = os.path.join(gsutil_directory, gsutil_executable)
  return gsutil_absolute_path


def _get_gcloud_path():
  """Get path to gcloud executable."""
  gcloud_executable = 'gcloud'
  if environment.platform() == 'WINDOWS':
    gcloud_executable += '.cmd'

  gcloud_directory = environment.get_value('GCLOUD_PATH')
  if not gcloud_directory:
    gcloud_absolute_path = shutil.which(gcloud_executable)
    if gcloud_absolute_path:
      return gcloud_absolute_path

    logs.error('Cannot locate gcloud in PATH, set GCLOUD_PATH to directory '
               'containing gcloud binary.')
    return None

  return os.path.join(gcloud_directory, gcloud_executable)


def _multiprocessing_args():
  """Get multiprocessing args for gsutil."""
  if utils.cpu_count() == 1:
    # GSUtil's default thread count is 5 as it assumes the common configuration
    # is many CPUs (GSUtil uses num_cpu processes).
    return ['-o', 'GSUtil:parallel_thread_count=16']

  return []


def _use_gcloud_storage():
  """Returns whether to use gcloud storage instead of gsutil."""
  return environment.get_value('USE_GCLOUD_STORAGE') == 'true'


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


# TODO: b/436307629 - Migrate gsutil commands to gcloud.
class GSUtilRunner:
  """GSUtil runner."""

  def __init__(self, process_runner=new_process.ProcessRunner):
    default_gsutil_args = ['-m']
    default_gsutil_args.extend(_multiprocessing_args())

    self.gsutil_runner = process_runner(
        _get_gsutil_path(), default_args=default_gsutil_args)
    self.gcloud_runner = process_runner(_get_gcloud_path())

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

  def run_gcloud(self, arguments, quiet=False, **kwargs):
    """Run gcloud."""
    if quiet:
      arguments = ['--quiet'] + arguments

    env = os.environ.copy()
    if 'PYTHONPATH' in env:
      env.pop('PYTHONPATH')

    return self.gcloud_runner.run_and_wait(arguments, env=env, **kwargs)

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
    # Use 'gcloud storage rsync' to download files from GCS bucket.
    sync_corpus_command = ['storage', 'rsync', '--recursive']
    if delete:
      sync_corpus_command.append('--delete-unmatched-destination-objects')
    if exclusion_pattern:
      sync_corpus_command.extend(['--exclude', exclusion_pattern])

    sync_corpus_command.extend([
        _filter_path(source, write=True),
        _filter_path(destination, write=True),
    ])

    return self.run_gcloud(sync_corpus_command, timeout=timeout, quiet=True)

  def _download_file_gsutil(self, gcs_url, file_path, timeout=None):
    """Download a file from GCS using gsutil."""
    command = ['cp', _filter_path(gcs_url), file_path]
    result = self.run_gsutil(command, timeout=timeout)
    if result.return_code:
      logs.error('GSUtilRunner.download_file (gsutil) failed:\nCommand: %s\n'
                 'Url: %s\n'
                 'Output %s' % (result.command, gcs_url, result.output))
    return result.return_code == 0

  def _download_file_gcloud(self, gcs_url, file_path, timeout=None):
    """Download a file from GCS using gcloud."""
    command = ['storage', 'cp', _filter_path(gcs_url), file_path]
    result = self.run_gcloud(command, timeout=timeout)
    if result.return_code:
      logs.error('GSUtilRunner.download_file (gcloud) failed:\nCommand: %s\n'
                 'Url: %s\n'
                 'Output %s' % (result.command, gcs_url, result.output))
    return result.return_code == 0

  def download_file(self, gcs_url, file_path, timeout=None):
    """Download a file from GCS."""
    if _use_gcloud_storage():
      return self._download_file_gcloud(gcs_url, file_path, timeout)
    return self._download_file_gsutil(gcs_url, file_path, timeout)

  def _upload_file_gsutil(self,
                          file_path,
                          gcs_url,
                          timeout=None,
                          gzip=False,
                          metadata=None):
    """Upload a single file to a given GCS url using gsutil."""
    if not file_path or not gcs_url:
      return False

    command = []
    if metadata:
      for key, value in metadata.items():
        command.extend(['-h', key + ':' + value])

    command.append('cp')
    if gzip:
      command.append('-Z')

    command.extend([file_path, _filter_path(gcs_url, write=True)])
    result = self.run_gsutil(command, timeout=timeout)

    if result.return_code:
      logs.error('GSUtilRunner.upload_file (gsutil) failed:\nCommand: %s\n'
                 'Filename: %s\n'
                 'Output: %s' % (result.command, file_path, result.output))

    return result.return_code == 0

  def _upload_file_gcloud(self,
                          file_path,
                          gcs_url,
                          timeout=None,
                          gzip=False,
                          metadata=None):
    """Upload a single file to a given GCS url using gcloud."""
    if not file_path or not gcs_url:
      return False

    dest_gcs_url = _filter_path(gcs_url, write=True)
    command = ['storage', 'cp']
    if gzip:
      command.append('--gzip-local-all')

    command.extend([file_path, dest_gcs_url])
    result = self.run_gcloud(command, timeout=timeout)

    if result.return_code:
      logs.error('GSUtilRunner.upload_file (gcloud upload) failed:\n'
                 'Command: %s\nFilename: %s\nOutput: %s' %
                 (result.command, file_path, result.output))
      return False

    if not metadata:
      return True

    command = ['storage', 'objects', 'update']
    update_metadata_args = []
    remove_metadata_args = []
    custom_metadata_args = []

    for key, value in metadata.items():
      key_lower = key.lower()
      if key_lower == 'cache-control':
        update_metadata_args.extend(['--cache-control', value])
      elif key_lower == 'content-disposition':
        update_metadata_args.extend(['--content-disposition', value])
      elif key_lower == 'content-encoding':
        update_metadata_args.extend(['--content-encoding', value])
      elif key_lower == 'content-language':
        update_metadata_args.extend(['--content-language', value])
      elif key_lower == 'content-type':
        update_metadata_args.extend(['--content-type', value])
      elif key_lower.startswith('x-goog-meta-'):
        custom_metadata_key = key_lower[len('x-goog-meta-'):]
        if value is None:
          remove_metadata_args.append(custom_metadata_key)
        else:
          custom_metadata_args.append(f'{custom_metadata_key}={value}')

    if update_metadata_args:
      command.extend(update_metadata_args)
    if remove_metadata_args:
      command.append('--remove-custom-metadata')
      command.append(','.join(remove_metadata_args))
    if custom_metadata_args:
      command.append('--update-custom-metadata')
      command.append(','.join(custom_metadata_args))

    if len(command) == 3:  # No metadata args were added.
      return True

    command.append(dest_gcs_url)
    result = self.run_gcloud(command, timeout=timeout)

    if result.return_code:
      logs.error('GSUtilRunner.upload_file (gcloud metadata) failed:\n'
                 'Command: %s\nFilename: %s\nOutput: %s' %
                 (result.command, file_path, result.output))
      return False

    return True

  def upload_file(self,
                  file_path,
                  gcs_url,
                  timeout=None,
                  gzip=False,
                  metadata=None):
    """Upload a single file to a given GCS url."""
    if _use_gcloud_storage():
      return self._upload_file_gcloud(file_path, gcs_url, timeout, gzip,
                                      metadata)
    return self._upload_file_gsutil(file_path, gcs_url, timeout, gzip, metadata)

  def _upload_files_to_url_gsutil(self, file_paths, gcs_url, timeout=None):
    """Upload files to the given GCS url using gsutil."""
    if not file_paths or not gcs_url:
      return False

    sync_corpus_command = ['cp', '-I', _filter_path(gcs_url, write=True)]
    filenames_buffer = '\n'.join(file_paths)
    result = self.run_gsutil(
        sync_corpus_command,
        input_data=filenames_buffer.encode('utf-8'),
        timeout=timeout)

    if result.return_code:
      logs.error(
          'GSUtilRunner.upload_files_to_url (gsutil) failed:\nCommand: %s\n'
          'Filenames:%s\n'
          'Output: %s' % (result.command, filenames_buffer, result.output))

    return result.return_code == 0

  def _upload_files_to_url_gcloud(self, file_paths, gcs_url, timeout=None):
    """Upload files to the given GCS url using gcloud."""
    if not file_paths or not gcs_url:
      return False

    sync_corpus_command = [
        'storage', 'cp', '-I',
        _filter_path(gcs_url, write=True)
    ]
    filenames_buffer = '\n'.join(file_paths)
    result = self.run_gcloud(
        sync_corpus_command,
        input_data=filenames_buffer.encode('utf-8'),
        timeout=timeout)

    if result.return_code:
      logs.error(
          'GSUtilRunner.upload_files_to_url (gcloud) failed:\nCommand: %s\n'
          'Filenames:%s\n'
          'Output: %s' % (result.command, filenames_buffer, result.output))

    return result.return_code == 0

  def upload_files_to_url(self, file_paths, gcs_url, timeout=None):
    """Upload files to the given GCS url."""
    if _use_gcloud_storage():
      return self._upload_files_to_url_gcloud(file_paths, gcs_url, timeout)
    return self._upload_files_to_url_gsutil(file_paths, gcs_url, timeout)

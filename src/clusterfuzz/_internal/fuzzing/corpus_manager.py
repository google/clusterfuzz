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
"""Functions for corpus synchronization with GCS."""

import contextlib
import datetime
import io
import os
import re
import shutil
import uuid
import zipfile

from google.protobuf import timestamp

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

try:
  from clusterfuzz._internal.google_cloud_utils import gsutil

  # Disable "invalid-name" because fixing the issue will cause pylint to
  # complain the None assignment is incorrectly named.
  DEFAULT_GSUTIL_RUNNER = gsutil.GSUtilRunner  # pylint: disable=invalid-name
except:
  # This is expected to fail on App Engine.
  gsutil = None
  DEFAULT_GSUTIL_RUNNER = None

BACKUP_ARCHIVE_FORMAT = 'zip'
CORPUS_FILES_SYNC_TIMEOUT = 60 * 60
LATEST_BACKUP_TIMESTAMP = 'latest'
PUBLIC_BACKUP_TIMESTAMP = 'public'
REGRESSIONS_GCS_PATH_SUFFIX = '_regressions'

ZIPPED_PATH_PREFIX = 'zipped'
PARTIAL_ZIPCORPUS_PREFIX = 'partial'
BASE_ZIPCORPUS_PREFIX = 'base'

RSYNC_ERROR_REGEX = (br'CommandException:\s*(\d+)\s*files?/objects? '
                     br'could not be copied/removed')

MAX_SYNC_ERRORS = 10

# Default used by shutil.
COPY_BUFFER_SIZE = 16 * 1024


def _rsync_errors_below_threshold(gsutil_result, max_errors):
  """Check if the number of errors during rsync is lower than our threshold."""
  match = re.search(RSYNC_ERROR_REGEX, gsutil_result.output, re.MULTILINE)
  if not match:
    return False

  error_count = int(match.group(1))

  # Ignore NotFoundException(s) since they can happen when files can get deleted
  # e.g. when pruning task is updating corpus.
  error_count -= gsutil_result.output.count(b'NotFoundException')
  error_count -= gsutil_result.output.count(b'No such file or directory')

  return error_count <= max_errors


def _handle_rsync_result(gsutil_result, max_errors):
  """Handle rsync result."""
  if gsutil_result.return_code == 0:
    sync_succeeded = True
  else:
    logs.log_warn(
        'gsutil rsync got non-zero:\n'
        'Command: %s\n'
        'Output: %s\n' % (gsutil_result.command, gsutil_result.output))
    sync_succeeded = _rsync_errors_below_threshold(gsutil_result, max_errors)

  return sync_succeeded and not gsutil_result.timed_out


def _count_corpus_files(directory):
  """Count the number of corpus files."""
  return shell.get_directory_file_count(directory)


def backup_corpus(backup_bucket_name, corpus, directory):
  """Archive and store corpus as a backup.

  Args:
    backup_bucket_name: Backup bucket.
    corpus: The FuzzTargetCorpus.
    directory: Path to directory to be archived and backuped.

  Returns:
    The backup GCS url, or None on failure.
  """
  if not backup_bucket_name:
    logs.log('No backup bucket provided, skipping corpus backup.')
    return None

  dated_backup_url = None
  timestamp = str(utils.utcnow().date())

  # The archive path for shutil.make_archive should be without an extension.
  backup_archive_path = os.path.join(
      os.path.dirname(os.path.normpath(directory)), timestamp)
  try:
    backup_archive_path = shutil.make_archive(backup_archive_path,
                                              BACKUP_ARCHIVE_FORMAT, directory)
    dated_backup_url = gcs_url_for_backup_file(
        backup_bucket_name, corpus.engine, corpus.project_qualified_target_name,
        timestamp)

    if not storage.copy_file_to(backup_archive_path, dated_backup_url):
      return None

    latest_backup_url = gcs_url_for_backup_file(
        backup_bucket_name, corpus.engine, corpus.project_qualified_target_name,
        LATEST_BACKUP_TIMESTAMP)

    if not storage.copy_blob(dated_backup_url, latest_backup_url):
      logs.log_error(
          'Failed to update latest corpus backup at "%s"' % latest_backup_url)
  except Exception as ex:
    logs.log_error(
        'backup_corpus failed: %s\n' % str(ex),
        backup_bucket_name=backup_bucket_name,
        directory=directory,
        backup_archive_path=backup_archive_path)

  finally:
    # Remove backup archive.
    shell.remove_file(backup_archive_path)

  return dated_backup_url


def gcs_url_for_backup_directory(backup_bucket_name, fuzzer_name,
                                 project_qualified_target_name):
  """Build GCS URL for corpus backup directory.

  Returns:
    A string giving the GCS URL.
  """
  return (f'gs://{backup_bucket_name}/corpus/{fuzzer_name}/'
          f'{project_qualified_target_name}/')


def gcs_url_for_backup_file(backup_bucket_name, fuzzer_name,
                            project_qualified_target_name, date):
  """Build GCS URL for corpus backup file for the given date.

  Returns:
    A string giving the GCS url.
  """
  backup_dir = gcs_url_for_backup_directory(backup_bucket_name, fuzzer_name,
                                            project_qualified_target_name)
  backup_file = str(date) + os.extsep + BACKUP_ARCHIVE_FORMAT
  return f'{backup_dir.rstrip("/")}/{backup_file}'


def legalize_filenames(file_paths):
  """Convert the name of every file in |file_paths| a name that is legal on
  Windows. Returns list of legally named files."""
  if environment.is_trusted_host():
    return file_paths

  illegal_chars = {'<', '>', ':', '\\', '|', '?', '*'}
  failed_to_move_files = []
  legally_named = []
  for file_path in file_paths:
    file_dir_path, basename = os.path.split(file_path)
    if not any(char in illegal_chars for char in basename):
      legally_named.append(file_path)
      continue

    # Hash file to get new name since it also lets us get rid of duplicates,
    # will not cause collisions for different files and makes things more
    # consistent (since libFuzzer uses hashes).
    sha1sum = utils.file_hash(file_path)
    new_file_path = os.path.join(file_dir_path, sha1sum)
    try:
      shutil.move(file_path, new_file_path)
      legally_named.append(new_file_path)
    except OSError:
      failed_to_move_files.append((file_path, new_file_path))
  if failed_to_move_files:
    logs.log_error(
        'Failed to rename files.', failed_to_move_files=failed_to_move_files)

  return legally_named


def legalize_corpus_files(directory):
  """Convert the name of every corpus file in |directory| to a name that is
  allowed on Windows."""
  # Iterate through return value of legalize_filenames to convert every
  # filename.
  files_list = shell.get_files_list(directory)
  legalize_filenames(files_list)


class GcsCorpus:
  """Google Cloud Storage corpus."""

  def __init__(self,
               bucket_name,
               bucket_path='/',
               gsutil_runner_func=DEFAULT_GSUTIL_RUNNER):
    """Inits the GcsCorpus.

    Args:
      bucket_name: Name of the bucket for corpus synchronization.
      bucket_path: Path in the bucket where the corpus is stored.
    """
    self._bucket_name = bucket_name
    self._bucket_path = bucket_path
    self._gsutil_runner = gsutil_runner_func()

  @property
  def bucket_name(self):
    return self._bucket_name

  @property
  def bucket_path(self):
    return self._bucket_path

  def get_zipcorpus_gcs_dir_url(self):
    """Build zipcorpus GCS URL for gsutil.
    Returns:
      A string giving the GCS URL.
    """
    url = storage.get_cloud_storage_file_path(
        self.bucket_name, f'{ZIPPED_PATH_PREFIX}{self.bucket_path}')
    if not url.endswith('/'):
      # Ensure that the bucket path is '/' terminated. Without this, when a
      # single file is being uploaded, it is renamed to the trailing non-/
      # terminated directory name instead.
      url += '/'
    return url

  def rsync_from_disk(self,
                      directory,
                      timeout=CORPUS_FILES_SYNC_TIMEOUT,
                      delete=True):
    """Upload local files to GCS and remove files which do not exist locally.

    Args:
      directory: Path to directory to sync from.
      timeout: Timeout for gsutil.
      delete: Whether or not to delete files on GCS that don't exist locally.

    Returns:
      A bool indicating whether or not the command succeeded.
    """
    corpus_gcs_url = _get_gcs_url(self.bucket_name, self.bucket_path)
    legalize_corpus_files(directory)
    result = self._gsutil_runner.rsync(
        directory, corpus_gcs_url, timeout, delete=delete)

    # Upload zipcorpus.
    # TODO(metzman): Get rid of the rest of this function when migration is
    # complete.
    filenames = shell.get_files_list(directory)
    self._upload_to_zipcorpus(filenames, partial=False)

    # Allow a small number of files to fail to be synced.
    return _handle_rsync_result(result, max_errors=MAX_SYNC_ERRORS)

  def get_zipcorpora_gcs_urls(self, max_partial_corpora=float('inf')):
    """Generates a sequence of GCS paths containing the base corpus and at most
    |max_partial_corpora| (all of them by default) of the most recent partial
    corpora. Note that this function can return a non-existent base zipcorpus,
    so callers must ensure the zipcorpus exists before copying it."""
    yield self.get_zipcorpus_gcs_url(partial=False)
    partial_corpora_gcs_url = (
        f'{self.get_zipcorpus_gcs_dir_url()}/{PARTIAL_ZIPCORPUS_PREFIX}*')
    partial_corpora = reversed(
        list(storage.list_blobs(partial_corpora_gcs_url)))
    for idx, partial_corpus in enumerate(partial_corpora):
      if idx > max_partial_corpora:
        break
      yield partial_corpus

  def download_zipcorpora(self, dst_dir):
    """Downloads zipcorpora, unzips their contents, and stores them in
    |dst_dir|"""
    for zipcorpus_url in self.get_zipcorpora_gcs_urls():
      # TODO(metzman): Find out what's the tradeoff between writing the file to
      # disk first or unpacking it in-memory.
      with get_temp_zip_filename() as temp_zip_filename:
        if not storage.exists(zipcorpus_url):
          # This is expected to happen in two scenarios:
          # 1. When a fuzzer is new, get_zipcorpora_gcs_urls() will always
          # return the base zipcorpus even if it doesn't exist.
          # 2. When this function is executed concurrently with a corpus prune,
          # the intermediate corpus may be deleted.
          if zipcorpus_url.endswith(f'{BASE_ZIPCORPUS_PREFIX}.zip'):
            logs.log_warn(f'Base zipcorpus {zipcorpus_url} does not exist.')
          else:
            logs.log_error(
                f'Zipcorpus {zipcorpus_url} was expected to exist but does not.'
            )
          continue
        if not storage.copy_file_from(zipcorpus_url, temp_zip_filename):
          continue
        archive.unpack(temp_zip_filename, dst_dir)

  def rsync_to_disk(self,
                    directory,
                    timeout=CORPUS_FILES_SYNC_TIMEOUT,
                    delete=True):
    """Run gsutil to download corpus files from GCS.

    Args:
      directory: Path to directory to sync to.
      timeout: Timeout for gsutil.
      delete: Whether or not to delete files on disk that don't exist locally.

    Returns:
      A bool indicating whether or not the command succeeded.
    """
    shell.create_directory(directory, create_intermediates=True)

    corpus_gcs_url = _get_gcs_url(self.bucket_name, self.bucket_path)
    result = self._gsutil_runner.rsync(corpus_gcs_url, directory, timeout,
                                       delete)

    # TODO(metzman): Download zipcorpora.

    # Allow a small number of files to fail to be synced.
    return _handle_rsync_result(result, max_errors=MAX_SYNC_ERRORS)

  def upload_files(self, file_paths, timeout=CORPUS_FILES_SYNC_TIMEOUT):
    """Upload files to the GCS.

    Args:
      file_paths: A sequence of file paths to upload.

    Returns:
      A bool indicating whether or not the command succeeded.
    """
    # TODO(metzman): Merge this with rsync from disk when migration is complete.
    if not file_paths:
      return True

    # Get a new file_paths iterator where all files have been renamed to be
    # legal on Windows.
    file_paths = legalize_filenames(file_paths)
    gcs_url = _get_gcs_url(self.bucket_name, self.bucket_path)
    result = self._gsutil_runner.upload_files_to_url(
        file_paths, gcs_url, timeout=timeout)

    # Upload zipcorpus.
    # TODO(metzman): Get rid of the rest of this function when migration is
    # complete.
    self._upload_to_zipcorpus(file_paths, partial=True)
    return result


class FuzzTargetCorpus(GcsCorpus):
  """Engine fuzzer (libFuzzer, AFL) specific corpus."""
  def rsync_from_disk(self,
                      directory,
                      timeout=CORPUS_FILES_SYNC_TIMEOUT,
                      delete=True):
    """Upload local files to GCS and remove files which do not exist locally.

    Overridden to have additional logging.

    Args:
      directory: Path to directory to sync to.
      timeout: Timeout for gsutil.
      delete: Whether or not to delete files on GCS that don't exist locally.

    Returns:
      A bool indicating whether or not the command succeeded.
    """
    result = super().rsync_from_disk(directory, timeout=timeout, delete=delete)

    num_files = _count_corpus_files(directory)
    logs.log('%d corpus files uploaded for %s.' %
             (num_files, self._project_qualified_target_name))

    return result

def _get_regressions_corpus_gcs_url(bucket_name, bucket_path):
  """Return gcs path to directory containing crash regressions."""
  return _get_gcs_url(self.bucket_name,
                      self.bucket_path,
                      suffix=REGRESSIONS_GCS_PATH_SUFFIX)


def download_corpus(corpus, directory):
  storage.download_signed_urls(corpus.download_urls, directory)
  storage.download_signed_urls(corpus.regression_download_urls, directory)


class HoldAsNeededFile(io.RawIOBase):
  """In-memory file object that when read (using destructive_read) discards
  previously written data."""

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self._buf_list = []

  def write(self, data):
    """Normal behaving write method."""
    self._buf_list.append(data)
    return len(data)

  def destructive_read(self):
    """Returns all the data we have and discards it."""
    old_buf = b''.join(self._buf_list)
    self._buf_list = []
    return old_buf

def get_temp_zip_filename():
  return shell.get_tempfile(suffix='.zip')


def _get_gcs_url(self, bucket_name, bucket_path, suffix=''):
  """Build corpus GCS URL for gsutil.
    Returns:
      A string giving the GCS URL.
  """
  url = f'gs://{bucket_name}{bucket_path}{suffix}'
  if not url.endswith('/'):
    # Ensure that the bucket path is '/' terminated. Without this, when a
    # single file is being uploaded, it is renamed to the trailing non-/
    # terminated directory name instead.
    url += '/'

  return url


def get_proto_corpus(bucket_name, bucket_path):
  gcs_url = _get_gcs_url(bucket_name, bucket_path)
  corpus_urls = {}
  # TODO(metzman): Allow this step to be skipped by trusted fuzzers.
  for corpus_element_url in storage.list_blobs(gcs_url):
    # Save a mapping from the download url to the deletion url. That way when we
    # want to delete, a file, we can find the deletion URL.
    # TODO(metzman): Make this configurable/optional to save time fuzzing where
    # it isn't needed (time will probably never exceed 10 seconds).
    corpus_urls[get_signed_download_url(corpus_element_url)] = (
        get_signed_delete_url(corpus_element_url))

  upload_urls = get_arbitrary_signed_upload_urls(
        remote_directory, max_uploads)
  last_updated = storage.last_updated(get_gcs_url(bucket_name, bucket_path))
  corpus = uworker_msg_pb2.Corpus(
        download_urls=download_urls,
        delete_urls=delete_urls,
        upload_urls=upload_urls,
        gcs_url=gcs_url,
    )
  if last_updated:
    timestamp = timestamp_pb2.Timestamp()
    corpus.last_updated = timestamp.FromDatetime(timestamp)

  return corpus


def get_fuzz_target_corpus(engine, project_qualified_target_name, quarantine=False, include_regressions=False):
  _engine = os.getenv('CORPUS_FUZZER_NAME_OVERRIDE', engine)
  if quarantine:
    sync_corpus_bucket_name = environment.get_value('QUARANTINE_BUCKET')
  else:
    sync_corpus_bucket_name = environment.get_value('CORPUS_BUCKET')

  if not sync_corpus_bucket_name:
      raise RuntimeError('No corpus bucket specified.')

  fuzz_target_corpus = uworker_msg.FuzzTargetCorpus()
  corpus = get_proto_corpus(bucket_name, bucket_path)
  fuzz_target_corpus.corpus = corpus

  if include_regressions:
    fuzz_target_corpus.regression_corpus = get_proto_corpus(sync_corpus_bucket_name, '/')


def _sync_corpus_to_disk(corpus, directory, timeout):



def sync_corpus_to_disk(fuzz_target_corpus, directory, timeout=SYNC_TIMEOUT, delete=True) -> bool:
  if not _sync_corpus_to_disk(
      fuzz_target_corpus.corpus, directory, timeout=timeout, delete=delete)

  if fuzz_target_corpus.HasField('regressions_corpus'):
    regressions_dir = os.path.join(directory, 'regressions')
    self._regressions_corpus.rsync_to_disk(
        regressions_dir, timeout=timeout, delete=False)

  num_files = _count_corpus_files(directory)
  logs.log(f'{num_files} corpus files downloaded for '
           '{self._project_qualified_target_name}.')
  return True

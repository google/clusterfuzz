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
import multiprocessing.pool
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


def _get_regressions_corpus_gcs_url(bucket_name, bucket_path):
  """Return gcs path to directory containing crash regressions."""
  return _get_gcs_url(self.bucket_name,
                      self.bucket_path,
                      suffix=REGRESSIONS_GCS_PATH_SUFFIX)


def download_corpus(corpus, directory):
  storage.download_signed_urls(corpus.download_urls, directory)
  storage.download_signed_urls(corpus.regression_download_urls, directory)


def _get_gcs_url(bucket_name, bucket_path, suffix=''):
  """Build corpus GCS URL for gsutil.
  Returns:
    A string giving the GCS URL.
  """
  # TODO(metzman): Delete this after we are done migrating to the zipcorpus
  # format.
  url = f'gs://{bucket_name}{bucket_path}{suffix}'
  if not urlf.endswith('/'):
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


def get_target_bucket_and_path(engine, project_qualified_target_name, quarantine=False):
  engine = os.getenv('CORPUS_FUZZER_NAME_OVERRIDE', engine)
  if quarantine:
    sync_corpus_bucket_name = environment.get_value('QUARANTINE_BUCKET')
  else:
    sync_corpus_bucket_name = environment.get_value('CORPUS_BUCKET')
  if not sync_corpus_bucket_name:
    raise RuntimeError('No corpus bucket specified.')
  return sync_corpus_bucket_name, f'/{engine}/{project_qualified_target_name}'


def get_fuzz_target_corpus(engine, project_qualified_target_name, quarantine=False, include_regressions=False):
  fuzz_target_corpus = uworker_msg.FuzzTargetCorpus()
  bucket_name, bucket_path = get_target_bucket_and_path(
      engine, project_qualified_target_name, quarantine)
  corpus = get_proto_corpus(sync_corpus_bucket_name, bucket_path)
  fuzz_target_corpus.corpus = corpus

  if include_regressions:
    regressions_bucket_path = f'{bucket_path}{REGRESSIONS_GCS_PATH_SUFFIX}'
    fuzz_target_corpus.regression_corpus = get_proto_corpus(
        bucket_name, regressions_bucket_path)
  return fuzz_target_corpus


def get_regressions_signed_upload_url(engine, project_qualified_target_name):
  bucket, path = get_target_bucket_and_path(
      engine, project_qualified_target_name)
  regression_url = _get_regressions_corpus_gcs_url(bucket, path)
  return get_arbitrary_signed_upload_url(regression_url)


def _sync_corpus_to_disk(corpus, directory, timeout):
  shell.create_directory(directory, create_intermediates=True)
  args = ((url, directory) for url in corpus.corpus_urls)
  result = storage.download_signed_urls(corpus.corpus_urls, directory)
  # TODO(metzman): Add timeout and tolerance for missing URLs.
  return result.count(False) < MAX_SYNC_ERRORS


def fuzz_target_corpus_sync_to_disk(fuzz_target_corpus, directory, timeout=SYNC_TIMEOUT) -> bool:
  if not _sync_corpus_to_disk(
      fuzz_target_corpus.corpus, directory, timeout=timeout, delete=delete):
    return False

  if fuzz_target_corpus.HasField('regressions_corpus'):
    regressions_dir = os.path.join(directory, 'regressions')
    self._regressions_corpus.rsync_to_disk(
        regressions_dir, timeout=timeout, delete=False)

  num_files = _count_corpus_files(directory)
  logs.log(f'{num_files} corpus files downloaded.')
  return True


def proto_upload_files(corpus, filepaths):
  results = storage.upload_signed_urls(corpus.upload_urls, filepaths)
  # Make sure we don't reuse upload_urls.
  corpus.upload_urls = corpus.upload_urls[:len(results)]
  return results


def fuzz_target_corpus_sync_from_disk(fuzz_target_corpus, directory) -> bool:
  files_to_delete = corpus.filenames_to_delete_urls_mapping.copy()
  files_to_upload = []
  for filepath in filepaths:
    files_to_upload.append(filepath)
    if filepath in files_to_delete:
      del files_to_delete[filepath]
  results = _corpus_upload_files(corpus, files_to_upload)
  storage.delete_signed_urls(files_to_delete.values())
  logs.log(f'{result.count(True)} corpus files uploaded.')
  return result.count(False) < MAX_SYNC_ERRORS

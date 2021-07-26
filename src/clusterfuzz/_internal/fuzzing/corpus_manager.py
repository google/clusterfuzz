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

import os
import re
import shutil

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
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

RSYNC_ERROR_REGEX = (br'CommandException:\s*(\d+)\s*files?/objects? '
                     br'could not be copied/removed')

MAX_SYNC_ERRORS = 10


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
  return 'gs://%s/corpus/%s/%s/' % (backup_bucket_name, fuzzer_name,
                                    project_qualified_target_name)


def gcs_url_for_backup_file(backup_bucket_name, fuzzer_name,
                            project_qualified_target_name, date):
  """Build GCS URL for corpus backup file for the given date.

  Returns:
    A string giving the GCS url.
  """
  backup_dir = gcs_url_for_backup_directory(backup_bucket_name, fuzzer_name,
                                            project_qualified_target_name)
  backup_file = str(date) + os.extsep + BACKUP_ARCHIVE_FORMAT
  return '%s/%s' % (backup_dir.rstrip('/'), backup_file)


def legalize_filenames(file_paths):
  """Convert the name of every file in |file_paths| a name that is legal on
  Windows. Returns list of legally named files."""
  # TODO(metzman): Support legalizing filenames when called on trusted host, but
  # file paths exist on untrusted workers. This is fine for now since Linux is
  # the only supported platform on OSS-Fuzz and this functionality is not needed
  # in OSS-Fuzz.
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


class GcsCorpus(object):
  """Google Cloud Storage corpus."""

  def __init__(self,
               bucket_name,
               bucket_path='/',
               log_results=True,
               _gsutil_runner=DEFAULT_GSUTIL_RUNNER):
    """Inits the GcsCorpus.

    Args:
      bucket_name: Name of the bucket for corpus synchronization.
      bucket_path: Path in the bucket where the corpus is stored.
    """
    self._bucket_name = bucket_name
    self._bucket_path = bucket_path
    self._log_results = log_results
    self._gsutil_runner = _gsutil_runner()

  @property
  def bucket_name(self):
    return self._bucket_name

  @property
  def bucket_path(self):
    return self._bucket_path

  def get_gcs_url(self, suffix=''):
    """Build corpus GCS URL for gsutil.
    Returns:
      A string giving the GCS URL.
    """
    url = 'gs://%s' % self.bucket_name + self.bucket_path + suffix
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
    corpus_gcs_url = self.get_gcs_url()
    legalize_corpus_files(directory)
    result = self._gsutil_runner.rsync(directory, corpus_gcs_url, timeout,
                                       delete)

    # Allow a small number of files to fail to be synced.
    return _handle_rsync_result(result, max_errors=MAX_SYNC_ERRORS)

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

    corpus_gcs_url = self.get_gcs_url()
    result = self._gsutil_runner.rsync(corpus_gcs_url, directory, timeout,
                                       delete)

    # Allow a small number of files to fail to be synced.
    return _handle_rsync_result(result, max_errors=MAX_SYNC_ERRORS)

  def upload_files(self, file_paths, timeout=CORPUS_FILES_SYNC_TIMEOUT):
    """Upload files to the GCS.

    Args:
      file_paths: A sequence of file paths to upload.

    Returns:
      A bool indicating whether or not the command succeeded.
    """
    if not file_paths:
      return True

    # Get a new file_paths iterator where all files have been renamed to be
    # legal on Windows.
    file_paths = legalize_filenames(file_paths)
    gcs_url = self.get_gcs_url()
    return self._gsutil_runner.upload_files_to_url(
        file_paths, gcs_url, timeout=timeout)


class FuzzTargetCorpus(GcsCorpus):
  """Engine fuzzer (libFuzzer, AFL) specific corpus."""

  def __init__(self,
               engine,
               project_qualified_target_name,
               quarantine=False,
               log_results=True,
               include_regressions=False,
               _gsutil_runner=DEFAULT_GSUTIL_RUNNER):
    """Inits the FuzzTargetCorpus.

    Args:
      engine: The engine name. e.g. "libFuzzer".
      project_qualified_target_name: The project qualified fuzzer name. e.g.
          "libxml2_xml_read_memory_fuzzer".
      quarantine: A bool indicating whether or not this is the quarantine
          corpus.

    Raises:
      RuntimeError: If the required environment variables are not set.
    """

    # This is used to let AFL share corpora with libFuzzer.
    self._engine = os.getenv('CORPUS_FUZZER_NAME_OVERRIDE', engine)
    self._project_qualified_target_name = project_qualified_target_name

    if quarantine:
      sync_corpus_bucket_name = environment.get_value('QUARANTINE_BUCKET')
    else:
      sync_corpus_bucket_name = environment.get_value('CORPUS_BUCKET')

    if not sync_corpus_bucket_name:
      raise RuntimeError('No corpus bucket specified.')

    GcsCorpus.__init__(
        self,
        sync_corpus_bucket_name,
        '/%s/%s' % (self._engine, self._project_qualified_target_name),
        log_results=log_results,
        _gsutil_runner=_gsutil_runner,
    )

    self._regressions_corpus = GcsCorpus(
        sync_corpus_bucket_name,
        '/%s/%s%s' % (self._engine, self._project_qualified_target_name,
                      REGRESSIONS_GCS_PATH_SUFFIX),
        log_results=log_results,
        _gsutil_runner=_gsutil_runner) if include_regressions else None

  @property
  def engine(self):
    return self._engine

  @property
  def project_qualified_target_name(self):
    return self._project_qualified_target_name

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
    result = GcsCorpus.rsync_from_disk(
        self, directory, timeout=timeout, delete=delete)

    num_files = _count_corpus_files(directory)
    if self._log_results:
      logs.log('%d corpus files uploaded for %s.' %
               (num_files, self._project_qualified_target_name))

    return result

  def rsync_to_disk(self,
                    directory,
                    timeout=CORPUS_FILES_SYNC_TIMEOUT,
                    delete=True):
    """Run gsutil to download corpus files from GCS.

    Overridden to have additional logging.

    Args:
      directory: Path to directory to sync to.
      timeout: Timeout for gsutil.
      delete: Whether or not to delete files on disk that don't exist locally.

    Returns:
      A bool indicating whether or not the command succeeded.
    """
    result = GcsCorpus.rsync_to_disk(
        self, directory, timeout=timeout, delete=delete)
    if not result:
      return False

    # Checkout additional regressions corpus if set and ignore the result.
    if self._regressions_corpus:
      regressions_dir = os.path.join(directory, 'regressions')
      self._regressions_corpus.rsync_to_disk(
          regressions_dir, timeout=timeout, delete=False)

    num_files = _count_corpus_files(directory)
    if self._log_results:
      logs.log('%d corpus files downloaded for %s.' %
               (num_files, self._project_qualified_target_name))

    return result

  def get_regressions_corpus_gcs_url(self):
    """Return gcs path to directory containing crash regressions."""
    return self.get_gcs_url(suffix=REGRESSIONS_GCS_PATH_SUFFIX)

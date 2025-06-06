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

import datetime
import itertools
import os
import re
import shutil
import tempfile
from typing import Optional

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks import task_types
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
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
    logs.warning('gsutil rsync got non-zero:\n'
                 'Command: %s\n'
                 'Output: %s\n' % (gsutil_result.command, gsutil_result.output))
    sync_succeeded = _rsync_errors_below_threshold(gsutil_result, max_errors)

  return sync_succeeded and not gsutil_result.timed_out


def _count_corpus_files(directory):
  """Count the number of corpus files."""
  return shell.get_directory_file_count(directory)


def rename_file_to_sha(filepath, directory=None):
  if directory is None:
    directory = os.path.dirname(filepath)
  sha1sum = utils.file_hash(filepath)
  new_filepath = os.path.join(directory, sha1sum)
  shutil.move(filepath, new_filepath)
  return new_filepath


def legalize_filenames(filepaths):
  """Convert the name of every file in |filepaths| a name that is legal on
  Windows. Returns list of legally named files."""
  if environment.is_trusted_host():
    return filepaths

  illegal_chars = {'<', '>', ':', '\\', '|', '?', '*'}
  legally_named = []
  failed_to_move_filepaths = []
  for filepath in filepaths:
    _, basename = os.path.split(filepath)
    if not any(char in illegal_chars for char in basename):
      legally_named.append(filepath)
      continue

    try:
      # Hash file to get new name since it also lets us get rid of duplicates,
      # will not cause collisions for different files and makes things more
      # consistent (since libFuzzer uses hashes).
      new_filepath = rename_file_to_sha(filepath)
      legally_named.append(new_filepath)
    except OSError:
      failed_to_move_filepaths.append(filepath)

  if failed_to_move_filepaths:
    logs.error(
        'Failed to rename files.',
        failed_to_move_filepaths=failed_to_move_filepaths)

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

  # TODO(metzman): Consider merging this with FuzzTargetCorpus.
  def __init__(self,
               bucket_name,
               bucket_path='/',
               log_results=True,
               gsutil_runner_func=DEFAULT_GSUTIL_RUNNER):
    """Inits the GcsCorpus.

    Args:
      bucket_name: Name of the bucket for corpus synchronization.
      bucket_path: Path in the bucket where the corpus is stored.
    """
    self._bucket_name = bucket_name
    self._bucket_path = bucket_path
    self._log_results = log_results
    self._gsutil_runner = gsutil_runner_func()

  @property
  def bucket_name(self):
    return self._bucket_name

  @property
  def bucket_path(self):
    return self._bucket_path

  def get_gcs_url(self):
    """Build corpus GCS URL for gsutil.
    Returns:
      A string giving the GCS URL.
    """
    url = f'gs://{self.bucket_name}{self.bucket_path}'
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
    result = self._gsutil_runner.rsync(
        directory, corpus_gcs_url, timeout, delete=delete)

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
               gsutil_runner_func=DEFAULT_GSUTIL_RUNNER):
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
        f'/{self._engine}/{self._project_qualified_target_name}',
        log_results=log_results,
        gsutil_runner_func=gsutil_runner_func,
    )

    self._regressions_corpus = GcsCorpus(
        sync_corpus_bucket_name,
        f'/{self._engine}/{self._project_qualified_target_name}'
        f'{REGRESSIONS_GCS_PATH_SUFFIX}',
        log_results=log_results,
        gsutil_runner_func=gsutil_runner_func) if include_regressions else None

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
    result = super().rsync_from_disk(directory, timeout=timeout, delete=delete)

    num_files = _count_corpus_files(directory)
    if self._log_results:
      logs.info('%d corpus files uploaded for %s.' %
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
    result = super().rsync_to_disk(directory, timeout=timeout, delete=delete)
    if not result:
      return False

    # Checkout additional regressions corpus if set and ignore the result.
    if self._regressions_corpus:
      regressions_dir = os.path.join(directory, 'regressions')
      self._regressions_corpus.rsync_to_disk(
          regressions_dir, timeout=timeout, delete=False)

    num_files = _count_corpus_files(directory)
    if self._log_results:
      logs.info('%d corpus files downloaded for %s.' %
                (num_files, self._project_qualified_target_name))

    return result


# pylint: disable=super-init-not-called
class ProtoFuzzTargetCorpus(FuzzTargetCorpus):
  """Implementation of GCS corpus that uses protos (uworker-compatible) for fuzz
  targets."""

  def __init__(self,
               engine,
               project_qualified_target_name,
               proto_corpus,
               allow_engine_override=True):
    # TODO(metzman): Do we need project_qualified_target_name?

    # This is used to let AFL share corpora with libFuzzer.
    if allow_engine_override:
      engine = os.getenv('CORPUS_FUZZER_NAME_OVERRIDE', engine)
    self._engine = engine

    self._project_qualified_target_name = project_qualified_target_name
    self.proto_corpus = proto_corpus
    proto_corpus.engine = self._engine
    proto_corpus.project_qualified_target_name = project_qualified_target_name
    self._filenames_to_delete_urls_mapping = {}

  def serialize(self):
    return self.proto_corpus

  @classmethod
  def deserialize(cls, proto_corpus):
    return ProtoFuzzTargetCorpus(
        proto_corpus.engine,
        proto_corpus.project_qualified_target_name,
        proto_corpus,
        allow_engine_override=False)

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
    filenames_to_delete_dict = self._filenames_to_delete_urls_mapping.copy()
    filepaths_to_upload = []
    logs.info('Rsyncing corpus from disk.')
    for filepath in shell.get_files_list(directory):
      filepath = rename_file_to_sha(filepath)
      filename = os.path.basename(filepath)
      if filename in filenames_to_delete_dict:
        # Remove it from the delete list if it is still on disk, since that
        # means it's still in the corpus.
        del filenames_to_delete_dict[filename]
      else:
        # We only need to upload if it wasn't uploaded already.
        filepaths_to_upload.append(filepath)

    logs.info('Uploading corpus.')
    results = self.upload_files(filepaths_to_upload)
    logs.info('Done uploading corpus.')
    filenames_to_delete = [
        delete_url for delete_url in set(filenames_to_delete_dict.values())
        if delete_url
    ]

    # Assert that we aren't making the very bad mistake of deleting the entire
    # corpus because we messed up our determination of which files were deleted
    # by libFuzzer during merge/pruning. We have to do this hacky <500 check
    # because we have many different kinds of corpuses
    # (e.g. quarantine, regression) but this check is for the main corpus.
    assert ((len(filenames_to_delete) != len(
        self._filenames_to_delete_urls_mapping)) or
            len(filenames_to_delete) < 1_000)

    logs.info('Deleting files.')
    storage.delete_signed_urls(filenames_to_delete)
    logs.info('Done files.')
    logs.info(f'Corpus. {results.count(True)} uploaded. '
              f'{len(filenames_to_delete)} deleted. '
              f'{len(self._filenames_to_delete_urls_mapping)} originally.')
    return results.count(False) < MAX_SYNC_ERRORS

  def rsync_to_disk(self,
                    directory,
                    timeout=CORPUS_FILES_SYNC_TIMEOUT,
                    delete=True) -> bool:
    """Sync fuzz target corpus to disk."""
    if not self._sync_corpus_to_disk(self.proto_corpus.corpus, directory):
      return False

    if self.proto_corpus.HasField('regressions_corpus'):
      regressions_dir = os.path.join(directory, 'regressions')
      self._sync_corpus_to_disk(self.proto_corpus.regressions_corpus,
                                regressions_dir)

    num_files = _count_corpus_files(directory)
    logs.info(f'{num_files} corpus files downloaded.')
    return True

  def _sync_corpus_to_disk(self, corpus, directory):
    """Syncs a corpus from GCS to disk."""
    shell.create_directory(directory, create_intermediates=True)
    if corpus.backup_url:
      tmpdir = environment.get_value('BOT_TMPDIR')
      with tempfile.NamedTemporaryFile(
          dir=tmpdir, suffix='.zip') as temp_zipfile:
        try:
          storage.download_signed_url_to_file(corpus.backup_url,
                                              temp_zipfile.name)
          with archive.open(temp_zipfile.name) as reader:
            reader.extract_all(directory)
            for member in reader.list_members():
              self._filenames_to_delete_urls_mapping[member.name] = None
        except RuntimeError:
          logs.warning('Couldn\'t download corpus backup')

    results = storage.download_signed_urls(corpus.corpus_urls, directory)
    fails = 0
    # Convert this to a dict so proto's map doesn't return a default value for
    # missing keys (this hides errors).
    corpus_urls = dict(corpus.corpus_urls)
    for result in results:
      if not result.url:
        fails += 1
        continue
      sha_filename = os.path.basename(rename_file_to_sha(result.filepath))
      self._filenames_to_delete_urls_mapping[sha_filename] = (
          corpus_urls[result.url])

    # TODO(metzman): Add timeout and tolerance for missing URLs.
    return fails < MAX_SYNC_ERRORS

  def upload_files(self, file_paths, timeout=CORPUS_FILES_SYNC_TIMEOUT) -> bool:
    del timeout
    num_upload_urls = len(self.proto_corpus.corpus.upload_urls)
    if len(file_paths) > num_upload_urls:
      logs.error(f'Cannot upload {len(file_paths)} filepaths, only have '
                 f'{len(self.proto_corpus.corpus.upload_urls)} upload urls.')
      file_paths = file_paths[:num_upload_urls]

    logs.info(f'Uploading {len(file_paths)} corpus files.')
    results = storage.upload_signed_urls(self.proto_corpus.corpus.upload_urls,
                                         file_paths)

    # Make sure we don't reuse upload_urls.
    urls_remaining = self.proto_corpus.corpus.upload_urls[len(results):]
    del self.proto_corpus.corpus.upload_urls[:]
    self.proto_corpus.corpus.upload_urls.extend(urls_remaining)

    return results

  def get_gcs_url(self):
    return self.proto_corpus.corpus.gcs_url


def gcs_url_for_backup_file(backup_bucket_name, fuzzer_name,
                            project_qualified_target_name, date):
  """Build GCS URL for corpus backup file for the given date.

  Returns:
    A string giving the GCS url.
  """
  if backup_bucket_name is None:
    return None
  if fuzzer_name is None:
    return None
  if project_qualified_target_name is None:
    return None
  backup_dir = gcs_url_for_backup_directory(backup_bucket_name, fuzzer_name,
                                            project_qualified_target_name)
  backup_file = str(date) + os.extsep + BACKUP_ARCHIVE_FORMAT
  return f'{backup_dir.rstrip("/")}/{backup_file}'


def backup_corpus(dated_backup_signed_url, corpus, directory):
  """Archive and store corpus as a backup.

  Args:
    dated_backup_signed_url: Signed url to upload the backup.
    corpus: uworker_msg.FuzzTargetCorpus.
    directory: Path to directory to be archived and backuped.

  Returns:
    The backup GCS url, or None on failure.
  """
  logs.info(f'Backing up corpus {corpus} {directory}')
  if not dated_backup_signed_url:
    logs.info('No backup url provided, skipping corpus backup.')
    return False

  timestamp = str(utils.utcnow().date())

  # The archive path for shutil.make_archive should be without an extension.
  backup_archive_path = os.path.join(
      os.path.dirname(os.path.normpath(directory)), timestamp)

  backup_succeeded = True
  try:
    backup_archive_path = shutil.make_archive(backup_archive_path,
                                              BACKUP_ARCHIVE_FORMAT, directory)
    with open(backup_archive_path, 'rb') as fp:
      data = fp.read()
      if not storage.upload_signed_url(data, dated_backup_signed_url):
        return False
  except Exception as ex:
    backup_succeeded = False
    logs.error(
        f'backup_corpus failed: {ex}\n',
        directory=directory,
        backup_archive_path=backup_archive_path)

  finally:
    # Remove backup archive.
    shell.remove_file(backup_archive_path)

  return backup_succeeded


def gcs_url_for_backup_directory(
    backup_bucket_name, fuzzer_name,
    project_qualified_target_name) -> Optional[str]:
  """Build GCS URL for corpus backup directory.

  Returns:
    A string giving the GCS URL.
  """
  return (f'gs://{backup_bucket_name}/corpus/{fuzzer_name}/'
          f'{project_qualified_target_name}/')


def _get_regressions_corpus_gcs_url(bucket_name, bucket_path):
  """Return gcs path to directory containing crash regressions."""
  return _get_gcs_url(
      bucket_name, bucket_path, suffix=REGRESSIONS_GCS_PATH_SUFFIX)


def _get_gcs_url(bucket_name, bucket_path, suffix=''):
  """Build corpus GCS URL for gsutil.
  Returns:
    A string giving the GCS URL.
  """
  # TODO(metzman): Delete this after we are done migrating to the zipcorpus
  # format.
  url = f'gs://{bucket_name}{bucket_path}{suffix}'
  if not url.endswith('/'):
    # Ensure that the bucket path is '/' terminated. Without this, when a
    # single file is being uploaded, it is renamed to the trailing non-/
    # terminated directory name instead.
    url += '/'

  return url


def get_proto_data_bundle_corpus(
    data_bundle) -> uworker_msg_pb2.DataBundleCorpus:  # pylint: disable=no-member
  """Returns a data bundle corpus that can be used by uworkers or trusted
  workers to download the data bundle files using the fastest means available to
  them."""
  data_bundle_corpus = uworker_msg_pb2.DataBundleCorpus()  # pylint: disable=no-member
  data_bundle_corpus.gcs_url = data_bundle.bucket_url()
  data_bundle_corpus.data_bundle.CopyFrom(
      uworker_io.entity_to_protobuf(data_bundle))
  if task_types.task_main_runs_on_uworker():
    # Slow path for when we need an untrusted worker to run a task. Note that
    # the security of the system (only the correctness) does not depend on this
    # path being taken. If it is not taken when we need to, utask_main will
    # simply fail as it tries to do privileged operation it does not have
    # permissions for.
    logs.info('Getting signed data bundle URLs.')
    urls = (f'{data_bundle_corpus.gcs_url}/{url}'
            for url in storage.list_blobs(data_bundle_corpus.gcs_url))
    data_bundle_corpus.corpus_urls.extend([
        url_pair[0] for url_pair in storage.sign_urls_for_existing_files(
            urls, include_delete_urls=False)
    ])
  else:
    logs.info('Not getting signed data bundle URLs.')

  return data_bundle_corpus


def sync_data_bundle_corpus_to_disk(data_bundle_corpus, directory):
  if (not task_types.task_main_runs_on_uworker() and
      not environment.is_uworker()):
    # Fast path for when we don't need an untrusted worker to run a task.
    return gsutil.GSUtilRunner().rsync(
        data_bundle_corpus.gcs_url, directory, delete=False).return_code == 0
  results = storage.download_signed_urls(data_bundle_corpus.corpus_urls,
                                         directory)
  fails = [result.url for result in results if not result.url]
  return len(fails) < MAX_SYNC_ERRORS


def get_proto_corpus(bucket_name,
                     bucket_path,
                     max_upload_urls,
                     include_delete_urls=False,
                     max_download_urls=None,
                     backup_url=None):
  """Returns a proto representation of a corpus."""
  gcs_url = _get_gcs_url(bucket_name, bucket_path)
  corpus = uworker_msg_pb2.Corpus(gcs_url=gcs_url)  # pylint: disable=no-member

  backup_exists = False
  if backup_url:
    # TODO(unassigned): Use any backup, not just latest.zip. You can list the
    # directory and pick the last element in the list that isn't public.zip.
    # Also, come up with a way that we can get backup if it exists and otherwise
    # find out immediately if it doesn't instead of retrying.
    backup_exists = storage.exists(backup_url)

  if backup_exists:
    # Corpus backup can take up to 24 hours, get any corpus element before the
    # backup was made.
    corpus.backup_url = storage.get_signed_download_url(backup_url)
    backup = list(storage.get_blobs(backup_url, single_file=True))
    start_time = backup[0]['updated'] - datetime.timedelta(days=1)
    blobs = storage.get_blobs(gcs_url)
    urls = (f'{storage.GS_PREFIX}/{bucket_name}/{blob["name"]}'
            for blob in blobs
            if blob['updated'] > start_time)
  else:
    urls = (f'{storage.GS_PREFIX}/{bucket_name}/{url}'
            for url in storage.list_blobs(gcs_url))

  if max_download_urls is not None:
    urls = itertools.islice(urls, max_download_urls)

  corpus_urls = storage.sign_urls_for_existing_files(urls, include_delete_urls)
  upload_urls = storage.get_arbitrary_signed_upload_urls(
      gcs_url, num_uploads=max_upload_urls)

  # Iterate over imap_unordered results.
  for upload_url in upload_urls:
    corpus.upload_urls.append(upload_url)
  for download_url, delete_url in corpus_urls:
    corpus.corpus_urls[download_url] = delete_url

  return corpus


def get_target_bucket_and_path(engine,
                               project_qualified_target_name,
                               quarantine=False):
  """Gets target and bucket path for the corpus."""
  engine = os.getenv('CORPUS_FUZZER_NAME_OVERRIDE', engine)
  if quarantine:
    sync_corpus_bucket_name = environment.get_value('QUARANTINE_BUCKET')
  else:
    sync_corpus_bucket_name = environment.get_value('CORPUS_BUCKET')
  if not sync_corpus_bucket_name:
    raise RuntimeError('No corpus bucket specified.')
  return sync_corpus_bucket_name, f'/{engine}/{project_qualified_target_name}'


def get_fuzz_target_corpus(engine,
                           project_qualified_target_name,
                           quarantine=False,
                           include_regressions=False,
                           include_delete_urls=False,
                           max_upload_urls=10000,
                           max_download_urls=None,
                           use_backup=False):
  """Copies the corpus from gcs to disk. Can run on uworker."""
  fuzz_target_corpus = uworker_msg_pb2.FuzzTargetCorpus()  # pylint: disable=no-member
  bucket_name, bucket_path = get_target_bucket_and_path(
      engine, project_qualified_target_name, quarantine)

  if use_backup:
    backup_bucket_name = environment.get_value('BACKUP_BUCKET')
    backup_engine_name = environment.get_value('CORPUS_FUZZER_NAME_OVERRIDE',
                                               engine)
    gcs_url = gcs_url_for_backup_file(backup_bucket_name, backup_engine_name,
                                      project_qualified_target_name,
                                      LATEST_BACKUP_TIMESTAMP)
  else:
    gcs_url = None
  corpus = get_proto_corpus(
      bucket_name,
      bucket_path,
      include_delete_urls=include_delete_urls,
      max_upload_urls=max_upload_urls,
      max_download_urls=max_download_urls,
      backup_url=gcs_url)

  fuzz_target_corpus.corpus.CopyFrom(corpus)

  assert not (include_regressions and quarantine)
  if include_regressions:
    regressions_bucket_path = f'{bucket_path}{REGRESSIONS_GCS_PATH_SUFFIX}'
    regressions_corpus = get_proto_corpus(
        bucket_name,
        regressions_bucket_path,
        max_upload_urls=0,  # This is never uploaded to using this mechanism.
        include_delete_urls=False,  # This is never deleted from.
        max_download_urls=max_download_urls)
    fuzz_target_corpus.regressions_corpus.CopyFrom(regressions_corpus)

  return ProtoFuzzTargetCorpus(engine, project_qualified_target_name,
                               fuzz_target_corpus)


def get_regressions_signed_upload_url(engine, project_qualified_target_name):
  bucket, path = get_target_bucket_and_path(engine,
                                            project_qualified_target_name)
  regression_url = _get_regressions_corpus_gcs_url(bucket, path)
  return storage.get_arbitrary_signed_upload_url(regression_url)


def get_pruning_corpora_urls(engine, project_qualified_name):
  bucket_name, bucket_path = get_target_bucket_and_path(
      engine, project_qualified_name, False)
  gcs_url = _get_gcs_url(bucket_name, bucket_path)
  bucket_name, bucket_path = get_target_bucket_and_path(
      engine, project_qualified_name, True)
  quarantine_gcs_url = _get_gcs_url(bucket_name, bucket_path)
  return gcs_url, quarantine_gcs_url


def get_corpuses_for_pruning(engine, project_qualified_name):
  """Returns a fuzz target corpus and quarantine corpus for pruning."""
  # We need to include upload URLs because of corpus pollination. This is
  # unfortunate as it is probably rarely used.
  corpus = get_fuzz_target_corpus(
      engine,
      project_qualified_name,
      include_regressions=True,
      include_delete_urls=True,
      max_upload_urls=3_000,
      max_download_urls=200_000)
  # We will never need to upload more than the number of testcases in the
  # corpus to the quarantine. But add a max of 500 to avoid spending
  # too much time on crazy edge cases.
  max_upload_urls = min(len(corpus.proto_corpus.corpus.corpus_urls), 500)
  quarantine_corpus = get_fuzz_target_corpus(
      engine,
      project_qualified_name,
      quarantine=True,
      include_delete_urls=True,
      max_upload_urls=max_upload_urls,
      max_download_urls=1_000)
  return corpus, quarantine_corpus

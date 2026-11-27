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
"""Unpack task for unpacking a multi-testcase archive
from user upload."""

import json
import os
import stat

from google.cloud import ndb

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell


def _get_extracted_testcase_path(testcases_directory, member_name):
  """Returns the on-disk path of an extracted archive member, or None if it is
  not a regular file that is safely contained in |testcases_directory|.

  The archive is user-controlled, so member names can't be trusted: they may be
  absolute paths or contain '..' components (which the archive reader refuses
  to extract), or refer to symlinks or hard links pointing at files outside of
  |testcases_directory|.
  """
  real_testcases_directory = os.path.realpath(testcases_directory)
  file_path = os.path.realpath(
      os.path.join(real_testcases_directory, member_name))
  if not file_path.startswith(real_testcases_directory + os.sep):
    logs.warning(f'Skipping archive member outside of the testcases directory: '
                 f'{member_name}.')
    return None

  try:
    file_stat = os.lstat(file_path)
  except OSError:
    # Not extracted.
    return None

  # Only regular files are testcases. Skip directories and special files. Also
  # skip files with multiple links, since a hard link may point to a file
  # outside of the testcases directory.
  if not stat.S_ISREG(file_stat.st_mode):
    return None

  if file_stat.st_nlink != 1:
    logs.warning(f'Skipping archive member with multiple hard links: '
                 f'{member_name}.')
    return None

  return file_path


def execute_task(metadata_id, job_type):
  """Unpack a bundled testcase archive and create analyze jobs for each item."""
  metadata = ndb.Key(data_types.BundledArchiveMetadata, int(metadata_id)).get()
  if not metadata:
    logs.error('Invalid bundle metadata id %s.' % metadata_id)
    return

  bot_name = environment.get_value('BOT_NAME')
  upload_metadata = data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.blobstore_key ==
      metadata.blobstore_key).get()
  if not upload_metadata:
    logs.error('Invalid upload metadata key %s.' % metadata.blobstore_key)
    return

  job = data_types.Job.query(data_types.Job.name == metadata.job_type).get()
  if not job:
    logs.error('Invalid job_type %s.' % metadata.job_type)
    return

  # Update the upload metadata with this bot name.
  upload_metadata.bot_name = bot_name
  upload_metadata.put()

  # We can't use FUZZ_INPUTS directory since it is constrained
  # by tmpfs limits.
  testcases_directory = environment.get_value('FUZZ_INPUTS_DISK')

  # Retrieve multi-testcase archive.
  archive_path = os.path.join(testcases_directory, metadata.archive_filename)
  if not blobs.read_blob_to_disk(metadata.blobstore_key, archive_path):
    logs.error(f'Could not retrieve archive for bundle {metadata_id}.')
    tasks.add_task('unpack', metadata_id, job_type)
    return

  try:
    with archive.open(archive_path) as reader:
      if not reader.extract_all(testcases_directory):
        logs.warning(
            f'Some members of the archive for bundle {metadata_id} could not '
            'be extracted. Only the extracted ones will be unpacked.')
      members = reader.list_members()
  except:
    logs.error(f'Could not unpack archive for bundle {metadata_id}.')
    tasks.add_task('unpack', metadata_id, job_type)
    return

  # Get additional testcase metadata (if any).
  additional_metadata = None
  if upload_metadata.additional_metadata_string:
    additional_metadata = json.loads(upload_metadata.additional_metadata_string)

  archive_state = data_types.ArchiveStatus.NONE
  bundled = True

  for f in members:
    if f.is_dir:
      continue

    absolute_file_path = _get_extracted_testcase_path(testcases_directory,
                                                      f.name)
    if not absolute_file_path:
      continue

    filename = os.path.basename(f.name)

    try:
      with open(absolute_file_path, 'rb') as file_handle:
        blob_key = blobs.write_blob(file_handle)
    except:
      blob_key = None

    if not blob_key:
      logs.error(
          'Could not write testcase %s to blobstore.' % absolute_file_path)
      continue

    data_handler.create_user_uploaded_testcase(
        blob_key,
        metadata.blobstore_key,
        archive_state,
        metadata.archive_filename,
        filename,
        metadata.timeout,
        job,
        metadata.job_queue,
        metadata.http_flag,
        metadata.gestures,
        metadata.additional_arguments,
        metadata.bug_information,
        metadata.crash_revision,
        metadata.uploader_email,
        metadata.platform_id,
        metadata.app_launch_command,
        metadata.fuzzer_name,
        metadata.overridden_fuzzer_name,
        metadata.fuzzer_binary_name,
        bundled,
        upload_metadata.retries,
        upload_metadata.bug_summary_update_flag,
        upload_metadata.quiet_flag,
        additional_metadata,
        trusted=bool(metadata.trusted))

  # The upload metadata for the archive is not needed anymore since we created
  # one for each testcase.
  upload_metadata.key.delete()

  shell.clear_testcase_directories()

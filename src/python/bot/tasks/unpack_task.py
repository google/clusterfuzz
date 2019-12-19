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

from google.cloud import ndb

from base import tasks
from datastore import data_handler
from datastore import data_types
from google_cloud_utils import blobs
from metrics import logs
from system import archive
from system import environment
from system import shell


def execute_task(metadata_id, job_type):
  """Unpack a bundled testcase archive and create analyze jobs for each item."""
  metadata = ndb.Key(data_types.BundledArchiveMetadata, int(metadata_id)).get()
  if not metadata:
    logs.log_error('Invalid bundle metadata id %s.' % metadata_id)
    return

  bot_name = environment.get_value('BOT_NAME')
  upload_metadata = data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.blobstore_key ==
      metadata.blobstore_key).get()
  if not upload_metadata:
    logs.log_error('Invalid upload metadata key %s.' % metadata.blobstore_key)
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
    logs.log_error('Could not retrieve archive for bundle %d.' % metadata_id)
    tasks.add_task('unpack', metadata_id, job_type)
    return

  try:
    archive.unpack(archive_path, testcases_directory)
  except:
    logs.log_error('Could not unpack archive for bundle %d.' % metadata_id)
    tasks.add_task('unpack', metadata_id, job_type)
    return

  # Get additional testcase metadata (if any).
  additional_metadata = None
  if upload_metadata.additional_metadata_string:
    additional_metadata = json.loads(upload_metadata.additional_metadata_string)

  archive_state = data_types.ArchiveStatus.NONE
  bundled = True
  file_list = archive.get_file_list(archive_path)

  for file_path in file_list:
    absolute_file_path = os.path.join(testcases_directory, file_path)
    filename = os.path.basename(absolute_file_path)

    # Only files are actual testcases. Skip directories.
    if not os.path.isfile(absolute_file_path):
      continue

    try:
      file_handle = open(absolute_file_path, 'rb')
      blob_key = blobs.write_blob(file_handle)
      file_handle.close()
    except:
      blob_key = None

    if not blob_key:
      logs.log_error(
          'Could not write testcase %s to blobstore.' % absolute_file_path)
      continue

    data_handler.create_user_uploaded_testcase(
        blob_key, metadata.blobstore_key, archive_state,
        metadata.archive_filename, filename, metadata.timeout,
        metadata.job_type, metadata.job_queue, metadata.http_flag,
        metadata.gestures, metadata.additional_arguments,
        metadata.bug_information, metadata.crash_revision,
        metadata.uploader_email, metadata.platform_id,
        metadata.app_launch_command, metadata.fuzzer_name,
        metadata.overridden_fuzzer_name, metadata.fuzzer_binary_name, bundled,
        upload_metadata.retries, upload_metadata.bug_summary_update_flag,
        upload_metadata.quiet_flag, additional_metadata)

  # The upload metadata for the archive is not needed anymore since we created
  # one for each testcase.
  upload_metadata.key.delete()

  shell.clear_testcase_directories()

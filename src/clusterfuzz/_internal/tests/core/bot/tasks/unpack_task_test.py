# Copyright 2026 Google LLC
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
"""Tests for unpack_task."""

import io
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile

from clusterfuzz._internal.bot.tasks import unpack_task
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils

JOB_NAME = 'libfuzzer_asan_job'
SECRET_CONTENTS = b'outside of the testcases directory'


@test_utils.with_cloud_emulators('datastore')
class ExecuteTaskTest(unittest.TestCase):
  """Tests for execute_task."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
        'clusterfuzz._internal.datastore.data_handler.'
        'create_user_uploaded_testcase',
        'clusterfuzz._internal.google_cloud_utils.blobs.read_blob_to_disk',
        'clusterfuzz._internal.google_cloud_utils.blobs.write_blob',
        'clusterfuzz._internal.system.shell.clear_testcase_directories',
    ])

    self.temp_dir = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)

    self.testcases_directory = os.path.join(self.temp_dir, 'fuzz_inputs_disk')
    os.mkdir(self.testcases_directory)
    os.environ['FUZZ_INPUTS_DISK'] = self.testcases_directory
    os.environ['BOT_NAME'] = 'bot'

    # A file on the bot that must never be uploaded.
    self.secret_path = os.path.join(self.temp_dir, 'secret')
    with open(self.secret_path, 'wb') as f:
      f.write(SECRET_CONTENTS)

    data_types.Job(name=JOB_NAME, platform='LINUX').put()

    self.uploaded = {}
    self.archive_source_path = None
    self.mock.write_blob.side_effect = self._write_blob
    self.mock.read_blob_to_disk.side_effect = self._read_blob_to_disk

  def _write_blob(self, file_handle):
    """Fake blobs.write_blob that records the uploaded contents."""
    blob_key = f'blob-{len(self.uploaded)}'
    self.uploaded[blob_key] = file_handle.read()
    return blob_key

  def _read_blob_to_disk(self, blob_key, local_path):
    """Fake blobs.read_blob_to_disk that copies the test archive."""
    del blob_key
    shutil.copy(self.archive_source_path, local_path)
    return True

  def _create_metadata(self, archive_filename):
    """Creates the bundle and upload metadata for |archive_filename|."""
    metadata = data_types.BundledArchiveMetadata(
        blobstore_key='archive_key',
        job_type=JOB_NAME,
        archive_filename=archive_filename,
        uploader_email='uploader@example.com')
    metadata.put()
    data_types.TestcaseUploadMetadata(blobstore_key='archive_key').put()
    return str(metadata.key.id())

  def _execute(self, archive_filename):
    metadata_id = self._create_metadata(archive_filename)
    unpack_task.execute_task(metadata_id, JOB_NAME)

  def _uploaded_testcases(self):
    """Returns {filename: contents} of the testcases that were created."""
    result = {}
    for call in self.mock.create_user_uploaded_testcase.call_args_list:
      blob_key = call.args[0]
      filename = call.args[4]
      result[filename] = self.uploaded[blob_key]
    return result

  def test_zip_skips_members_outside_testcases_directory(self):
    """Tests that absolute and '..' members of a zip archive are not read from
    the bot's filesystem."""
    self.archive_source_path = os.path.join(self.temp_dir, 'bundle.zip')
    relative_secret_path = os.path.relpath(
        self.secret_path, start=self.testcases_directory)
    self.assertTrue(relative_secret_path.startswith('..'))

    with zipfile.ZipFile(self.archive_source_path, 'w') as zip_file:
      zip_file.writestr('testcase1', b'testcase 1')
      zip_file.writestr('dir/testcase2', b'testcase 2')
      zip_file.writestr(self.secret_path, b'absolute')
      zip_file.writestr(relative_secret_path, b'relative')

    self._execute('bundle.zip')

    self.assertEqual({
        'testcase1': b'testcase 1',
        'testcase2': b'testcase 2',
    }, self._uploaded_testcases())
    self.assertNotIn(SECRET_CONTENTS, self.uploaded.values())
    self.mock.add_task.assert_not_called()

  def test_tar_skips_links_outside_testcases_directory(self):
    """Tests that symlinks and hard links in a tar archive are not followed to
    files outside of the testcases directory."""
    self.archive_source_path = os.path.join(self.temp_dir, 'bundle.tar')

    with tarfile.open(self.archive_source_path, 'w') as tar_file:
      contents = b'testcase 1'
      info = tarfile.TarInfo('testcase1')
      info.size = len(contents)
      tar_file.addfile(info, io.BytesIO(contents))

      symlink = tarfile.TarInfo('symlink')
      symlink.type = tarfile.SYMTYPE
      symlink.linkname = self.secret_path
      tar_file.addfile(symlink)

      hardlink = tarfile.TarInfo('hardlink')
      hardlink.type = tarfile.LNKTYPE
      hardlink.linkname = self.secret_path
      tar_file.addfile(hardlink)

    self._execute('bundle.tar')

    self.assertEqual({
        'testcase1': b'testcase 1',
    }, self._uploaded_testcases())
    self.assertNotIn(SECRET_CONTENTS, self.uploaded.values())
    self.mock.add_task.assert_not_called()

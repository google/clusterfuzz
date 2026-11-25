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
from unittest import mock
import zipfile

from clusterfuzz._internal.bot.tasks import unpack_task
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils

JOB_NAME = 'libfuzzer_asan_job'
UPLOADER_EMAIL = 'uploader@example.com'
OUTSIDE_CONTENTS = b'outside of the testcases directory'


def _add_tar_file(tar_file, name, contents):
  """Adds a regular file to |tar_file|."""
  info = tarfile.TarInfo(name)
  info.size = len(contents)
  tar_file.addfile(info, io.BytesIO(contents))


def _add_tar_link(tar_file, name, link_type, target):
  """Adds a symlink or a hard link to |tar_file|."""
  info = tarfile.TarInfo(name)
  info.type = link_type
  info.linkname = target
  tar_file.addfile(info)


class UnpackTaskTestBase(unittest.TestCase):
  """Common set up for unpack_task tests."""

  def setUp(self):
    helpers.patch_environ(self)

    self.temp_dir = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)

    self.testcases_directory = os.path.join(self.temp_dir, 'fuzz_inputs_disk')
    os.mkdir(self.testcases_directory)
    os.environ['FUZZ_INPUTS_DISK'] = self.testcases_directory
    os.environ['BOT_NAME'] = 'bot'

    # A file on the bot that must never be uploaded.
    self.outside_path = os.path.join(self.temp_dir, 'outside')
    with open(self.outside_path, 'wb') as f:
      f.write(OUTSIDE_CONTENTS)

    self.job = data_types.Job(name=JOB_NAME, platform='LINUX')
    self.job.put()

  def _archive_path(self, archive_filename):
    return os.path.join(self.temp_dir, archive_filename)

  def _create_metadata(self, archive_filename, blobstore_key, trusted=False):
    """Creates the bundle and upload metadata, as upload_testcase does."""
    metadata = data_types.BundledArchiveMetadata(
        blobstore_key=blobstore_key,
        job_type=JOB_NAME,
        job_queue='jobs-linux',
        archive_filename=archive_filename,
        uploader_email=UPLOADER_EMAIL,
        trusted=trusted)
    metadata.put()
    data_types.TestcaseUploadMetadata(
        blobstore_key=blobstore_key,
        original_blobstore_key=blobstore_key,
        filename=archive_filename,
        uploader_email=UPLOADER_EMAIL,
        bundled=True,
        status='Pending').put()
    return str(metadata.key.id())


@test_utils.with_cloud_emulators('datastore')
class ExecuteTaskTest(UnpackTaskTestBase):
  """Tests for execute_task, with storage and testcase creation mocked."""

  def setUp(self):
    super().setUp()
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
        'clusterfuzz._internal.datastore.data_handler.'
        'create_user_uploaded_testcase',
        'clusterfuzz._internal.google_cloud_utils.blobs.read_blob_to_disk',
        'clusterfuzz._internal.google_cloud_utils.blobs.write_blob',
        'clusterfuzz._internal.system.shell.clear_testcase_directories',
    ])

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

  def _execute(self, archive_filename):
    self.archive_source_path = self._archive_path(archive_filename)
    metadata_id = self._create_metadata(archive_filename, 'archive_key')
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
    relative_outside_path = os.path.relpath(
        self.outside_path, start=self.testcases_directory)
    self.assertTrue(relative_outside_path.startswith('..'))

    with zipfile.ZipFile(self._archive_path('bundle.zip'), 'w') as zip_file:
      zip_file.writestr('testcase1', b'testcase 1')
      zip_file.writestr('dir/testcase2', b'testcase 2')
      zip_file.writestr(self.outside_path, b'absolute')
      zip_file.writestr(relative_outside_path, b'relative')

    self._execute('bundle.zip')

    self.assertEqual({
        'testcase1': b'testcase 1',
        'testcase2': b'testcase 2',
    }, self._uploaded_testcases())
    self.assertNotIn(OUTSIDE_CONTENTS, self.uploaded.values())
    self.mock.add_task.assert_not_called()

  def test_tar_skips_links_outside_testcases_directory(self):
    """Tests that symlinks and hard links in a tar archive are not followed to
    files outside of the testcases directory."""
    with tarfile.open(self._archive_path('bundle.tar'), 'w') as tar_file:
      _add_tar_file(tar_file, 'testcase1', b'testcase 1')
      _add_tar_link(tar_file, 'symlink', tarfile.SYMTYPE, self.outside_path)
      _add_tar_link(tar_file, 'hardlink', tarfile.LNKTYPE, self.outside_path)

    self._execute('bundle.tar')

    self.assertEqual({
        'testcase1': b'testcase 1',
    }, self._uploaded_testcases())
    self.assertNotIn(OUTSIDE_CONTENTS, self.uploaded.values())
    self.mock.add_task.assert_not_called()

  def test_retries_when_archive_cannot_be_retrieved(self):
    """Tests that the task is retried when the archive can't be retrieved."""
    self.mock.read_blob_to_disk.side_effect = None
    self.mock.read_blob_to_disk.return_value = False
    metadata_id = self._create_metadata('bundle.zip', 'archive_key')

    unpack_task.execute_task(metadata_id, JOB_NAME)

    self.mock.add_task.assert_called_once_with('unpack', metadata_id, JOB_NAME)
    self.mock.create_user_uploaded_testcase.assert_not_called()

  def test_retries_when_archive_cannot_be_unpacked(self):
    """Tests that the task is retried when the archive is invalid."""
    with open(self._archive_path('bundle.zip'), 'wb') as f:
      f.write(b'not a zip file')

    self._execute('bundle.zip')

    self.mock.add_task.assert_called_once_with('unpack', mock.ANY, JOB_NAME)
    self.mock.create_user_uploaded_testcase.assert_not_called()


@test_utils.with_cloud_emulators('datastore')
class ExecuteTaskIntegrationTest(UnpackTaskTestBase):
  """Tests for execute_task with real blob storage (local filesystem backed)
  and real testcase creation. Only task queueing is mocked."""

  def setUp(self):
    super().setUp()
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
        'clusterfuzz._internal.system.shell.clear_testcase_directories',
    ])

    os.environ['LOCAL_GCS_BUCKETS_PATH'] = os.path.join(self.temp_dir, 'gcs')
    os.environ['TEST_BLOBS_BUCKET'] = 'blobs-bucket'
    storage.create_bucket_if_needed('blobs-bucket')

  def _execute(self, archive_filename, trusted=False):
    """Uploads the archive to blob storage and runs the unpack task, like a
    multiple testcase upload does."""
    archive_key = blobs.write_blob(self._archive_path(archive_filename))
    metadata_id = self._create_metadata(
        archive_filename, archive_key, trusted=trusted)
    unpack_task.execute_task(metadata_id, JOB_NAME)
    return archive_key

  def _assert_testcases_created(self, archive_filename, archive_key,
                                expected_testcases):
    """Asserts that exactly |expected_testcases| ({filename: contents}) were
    created from the archive, with their metadata and analyze tasks."""
    testcases = list(data_types.Testcase.query())
    self.assertCountEqual(expected_testcases.keys(),
                          [testcase.absolute_path for testcase in testcases])

    for testcase in testcases:
      self.assertEqual(expected_testcases[testcase.absolute_path],
                       blobs.read_key(testcase.fuzzed_keys))
      self.assertEqual(JOB_NAME, testcase.job_type)
      self.assertEqual(UPLOADER_EMAIL, testcase.uploader_email)
      self.assertEqual(archive_filename, testcase.archive_filename)
      self.assertEqual(data_types.ArchiveStatus.NONE, testcase.archive_state)
      self.assertEqual('Pending', testcase.status)

    # The archive's upload metadata is replaced by one per testcase.
    upload_metadata = list(data_types.TestcaseUploadMetadata.query())
    self.assertCountEqual(
        [testcase.key.id() for testcase in testcases],
        [metadata.testcase_id for metadata in upload_metadata])
    for metadata in upload_metadata:
      self.assertTrue(metadata.bundled)
      self.assertEqual(archive_key, metadata.original_blobstore_key)
      self.assertEqual('Pending', metadata.status)

    # An analyze task is created for each testcase, and the unpack task is not
    # retried.
    self.assertCountEqual(
        [('analyze', testcase.key.id(), JOB_NAME) for testcase in testcases],
        [call.args[:3] for call in self.mock.add_task.call_args_list])
    self.mock.clear_testcase_directories.assert_called_once_with()

  def test_zip_bundle(self):
    """Tests unpacking a regular zip archive with nested directories."""
    with zipfile.ZipFile(self._archive_path('bundle.zip'), 'w') as zip_file:
      zip_file.writestr('testcase1.html', b'testcase 1')
      zip_file.writestr('dir/', b'')
      zip_file.writestr('dir/testcase2.js', b'testcase 2')
      zip_file.writestr('dir/subdir/testcase3', b'testcase 3')

    archive_key = self._execute('bundle.zip')

    self._assert_testcases_created(
        'bundle.zip', archive_key, {
            'testcase1.html': b'testcase 1',
            'testcase2.js': b'testcase 2',
            'testcase3': b'testcase 3',
        })

  def test_tgz_bundle(self):
    """Tests unpacking a regular gzipped tar archive with nested
    directories."""
    with tarfile.open(self._archive_path('bundle.tgz'), 'w:gz') as tar_file:
      _add_tar_file(tar_file, 'testcase1.html', b'testcase 1')
      _add_tar_file(tar_file, 'dir/testcase2.js', b'testcase 2')

    archive_key = self._execute('bundle.tgz')

    self._assert_testcases_created('bundle.tgz', archive_key, {
        'testcase1.html': b'testcase 1',
        'testcase2.js': b'testcase 2',
    })

  def test_zip_bundle_with_members_outside_testcases_directory(self):
    """Tests that only the regular testcases of a zip archive with absolute and
    '..' members are created."""
    relative_outside_path = os.path.relpath(
        self.outside_path, start=self.testcases_directory)

    with zipfile.ZipFile(self._archive_path('bundle.zip'), 'w') as zip_file:
      zip_file.writestr('testcase1', b'testcase 1')
      zip_file.writestr(self.outside_path, b'absolute')
      zip_file.writestr(relative_outside_path, b'relative')

    archive_key = self._execute('bundle.zip')

    self._assert_testcases_created('bundle.zip', archive_key, {
        'testcase1': b'testcase 1',
    })

  def test_trusted_bundle_propagates_trusted_flag(self):
    """Tests that trusted=True on BundledArchiveMetadata propagates to testcases."""
    with zipfile.ZipFile(self._archive_path('bundle.zip'), 'w') as zip_file:
      zip_file.writestr('testcase1', b'testcase 1')

    archive_key = self._execute('bundle.zip', trusted=True)

    self._assert_testcases_created('bundle.zip', archive_key, {
        'testcase1': b'testcase 1',
    })
    testcases = list(data_types.Testcase.query())
    self.assertTrue(all(testcase.trusted for testcase in testcases))

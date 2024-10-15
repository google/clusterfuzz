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
"""update_task tests."""
import os
import tempfile
import unittest
import zipfile

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks import update_task
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class GetLocalSourceRevisionTest(fake_filesystem_unittest.TestCase):
  """Test get_local_source_revision."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    helpers.patch_environ(self)

    os.environ['ROOT_DIR'] = '/root'
    os.environ['FAIL_RETRIES'] = '1'

  def test_no_revision(self):
    """Test when there's no revision."""
    self.assertIsNone(update_task.get_local_source_revision())

  def test_has_revision(self):
    """Test when there's a revision."""
    os.mkdir('/root')
    self.fs.create_file(
        os.path.join('/root', utils.LOCAL_SOURCE_MANIFEST), contents='revision')
    self.assertEqual('revision', update_task.get_local_source_revision())


class TrackRevisionTest(fake_filesystem_unittest.TestCase):
  """Test _track_revision."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.get_clusterfuzz_release',
        'clusterfuzz._internal.system.environment.platform',
        'clusterfuzz._internal.system.environment.platform_version'
    ])

    os.environ['ROOT_DIR'] = '/root'
    os.environ['FAIL_RETRIES'] = '1'

    self.os_type = 'unix'
    self.os_version = 'v5'
    self.clusterfuzz_release = 'prod'
    self.mock.platform_version.return_value = self.os_version
    self.mock.platform.return_value = self.os_type
    self.mock.get_clusterfuzz_release.return_value = self.clusterfuzz_release

    monitor.metrics_store().reset_for_testing()

  def test_no_revision(self):
    """Test when there's no revision."""
    update_task.track_revision()
    self.assertEqual(
        0,
        monitoring_metrics.BOT_COUNT.get({
            'revision': 'revision',
            'os_type': self.os_type,
            'os_version': self.os_version,
            'release': self.clusterfuzz_release,
        }))

  def test_has_revision(self):
    """Test when there's a revision."""
    os.mkdir('/root')
    self.fs.create_file(
        os.path.join('/root', utils.LOCAL_SOURCE_MANIFEST), contents='revision')
    update_task.track_revision()
    self.assertEqual(
        1,
        monitoring_metrics.BOT_COUNT.get({
            'revision': 'revision',
            'os_type': self.os_type,
            'os_version': self.os_version,
            'release': self.clusterfuzz_release,
        }))


class GetNewerSourceRevisionTest(unittest.TestCase):
  """Test get_newer_source_revision."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.update_task.get_remote_source_revision',
        'clusterfuzz._internal.bot.tasks.update_task.get_local_source_revision',
    ])

    os.environ['ROOT_DIR'] = 'root_dir'
    os.environ['BOT_TMPDIR'] = 'bot_tmpdir'
    os.environ['FAIL_RETRIES'] = '1'
    self.manifest_suffix = '.3'

  def test_no_local_revision(self):
    """Test no local revision."""
    self.mock.get_remote_source_revision.return_value = 'remote'
    self.mock.get_local_source_revision.return_value = ''
    self.assertEqual('remote', update_task.get_newer_source_revision())

    self.mock.get_local_source_revision.assert_called_once_with()
    self.mock.get_remote_source_revision.assert_called_once_with(
        'gs://test-deployment-bucket/clusterfuzz-source.manifest' +
        self.manifest_suffix)

  def test_error_on_remote_revision(self):
    """Test error on remote revision."""
    self.mock.get_remote_source_revision.side_effect = Exception('fake')
    self.assertIsNone(update_task.get_newer_source_revision())

    self.assertEqual(0, self.mock.get_local_source_revision.call_count)

  def test_older_revision(self):
    """Test remote revision is older."""
    self.mock.get_remote_source_revision.return_value = '123'
    self.mock.get_local_source_revision.return_value = '456789'
    self.assertIsNone(update_task.get_newer_source_revision())

    self.mock.get_local_source_revision.assert_called_once_with()
    self.mock.get_remote_source_revision.assert_called_once_with(
        'gs://test-deployment-bucket/clusterfuzz-source.manifest' +
        self.manifest_suffix)

  def test_newer_revision(self):
    """Test remote revision is newer."""
    self.mock.get_remote_source_revision.return_value = '456'
    self.mock.get_local_source_revision.return_value = '12345'
    self.assertEqual('456', update_task.get_newer_source_revision())

    self.mock.get_local_source_revision.assert_called_once_with()
    self.mock.get_remote_source_revision.assert_called_once_with(
        'gs://test-deployment-bucket/clusterfuzz-source.manifest' +
        self.manifest_suffix)


class GetUrlsTest(unittest.TestCase):
  """Tests getting source and manifest URLs."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'platform.system',
    ])
    self.manifest_suffix = '.3'
    self.deployment_suffix = '-3'

  def test_get_source_manifest_url(self):
    """Test get_source_manifest_url."""
    self.assertEqual(
        'gs://test-deployment-bucket/clusterfuzz-source.manifest' +
        self.manifest_suffix, update_task.get_source_manifest_url())

  def test_get_source_url_windows(self):
    """Test get_source_url on windows."""
    self.mock.system.return_value = 'Windows'
    self.assertEqual(
        'gs://test-deployment-bucket/windows%s.zip' % self.deployment_suffix,
        update_task.get_source_url())

  def test_get_source_url_macos(self):
    """Test get_source_url on macos."""
    self.mock.system.return_value = 'Darwin'
    self.assertEqual(
        'gs://test-deployment-bucket/macos%s.zip' % self.deployment_suffix,
        update_task.get_source_url())

  def test_get_source_url_linux(self):
    """Test get_source_url on linux."""
    self.mock.system.return_value = 'Linux'
    self.assertEqual(
        'gs://test-deployment-bucket/linux%s.zip' % self.deployment_suffix,
        update_task.get_source_url())


@test_utils.slow
@test_utils.integration
class UpdateSourceCodeIntegrationTest(unittest.TestCase):
  """Tests updating clusterfuzz source code."""

  def setUp(self):
    helpers.patch_environ(self)
    if os.getenv('PARALLEL_TESTS'):
      self.skipTest('Package testing is disabled when running in parallel.')

    self.temp_directory = self._make_temp_dir()
    self.bot_tmpdir = self._make_temp_dir()
    os.environ['ROOT_DIR'] = os.path.join(self.temp_directory, 'child')
    os.mkdir(os.environ['ROOT_DIR'])
    os.environ['BOT_TMPDIR'] = self.bot_tmpdir
    os.environ['TEST_TMPDIR'] = self.bot_tmpdir
    self.saved_cwd = os.getcwd()
    os.chdir(os.environ['ROOT_DIR'])
    helpers.patch(self, [
        'clusterfuzz._internal.system.process_handler.cleanup_stale_processes',
        'local.butler.common.is_git_dirty',
        'clusterfuzz._internal.bot.tasks.update_task.get_source_url',
        'clusterfuzz._internal.base.utils.read_data_from_file',
    ])
    self.mock.get_source_url.return_value = 'gs://clusterfuzz-deployment/linux-3.zip'
    self.mock.read_data_from_file.return_value = b'version'

  def tearDown(self):
    os.chdir(self.saved_cwd)

  def _make_temp_dir(self):
    if not hasattr(self, '_dirs'):
      self._dirs = []
    created_dir = tempfile.TemporaryDirectory()
    dir_name = created_dir.name
    self._dirs.append(created_dir)
    return dir_name

  def test_files_have_read_and_write_permissions(self):
    """Tests that all the extracted files have both read and write permissions."""
    update_task.update_source_code()
    for dirpath, _, filenames in os.walk(
        os.path.join(self.temp_directory, 'clusterfuzz')):
      for filename in filenames:
        filepath = os.path.join(dirpath, filename)
        self.assertTrue(os.access(filepath, os.R_OK))
        self.assertTrue(os.access(filepath, os.W_OK))

  def test_all_files_are_correctly_unpacked(self):
    """Tests that all files in the zip archive are correctly unpacked."""
    update_task.update_source_code()
    zipfile_path = os.path.join(self._make_temp_dir(), 'linux.zip')
    storage.copy_file_from('gs://clusterfuzz-deployment/linux-3.zip',
                           zipfile_path)
    archive = zipfile.ZipFile(zipfile_path)
    for file in archive.namelist():
      if os.path.basename(file) == 'adb':
        continue
      self.assertTrue(os.path.exists(os.path.join(self.temp_directory, file)))

  def test_archive_execute_permission_is_respected(self):
    """Tests that the exectuable bit is correctly propagated to source files."""
    update_task.update_source_code()
    zipfile_path = os.path.join(self._make_temp_dir(), 'linux.zip')
    storage.copy_file_from('gs://clusterfuzz-deployment/linux-3.zip',
                           zipfile_path)
    archive = zipfile.ZipFile(zipfile_path)
    for member in archive.infolist():
      if os.path.basename(member.filename) == 'adb':
        continue
      mode = (member.external_attr >> 16) & 0o7777
      filepath = os.path.join(self.temp_directory, member.filename)
      if mode & 0o100:
        self.assertTrue(os.access(filepath, os.X_OK))

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
import sys
import unittest

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks import update_task
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

    os.environ['ROOT_DIR'] = '/root'
    os.environ['FAIL_RETRIES'] = '1'

    monitor.metrics_store().reset_for_testing()

  def test_no_revision(self):
    """Test when there's no revision."""
    update_task.track_revision()
    self.assertEqual(0,
                     monitoring_metrics.BOT_COUNT.get({
                         'revision': 'revision'
                     }))

  def test_has_revision(self):
    """Test when there's a revision."""
    os.mkdir('/root')
    self.fs.create_file(
        os.path.join('/root', utils.LOCAL_SOURCE_MANIFEST), contents='revision')
    update_task.track_revision()
    self.assertEqual(1,
                     monitoring_metrics.BOT_COUNT.get({
                         'revision': 'revision'
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

    if sys.version_info.major == 3:
      self.manifest_suffix = '.3'
    else:
      self.manifest_suffix = ''

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
    if sys.version_info.major == 3:
      self.manifest_suffix = '.3'
      self.deployment_suffix = '-3'
    else:
      self.manifest_suffix = ''
      self.deployment_suffix = ''

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

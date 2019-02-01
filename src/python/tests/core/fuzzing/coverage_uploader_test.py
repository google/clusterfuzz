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
"""Tests for the coverage_uploader module."""

import datetime
import os

from pyfakefs import fake_filesystem_unittest

from fuzzing import coverage_uploader
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


def _mock_config_get(_, param):
  """Handle test configuration options."""
  if param == 'coverage.fuzzer-testcases.bucket':
    return 'test-coverage-testcases'

  return None


class FakeGSUtilRunner(object):
  """Fake gsutil runner for testing."""
  rsync_calls = []

  def rsync(self, source, destination):
    FakeGSUtilRunner.rsync_calls.append((source, destination))


class UploadTestsToCloudStorageTest(fake_filesystem_unittest.TestCase):
  """Tests for upload_tests_to_cloud_storage."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'base.utils.utcnow',
        'config.local_config.ProjectConfig.get',
        'datastore.locks.acquire_lock',
        'datastore.locks.release_lock',
        'google_cloud_utils.gsutil.GSUtilRunner',
        'google_cloud_utils.storage.list_blobs',
        'google_cloud_utils.storage.read_data',
        'google_cloud_utils.storage.write_data',
    ])

    test_utils.set_up_pyfakefs(self)

    self.mock.write_data.return_value = True
    self.mock.utcnow.side_effect = lambda: datetime.datetime(2018, 11, 1, 0, 0)

    FakeGSUtilRunner.calls = []
    self.mock.GSUtilRunner.side_effect = FakeGSUtilRunner
    self.mock.get.side_effect = _mock_config_get

    os.environ['BOT_NAME'] = 'test-bot'
    os.environ['BOT_TMPDIR'] = '/tmp'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['TRADITIONAL_FUZZER_COVERAGE'] = 'True'

  def test_tests_created_in_correct_bucket(self):
    """Ensure that we invoke gsutil correctly to store tests."""
    files = ['/a/b/file1.txt', '/a/file2.txt', '/b/c/file3.txt']
    coverage_uploader.upload_testcases_if_needed('test_fuzzer', files, '/a/')

    self.mock.write_data.assert_called_with(
        'b/file1.txt\nfile2.txt',
        'gs://test-coverage-testcases/2018-11-01/test_fuzzer/'
        '5b680a295e1f3a81160a0bd71ca2abbcb8d19521/file_list.txt')

    self.assertEquals(
        FakeGSUtilRunner.rsync_calls,
        [('/a/', 'gs://test-coverage-testcases/2018-11-01/test_fuzzer/'
          '5b680a295e1f3a81160a0bd71ca2abbcb8d19521')])

  def test_data_directory_ignored(self):
    """Ensure that we do nothing if the output directory is empty."""
    files = ['/data/b/file1.txt', '/data/file2.txt', '/data/c/file3.txt']
    coverage_uploader.upload_testcases_if_needed('test_fuzzer', files,
                                                 '/testcases/')
    self.assertEquals(FakeGSUtilRunner.rsync_calls, [])

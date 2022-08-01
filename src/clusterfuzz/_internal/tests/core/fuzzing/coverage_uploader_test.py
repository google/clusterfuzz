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

from clusterfuzz._internal.fuzzing import coverage_uploader
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


def _mock_config_get(_, param):
  """Handle test configuration options."""
  if param == 'coverage.fuzzer-testcases.bucket':
    return 'test-coverage-testcases'

  return None


class FakeGSUtilRunner(object):
  """Fake gsutil runner for testing."""
  rsync_calls = []

  def rsync(self, source, destination, exclusion_pattern=None):
    FakeGSUtilRunner.rsync_calls.append((source, destination,
                                         exclusion_pattern))


class UploadTestsToCloudStorageTest(fake_filesystem_unittest.TestCase):
  """Tests for upload_tests_to_cloud_storage."""

  def setUp(self):
    """Setup for upload tests to cloud storage test."""
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
        'clusterfuzz._internal.config.local_config.ProjectConfig.get',
        'clusterfuzz._internal.datastore.locks.acquire_lock',
        'clusterfuzz._internal.datastore.locks.release_lock',
        'clusterfuzz._internal.google_cloud_utils.gsutil.GSUtilRunner',
        'clusterfuzz._internal.google_cloud_utils.storage.list_blobs',
        'clusterfuzz._internal.google_cloud_utils.storage.read_data',
        'clusterfuzz._internal.google_cloud_utils.storage.write_data',
    ])

    test_utils.set_up_pyfakefs(self)

    self.mock.write_data.return_value = True
    self.mock.utcnow.side_effect = lambda: datetime.datetime(2018, 11, 1, 0, 0)

    FakeGSUtilRunner.rsync_calls = []
    self.mock.GSUtilRunner.side_effect = FakeGSUtilRunner
    self.mock.get.side_effect = _mock_config_get

    os.environ['BOT_NAME'] = 'test-bot'
    os.environ['BOT_TMPDIR'] = '/tmp'
    os.environ['FAIL_RETRIES'] = '1'

  def test_tests_created_in_correct_bucket(self):
    """Ensure that we invoke gsutil correctly to store tests."""
    files = [
        '/testcases/a/file1.txt', '/testcases/file2.txt',
        '/something/b/file3.txt', '/data/f/g/file4.txt'
    ]
    coverage_uploader.upload_testcases_if_needed('test_fuzzer', files,
                                                 '/testcases', '/data')

    self.mock.write_data.assert_called_with(
        b'a/file1.txt\nfile2.txt\nf/g/file4.txt',
        'gs://test-coverage-testcases/2018-11-01/test_fuzzer/'
        '5b680a295e1f3a81160a0bd71ca2abbcb8d19521/file_list.txt')
    self.assertEqual(
        FakeGSUtilRunner.rsync_calls,
        [('/testcases', 'gs://test-coverage-testcases/'
          '2018-11-01/test_fuzzer/5b680a295e1f3a81160a0bd71ca2abbcb8d19521',
          None),
         ('/data', 'gs://test-coverage-testcases/'
          '2018-11-01/test_fuzzer/5b680a295e1f3a81160a0bd71ca2abbcb8d19521',
          '(?!.*fuzz-)'),
         ('/data', 'gs://test-coverage-testcases/'
          '2018-11-01/test_fuzzer/5b680a295e1f3a81160a0bd71ca2abbcb8d19521',
          '(?!.*resource)')])

  def test_empty_testcases_list(self):
    """Ensure that we do nothing when we have no testcases."""
    coverage_uploader.upload_testcases_if_needed('test_fuzzer', [],
                                                 '/testcases', '/data')
    self.assertEqual(self.mock.write_data.call_count, 0)
    self.assertEqual(FakeGSUtilRunner.rsync_calls, [])

  def test_large_testcase_list(self):
    """Ensure that we cap number of uploaded testcases."""
    files = ['/testcases/file%s' % i for i in range(20000)]
    coverage_uploader.upload_testcases_if_needed('test_fuzzer', files,
                                                 '/testcases', '/data')

    filtered_files_list = '\n'.join(
        ['file%s' % i for i in range(1000)]).encode('utf-8')
    self.mock.write_data.assert_called_with(
        filtered_files_list,
        'gs://test-coverage-testcases/2018-11-01/test_fuzzer/'
        '5b680a295e1f3a81160a0bd71ca2abbcb8d19521/file_list.txt')
    self.assertEqual(
        FakeGSUtilRunner.rsync_calls,
        [('/testcases', 'gs://test-coverage-testcases/'
          '2018-11-01/test_fuzzer/5b680a295e1f3a81160a0bd71ca2abbcb8d19521',
          None)])

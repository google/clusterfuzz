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

import os
import unittest
from unittest import mock

from clusterfuzz._internal.bot.tasks import unpack_task
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class UnpackTaskTest(unittest.TestCase):
  """Tests for unpack_task.execute_task."""

  def setUp(self):
    helpers.patch_environ(self)
    os.environ['FUZZ_INPUTS_DISK'] = '/tmp'
    os.environ['BOT_NAME'] = 'bot-1'
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
        'clusterfuzz._internal.base.tasks.default_queue',
        'clusterfuzz._internal.google_cloud_utils.blobs.read_blob_to_disk',
    ])
    self.mock.default_queue.return_value = 'high-end-jobs-windows'
    data_types.Job(
        name='swarming_job',
        platform='ANDROID_EMULATOR',
        environment_string='IS_SWARMING_JOB = True\n').put()
    self.metadata = data_types.BundledArchiveMetadata(
        blobstore_key='blob-key',
        archive_filename='testcases.zip',
        job_queue='preprocess-swarming',
        job_type='swarming_job')
    self.metadata.put()
    data_types.TestcaseUploadMetadata(
        blobstore_key='blob-key', filename='testcases.zip', bundled=True).put()

  def test_blob_read_retry_uses_linux_queue_when_swarming_enabled(self):
    """Tests that blob-read retries use jobs-linux when Swarming is enabled."""
    flag = data_types.FeatureFlag(id='swarming_remote_execution', enabled=True)
    flag.put()

    self.mock.read_blob_to_disk.return_value = False
    unpack_task.execute_task(self.metadata.key.id(), 'swarming_job')

    self.mock.add_task.assert_called_once_with(
        'unpack', self.metadata.key.id(), 'swarming_job', queue='jobs-linux')

    self.mock.add_task.reset_mock()
    flag.enabled = False
    flag.put()
    unpack_task.execute_task(self.metadata.key.id(), 'swarming_job')

    self.mock.add_task.assert_called_once_with(
        'unpack',
        self.metadata.key.id(),
        'swarming_job',
        queue='high-end-jobs-windows')

  @mock.patch(
      'clusterfuzz._internal.system.archive.open',
      side_effect=RuntimeError('corrupt archive'))
  def test_extract_failure_retry_uses_linux_queue_for_swarming_job(self, _):
    """Tests that archive extraction retries also route to jobs-linux."""
    data_types.FeatureFlag(id='swarming_remote_execution', enabled=True).put()

    self.mock.read_blob_to_disk.return_value = True
    unpack_task.execute_task(self.metadata.key.id(), 'swarming_job')

    self.mock.add_task.assert_called_once_with(
        'unpack', self.metadata.key.id(), 'swarming_job', queue='jobs-linux')

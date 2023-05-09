# Copyright 2023 Google LLC
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
"""Tests for uworker_io."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from google.cloud import ndb

from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class TworkerPreprocessTest(unittest.TestCase):
  OUTPUT_SIGNED_UPLOAD_URL = 'https://signed-upload-output'
  OUTPUT_DOWNLOAD_GCS_URL = '/download-output'
  INPUT_SIGNED_DOWNLOAD_URL = 'https://signed-download-input'
  UWORKER_ENV = {'ENVVAR': 'VALUE'}
  TASK_ARGUMENT = 'testcase-id'
  JOB_TYPE = 'libfuzzer_asan'
  INPUT = {'input': 'something'}

  def setUp(self):
    # helpers.patch_environ(self)
    # os.environ['TEST_CORPUS_BUCKET'] = 'UWORKER_IO_TEST'
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.get_uworker_output_urls',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.serialize_and_upload_uworker_input',
    ])
    self.mock.get_uworker_output_urls.return_value = (
        self.OUTPUT_SIGNED_UPLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL)
    self.mock.serialize_and_upload_uworker_input.return_value = (
        self.INPUT_SIGNED_DOWNLOAD_URL)

  def test_worker_preprocess(self):
    module = mock.MagicMock()
    module.utask_preprocess.return_value = self.INPUT
    result = utasks.tworker_preprocess(module, self.TASK_ARGUMENT,
                                       self.JOB_TYPE, self.UWORKER_ENV)
    self.mock.serialize_and_upload_uworker_input.assert_called_with(self.INPUT, self.JOB_TYPE, self.OUTPUT_SIGNED_UPLOAD_URL)
    self.assertEqual((self.INPUT_SIGNED_DOWNLOAD_URL,
                      self.OUTPUT_DOWNLOAD_GCS_URL),
                     result)

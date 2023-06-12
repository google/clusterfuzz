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
import unittest
from unittest import mock

from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.tests.test_libs import helpers


class TworkerPreprocessTest(unittest.TestCase):
  """Tests that tworker_preprocess works as intended."""
  OUTPUT_SIGNED_UPLOAD_URL = 'https://signed-upload-output'
  OUTPUT_DOWNLOAD_GCS_URL = '/download-output'
  INPUT_SIGNED_DOWNLOAD_URL = 'https://signed-download-input'
  UWORKER_ENV = {'ENVVAR': 'VALUE'}
  TASK_ARGUMENT = 'testcase-id'
  JOB_TYPE = 'libfuzzer_asan'
  INPUT = {'input': 'something'}

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.get_uworker_output_urls',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.serialize_and_upload_uworker_input',
    ])
    self.mock.get_uworker_output_urls.return_value = (
        self.OUTPUT_SIGNED_UPLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL)
    self.mock.serialize_and_upload_uworker_input.return_value = (
        self.INPUT_SIGNED_DOWNLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL)

  def test_tworker_preprocess(self):
    """Tests that tworker_preprocess works as intended."""
    module = mock.MagicMock()
    module.utask_preprocess.return_value = self.INPUT
    result = utasks.tworker_preprocess(module, self.TASK_ARGUMENT,
                                       self.JOB_TYPE, self.UWORKER_ENV)

    module.utask_preprocess.assert_called_with(self.TASK_ARGUMENT,
                                               self.JOB_TYPE, self.UWORKER_ENV)
    self.mock.serialize_and_upload_uworker_input.assert_called_with(
        self.INPUT, self.JOB_TYPE)
    self.assertEqual(
        (self.INPUT_SIGNED_DOWNLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL), result)


class SetUworkerEnvTest(unittest.TestCase):
  """Tests that set_uworker_env works as intended."""
  UWORKER_ENV = {'ENVVAR': 'VALUE', 'ENVVAR2': 'NEWVALUE'}

  def setUp(self):
    helpers.patch_environ(self)

  def test_set_uworker_env(self):
    """Tests that set_uworker_env works."""
    # Test overwriting.
    os.environ['ENVVAR2'] = 'original'
    utasks.set_uworker_env(self.UWORKER_ENV)
    self.assertEqual(os.environ['ENVVAR'], 'VALUE')
    self.assertEqual(os.environ['ENVVAR2'], 'NEWVALUE')


class UworkerMainTest(unittest.TestCase):
  """Tests that uworker_main works as intended."""
  UWORKER_ENV = {'ENVVAR': 'VALUE', 'ENVVAR2': 'NEWVALUE'}
  UWORKER_OUTPUT_UPLOAD_URL = 'https://uworker_output_upload_url'

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.download_and_deserialize_uworker_input',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.serialize_and_upload_uworker_output',
    ])
    uworker_input = {
        'inputarg': 'input-val',
        'uworker_env': self.UWORKER_ENV,
        'uworker_output_upload_url': self.UWORKER_OUTPUT_UPLOAD_URL
    }
    self.mock.download_and_deserialize_uworker_input.return_value = (
        uworker_input)

  def test_uworker_main(self):
    """Tests that uworker_main works as intended."""
    module = mock.MagicMock()
    uworker_output = {'revision': 1, 'testcase': None}
    module.utask_main.return_value = uworker_io.UworkerOutput(**uworker_output)
    input_download_url = 'http://input'
    utasks.uworker_main(module, input_download_url)
    module.utask_main.assert_called_with(inputarg='input-val')

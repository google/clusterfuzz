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
from clusterfuzz._internal.bot.tasks.utasks import analyze_task
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.bot.tasks.utasks import uworker_io2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class TworkerPreprocessTest(unittest.TestCase):
  """Tests that tworker_preprocess works as intended."""
  OUTPUT_SIGNED_UPLOAD_URL = 'https://signed-upload-output'
  OUTPUT_DOWNLOAD_GCS_URL = '/download-output'
  INPUT_SIGNED_DOWNLOAD_URL = 'https://signed-download-input'
  UWORKER_ENV = {'ENVVAR': 'VALUE'}
  TASK_ARGUMENT = 'testcase-id'
  JOB_TYPE = 'libfuzzer_asan'

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.get_uworker_output_urls',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.serialize_and_upload_uworker_input',
    ])
    self.mock.get_uworker_output_urls.return_value = (
        self.OUTPUT_SIGNED_UPLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL)
    self.mock.serialize_and_upload_uworker_input.return_value = (
        self.INPUT_SIGNED_DOWNLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL)
    self.uworker_input = uworker_io.UworkerInput(job_type='something')

  def test_tworker_preprocess(self):
    """Tests that tworker_preprocess works as intended."""
    module = mock.MagicMock()
    module.utask_preprocess.return_value = self.uworker_input
    module.__name__ = 'mock_task'
    result = utasks.tworker_preprocess(module, self.TASK_ARGUMENT,
                                       self.JOB_TYPE, self.UWORKER_ENV)

    module.utask_preprocess.assert_called_with(self.TASK_ARGUMENT,
                                               self.JOB_TYPE, self.UWORKER_ENV)
    self.mock.serialize_and_upload_uworker_input.assert_called_with(
        self.uworker_input)
    self.assertEqual(
        (self.INPUT_SIGNED_DOWNLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL), result)

  def test_return_none(self):
    module = mock.MagicMock()
    module.utask_preprocess.return_value = None
    self.assertIsNone(
        utasks.tworker_preprocess(module, self.TASK_ARGUMENT, self.JOB_TYPE,
                                  self.UWORKER_ENV))
    self.assertIsNone(
        utasks.tworker_preprocess_no_io(module, self.TASK_ARGUMENT,
                                        self.JOB_TYPE, self.UWORKER_ENV))


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


@test_utils.with_cloud_emulators('datastore')
class UworkerMainTest(unittest.TestCase):
  """Tests that uworker_main works as intended."""
  UWORKER_ENV = {'ENVVAR': 'VALUE', 'ENVVAR2': 'NEWVALUE'}
  UWORKER_OUTPUT_UPLOAD_URL = 'https://uworker_output_upload_url'

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.download_signed_url',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.serialize_and_upload_uworker_output',
        'clusterfuzz._internal.bot.tasks.utasks.get_utask_module',
    ])
    self.module = mock.MagicMock()
    self.mock.get_utask_module.return_value = self.module

  def test_uworker_main(self):
    """Tests that uworker_main works as intended."""
    uworker_input = uworker_io.UworkerInput(
        original_job_type='original_job_type-value',
        uworker_env=self.UWORKER_ENV,
        uworker_output_upload_url=self.UWORKER_OUTPUT_UPLOAD_URL,
    )
    self.mock.download_signed_url.return_value = uworker_io.serialize_uworker_input(
        uworker_input)

    self.module.utask_main.return_value = uworker_io.UworkerOutput(
        testcase=None,
        crash_time=70.1,
    )

    utasks.uworker_main('http://input')

    self.module.utask_main.assert_called_once()
    [[main_input], []] = self.module.utask_main.call_args
    self.assertIsInstance(main_input, uworker_io.DeserializedUworkerMsg)
    self.assertEqual(main_input.original_job_type, 'original_job_type-value')
    with self.assertRaises(AttributeError):
      main_input.uworker_env  # pylint: disable=pointless-statement
    with self.assertRaises(AttributeError):
      main_input.uworker_output_upload_url  # pylint: disable=pointless-statement

  def test_uworker_main_io2(self):
    """Verifies that `uworker_io2` deserialization is used for analyze task."""
    uworker_input = uworker_io.UworkerInput(
        testcase=test_utils.create_generic_testcase(),
        original_job_type='original_job_type-value',
        uworker_env=self.UWORKER_ENV,
        uworker_output_upload_url=self.UWORKER_OUTPUT_UPLOAD_URL,
        module_name=analyze_task.__name__,
    )
    self.mock.download_signed_url.return_value = uworker_io.serialize_uworker_input(
        uworker_input)

    self.module.utask_main.return_value = uworker_io.UworkerOutput(
        testcase=None,
        crash_time=70.1,
    )

    utasks.uworker_main('http://input')

    self.module.utask_main.assert_called_once_with(
        uworker_io2.Input(
            testcase=uworker_input.testcase,
            testcase_id='',
            testcase_upload_metadata=None,
            job_type='',
            original_job_type='original_job_type-value',
            uworker_env=self.UWORKER_ENV,
            uworker_output_upload_url=self.UWORKER_OUTPUT_UPLOAD_URL,
            fuzzer_name='',
            module_name=analyze_task.__name__,
            setup_input=None,
            analyze_task_input=None,
        ))


class GetUtaskModuleTest(unittest.TestCase):

  def test_get_utask_module(self):
    module_name = 'clusterfuzz._internal.bot.tasks.utasks.analyze_task'
    self.assertEqual(utasks.get_utask_module(module_name), analyze_task)
    module_name = analyze_task.__name__
    self.assertEqual(utasks.get_utask_module(module_name), analyze_task)

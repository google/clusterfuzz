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
import time
import unittest
from unittest import mock

from google.protobuf import timestamp_pb2

from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.bot.tasks.utasks import analyze_task
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers


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

  def test_tworker_preprocess(self):
    """Tests that tworker_preprocess works as intended."""
    module = mock.MagicMock(__name__='tasks.analyze_task')
    module.__name__ = 'mock_task'

    uworker_input = uworker_msg_pb2.Input(job_type='something')
    module.utask_preprocess.return_value = uworker_input

    start_time_ns = time.time_ns()

    result = utasks.tworker_preprocess(module, self.TASK_ARGUMENT,
                                       self.JOB_TYPE, self.UWORKER_ENV)

    end_time_ns = time.time_ns()

    module.utask_preprocess.assert_called_with(self.TASK_ARGUMENT,
                                               self.JOB_TYPE, self.UWORKER_ENV)

    self.mock.serialize_and_upload_uworker_input.assert_called_with(uworker_input)
    self.assertGreaterEqual(uworker_input.preprocess_start_time.ToNanoseconds(), start_time_ns)
    self.assertLessEqual(uworker_input.preprocess_start_time.ToNanoseconds(), end_time_ns)

    durations = monitoring_metrics.UTASK_E2E_DURATION_SECS.get({
        'task': 'mock',
        'job': self.JOB_TYPE,
        'subtask': 'preprocess',
        'mode': 'batch',
        'platform': 'LINUX',
    })
    self.assertEqual(durations.count, 1)
    self.assertLess(durations.sum * 10**9, end_time_ns - uworker_input.preprocess_start_time.ToNanoseconds())

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


class UworkerMainTest(unittest.TestCase):
  """Tests that uworker_main works as intended."""
  UWORKER_ENV = {'ENVVAR': 'VALUE', 'ENVVAR2': 'NEWVALUE'}
  UWORKER_OUTPUT_UPLOAD_URL = 'https://uworker_output_upload_url'

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.download_and_deserialize_uworker_input',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.serialize_and_upload_uworker_output',
        'clusterfuzz._internal.bot.tasks.utasks.get_utask_module',
    ])
    self.module = mock.MagicMock(__name__='tasks.analyze_task')
    self.mock.get_utask_module.return_value = self.module

  def test_uworker_main(self):
    """Tests that uworker_main works as intended."""
    start_time_ns = time.time_ns()
    start_timestamp = timestamp_pb2.Timestamp()
    start_timestamp.FromNanoseconds(start_time_ns)

    uworker_input = uworker_msg_pb2.Input(
        job_type='job_type-value',
        original_job_type='original_job_type-value',
        uworker_env=self.UWORKER_ENV,
        uworker_output_upload_url=self.UWORKER_OUTPUT_UPLOAD_URL,
        preprocess_start_time=start_timestamp,
    )
    self.mock.download_and_deserialize_uworker_input.return_value = (
        uworker_input)

    uworker_output = {
        'crash_time': 70.1,
    }
    self.module.utask_main.return_value = uworker_msg_pb2.Output(
        **uworker_output)
    input_download_url = 'http://input'

    utasks.uworker_main(input_download_url)

    end_time_ns = time.time_ns()

    self.module.utask_main.assert_called_with(uworker_input)

    durations = monitoring_metrics.UTASK_E2E_DURATION_SECS.get({
        'task': 'analyze',
        'job': uworker_input.job_type,
        'subtask': 'uworker_main',
        'mode': 'batch',
        'platform': 'LINUX',
    })
    self.assertEqual(durations.count, 1)
    self.assertLess(durations.sum * 10**9, end_time_ns - start_time_ns)


class GetUtaskModuleTest(unittest.TestCase):

  def test_get_utask_module(self):
    module_name = 'clusterfuzz._internal.bot.tasks.utasks.analyze_task'
    self.assertEqual(utasks.get_utask_module(module_name), analyze_task)
    module_name = analyze_task.__name__
    self.assertEqual(utasks.get_utask_module(module_name), analyze_task)

class TworkerPostprocessTest(unittest.TestCase):
  """Tests that tworker_postprocess works as intended."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.download_and_deserialize_uworker_output',
        'clusterfuzz._internal.bot.tasks.utasks.get_utask_module',
    ])

  def test_success(self):
    download_url = 'https://uworker_output_download_url'
    uworker_output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            job_type='foo-job',
        ),
    )
    self.mock.download_and_deserialize_uworker_output.return_value = (uworker_output)

    module = mock.MagicMock(__name__='mock_task')
    self.mock.get_utask_module.return_value = module

    start_time_ns = time.time_ns()
    utasks.tworker_postprocess(download_url)
    end_time_ns = time.time_ns()

    self.mock.download_and_deserialize_uworker_output.assert_called_with(download_url)
    module.utask_postprocess.assert_called_with(uworker_output)

    durations = monitoring_metrics.UTASK_E2E_DURATION_SECS.get({
        'task': 'mock',
        'job': 'foo-job',
        'subtask': 'postprocess',
        'mode': 'batch',
        'platform': 'LINUX',
    })
    self.assertEqual(durations.count, 1)
    self.assertLess(durations.sum * 10**9, end_time_ns - start_time_ns)

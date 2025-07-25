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

import datetime
import os
import time
import unittest
from unittest import mock

from google.protobuf import timestamp_pb2
import parameterized

from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.bot.tasks.utasks import analyze_task
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class TworkerPreprocessTest(unittest.TestCase):
  """Tests that tworker_preprocess works as intended."""
  OUTPUT_SIGNED_UPLOAD_URL = 'https://signed-upload-output'
  OUTPUT_DOWNLOAD_GCS_URL = '/download-output'
  INPUT_SIGNED_DOWNLOAD_URL = 'https://signed-download-input'
  UWORKER_ENV = {'ENVVAR': 'VALUE'}
  TASK_ARGUMENT = '1'  # testcase_id
  JOB_TYPE = 'libfuzzer_asan'

  def setUp(self):
    monitor.metrics_store().reset_for_testing()
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks._get_execution_mode',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.get_uworker_output_urls',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.serialize_and_upload_uworker_input',
        'clusterfuzz._internal.metrics.events.emit',
        'clusterfuzz._internal.metrics.events._get_datetime_now',
    ])
    self.mock._get_datetime_now.return_value = datetime.datetime(2025, 1, 1)  # pylint: disable=protected-access
    self.mock.get_uworker_output_urls.return_value = (
        self.OUTPUT_SIGNED_UPLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL)
    self.mock.serialize_and_upload_uworker_input.return_value = (
        self.INPUT_SIGNED_DOWNLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL)
    os.environ['CF_TASK_ID'] = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    os.environ['CF_TASK_NAME'] = 'mock_task'

  def tearDown(self):
    task_utils.TESTCASE_BASED_TASKS.discard('mock')

  @parameterized.parameterized.expand([utasks.Mode.BATCH, utasks.Mode.SWARMING])
  def test_tworker_preprocess(self, execution_mode: utasks.Mode):
    """Tests that tworker_preprocess works as intended."""
    module = mock.MagicMock(__name__='mock_task')
    task_utils.TESTCASE_BASED_TASKS.add('mock')

    self.mock._get_execution_mode.return_value = execution_mode  # pylint: disable=protected-access

    uworker_input = uworker_msg_pb2.Input(job_type='something')
    module.utask_preprocess.return_value = uworker_input

    start_time_ns = time.time_ns()

    result = utasks.tworker_preprocess(module, self.TASK_ARGUMENT,
                                       self.JOB_TYPE, self.UWORKER_ENV)

    end_time_ns = time.time_ns()

    module.utask_preprocess.assert_called_with(self.TASK_ARGUMENT,
                                               self.JOB_TYPE, self.UWORKER_ENV)

    self.mock.serialize_and_upload_uworker_input.assert_called_with(
        uworker_input)
    self.assertGreaterEqual(uworker_input.preprocess_start_time.ToNanoseconds(),
                            start_time_ns)
    self.assertLessEqual(uworker_input.preprocess_start_time.ToNanoseconds(),
                         end_time_ns)

    metric_labels = {
        'task': 'mock',
        'job': self.JOB_TYPE,
        'subtask': 'preprocess',
        'mode': execution_mode.value,
        'platform': 'LINUX',
    }

    durations = monitoring_metrics.UTASK_SUBTASK_DURATION_SECS.get(
        metric_labels)
    self.assertEqual(durations.count, 1)
    self.assertLess(durations.sum * 10**9, end_time_ns - start_time_ns)

    e2e_durations = monitoring_metrics.UTASK_SUBTASK_E2E_DURATION_SECS.get(
        metric_labels)
    self.assertEqual(e2e_durations.count, 1)
    self.assertLess(
        e2e_durations.sum * 10**9,
        end_time_ns - uworker_input.preprocess_start_time.ToNanoseconds())

    self.assertEqual(
        (self.INPUT_SIGNED_DOWNLOAD_URL, self.OUTPUT_DOWNLOAD_GCS_URL), result)

    # Asserts for task execution event.
    task_event = events.TaskExecutionEvent(
        testcase_id=int(self.TASK_ARGUMENT),
        task_stage=utasks._Subtask.PREPROCESS.value,  # pylint: disable=protected-access
        task_status=events.TaskStatus.STARTED,
        task_outcome=None,
        task_job=self.JOB_TYPE,
        task_fuzzer=None)
    # Asserts task id/name fields were retrieved in base event.
    self.assertEqual(task_event.task_name, 'mock_task')
    self.assertEqual(task_event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.mock.emit.assert_called_once_with(task_event)

  def test_return_none(self):
    """Tests tworker_preprocess works as expected if utask returns none."""
    module = mock.MagicMock(__name__='mock_task')
    module.utask_preprocess.return_value = None
    task_utils.TESTCASE_BASED_TASKS.add('mock')

    self.assertIsNone(
        utasks.tworker_preprocess(module, self.TASK_ARGUMENT, self.JOB_TYPE,
                                  self.UWORKER_ENV))
    # Asserts for task execution event.
    task_event = events.TaskExecutionEvent(
        testcase_id=int(self.TASK_ARGUMENT),
        task_stage=utasks._Subtask.PREPROCESS.value,  # pylint: disable=protected-access
        task_status=events.TaskStatus.EXCEPTION,
        task_outcome=events.TaskOutcome.PREPROCESS_NO_RETURN,
        task_job=self.JOB_TYPE,
        task_fuzzer=None)
    # Asserts task id/name fields were retrieved in base event.
    self.assertEqual(task_event.task_name, 'mock_task')
    self.assertEqual(task_event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.mock.emit.assert_called_once_with(task_event)
    self.mock.emit.reset_mock()

    self.assertIsNone(
        utasks.tworker_preprocess_no_io(module, self.TASK_ARGUMENT,
                                        self.JOB_TYPE, self.UWORKER_ENV))
    # Asserts for task execution event.
    task_event = events.TaskExecutionEvent(
        testcase_id=int(self.TASK_ARGUMENT),
        task_stage=utasks._Subtask.PREPROCESS.value,  # pylint: disable=protected-access
        task_status=events.TaskStatus.EXCEPTION,
        task_outcome=events.TaskOutcome.PREPROCESS_NO_RETURN,
        task_job=self.JOB_TYPE,
        task_fuzzer=None)
    # Asserts task id/name fields were retrieved in base event.
    self.assertEqual(task_event.task_name, 'mock_task')
    self.assertEqual(task_event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.mock.emit.assert_called_once_with(task_event)


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
    monitor.metrics_store().reset_for_testing()
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks._get_execution_mode',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.download_and_deserialize_uworker_input',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.serialize_and_upload_uworker_output',
        'clusterfuzz._internal.bot.tasks.utasks.get_utask_module',
        'clusterfuzz._internal.system.environment.is_swarming_bot',
        'clusterfuzz._internal.metrics.events.emit',
    ])
    self.module = mock.MagicMock(__name__='tasks.analyze_task')
    self.mock.get_utask_module.return_value = self.module

  @parameterized.parameterized.expand([utasks.Mode.BATCH, utasks.Mode.SWARMING])
  def test_uworker_main(self, execution_mode: utasks.Mode):
    """Tests that uworker_main works as intended."""
    start_time_ns = time.time_ns()

    if execution_mode == utasks.Mode.SWARMING:
      self.mock.is_swarming_bot.return_value = True  # pylint: disable=protected-access
    else:
      self.mock.is_swarming_bot.return_value = False

    preprocess_start_time_ns = start_time_ns - 42 * 10**9  # In the past.
    preprocess_start_timestamp = timestamp_pb2.Timestamp()
    preprocess_start_timestamp.FromNanoseconds(preprocess_start_time_ns)

    uworker_input = uworker_msg_pb2.Input(
        job_type='job_type-value',
        variant_task_input=uworker_msg_pb2.VariantTaskInput(
            original_job_type='original_job_type-value'),
        uworker_env=self.UWORKER_ENV,
        uworker_output_upload_url=self.UWORKER_OUTPUT_UPLOAD_URL,
        preprocess_start_time=preprocess_start_timestamp,
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

    metric_labels = {
        'task': 'analyze',
        'job': uworker_input.job_type,
        'subtask': 'uworker_main',
        'mode': execution_mode.value,
        'platform': 'LINUX',
    }

    durations = monitoring_metrics.UTASK_SUBTASK_DURATION_SECS.get(
        metric_labels)
    self.assertEqual(durations.count, 1)
    self.assertLess(durations.sum * 10**9, end_time_ns - start_time_ns)

    e2e_durations = monitoring_metrics.UTASK_SUBTASK_E2E_DURATION_SECS.get(
        metric_labels)
    self.assertEqual(e2e_durations.count, 1)
    self.assertLess(e2e_durations.sum * 10**9,
                    end_time_ns - preprocess_start_time_ns)
    self.assertGreaterEqual(e2e_durations.sum, 42)

    # Asserts that task events were not emitted from main (as these may cause
    # a permission denied error if running in a untrusted worker).
    self.mock.emit.assert_not_called()


class GetUtaskModuleTest(unittest.TestCase):

  def test_get_utask_module(self):
    module_name = 'clusterfuzz._internal.bot.tasks.utasks.analyze_task'
    self.assertEqual(utasks.get_utask_module(module_name), analyze_task)
    module_name = analyze_task.__name__
    self.assertEqual(utasks.get_utask_module(module_name), analyze_task)


@test_utils.with_cloud_emulators('datastore')
class TworkerPostprocessTest(unittest.TestCase):
  """Tests that tworker_postprocess works as intended."""

  def setUp(self):
    monitor.metrics_store().reset_for_testing()
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks._get_execution_mode',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.download_and_deserialize_uworker_output',
        'clusterfuzz._internal.bot.tasks.utasks.get_utask_module',
        'clusterfuzz._internal.metrics.events.emit',
        'clusterfuzz._internal.metrics.events._get_datetime_now',
    ])
    self.mock._get_datetime_now.return_value = datetime.datetime(2025, 1, 1)  # pylint: disable=protected-access
    os.environ['CF_TASK_ID'] = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    os.environ['CF_TASK_NAME'] = 'mock_task'

  def tearDown(self):
    task_utils.FUZZER_BASED_TASKS.discard('mock')

  @parameterized.parameterized.expand([utasks.Mode.BATCH, utasks.Mode.SWARMING])
  def test_success(self, execution_mode: utasks.Mode):
    """Tests that if utask_postprocess suceeds, uworker_postprocess does too.
    """
    self.mock._get_execution_mode.return_value = execution_mode  # pylint: disable=protected-access
    download_url = 'https://uworker_output_download_url'

    start_time_ns = time.time_ns()

    preprocess_start_time_ns = start_time_ns - 42 * 10**9  # In the past.
    preprocess_start_timestamp = timestamp_pb2.Timestamp()
    preprocess_start_timestamp.FromNanoseconds(preprocess_start_time_ns)

    uworker_output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            fuzzer_name='fuzzer_test',
            job_type='foo-job',
            preprocess_start_time=preprocess_start_timestamp),)
    self.mock.download_and_deserialize_uworker_output.return_value = (
        uworker_output)

    module = mock.MagicMock(__name__='mock_task')
    self.mock.get_utask_module.return_value = module
    task_utils.FUZZER_BASED_TASKS.add('mock')

    utasks.tworker_postprocess(download_url)
    end_time_ns = time.time_ns()

    self.mock.download_and_deserialize_uworker_output.assert_called_with(
        download_url)
    module.utask_postprocess.assert_called_with(uworker_output)

    metric_labels = {
        'task': 'mock',
        'job': 'foo-job',
        'subtask': 'postprocess',
        'mode': execution_mode.value,
        'platform': 'LINUX',
    }

    durations = monitoring_metrics.UTASK_SUBTASK_DURATION_SECS.get(
        metric_labels)
    self.assertEqual(durations.count, 1)
    self.assertLess(durations.sum * 10**9, end_time_ns - start_time_ns)

    e2e_durations = monitoring_metrics.UTASK_SUBTASK_E2E_DURATION_SECS.get(
        metric_labels)
    self.assertEqual(e2e_durations.count, 1)
    self.assertLess(e2e_durations.sum * 10**9,
                    end_time_ns - preprocess_start_time_ns)
    self.assertGreaterEqual(e2e_durations.sum, 42)

    # Asserts for task execution event.
    self.assertEqual(self.mock.emit.call_count, 2)
    task_finished_event = events.TaskExecutionEvent(
        testcase_id=None,
        task_fuzzer='fuzzer_test',
        task_stage=utasks._Subtask.POSTPROCESS.value,  # pylint: disable=protected-access
        task_status=events.TaskStatus.POST_STARTED,
        task_outcome=uworker_msg_pb2.ErrorType.Name(0),
        task_job='foo-job')
    task_post_event = events.TaskExecutionEvent(
        testcase_id=None,
        task_fuzzer='fuzzer_test',
        task_stage=utasks._Subtask.POSTPROCESS.value,  # pylint: disable=protected-access
        task_status=events.TaskStatus.POST_COMPLETED,
        task_outcome=uworker_msg_pb2.ErrorType.Name(0),
        task_job='foo-job')
    # Asserts task id/name fields were retrieved in base event.
    self.assertEqual(task_finished_event.task_name, 'mock_task')
    self.assertEqual(task_finished_event.task_id,
                     'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(task_post_event.task_name, 'mock_task')
    self.assertEqual(task_post_event.task_id,
                     'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')

    self.mock.emit.assert_any_call(task_finished_event)
    self.mock.emit.assert_any_call(task_post_event)

  @parameterized.parameterized.expand([utasks.Mode.BATCH, utasks.Mode.SWARMING])
  def test_event_emit_during_exception(self, execution_mode: utasks.Mode):
    """Test the task event emit when an unhandle exception occurs."""
    self.mock._get_execution_mode.return_value = execution_mode  # pylint: disable=protected-access
    download_url = 'https://uworker_output_download_url'
    preprocess_start_timestamp = timestamp_pb2.Timestamp()
    preprocess_start_timestamp.FromNanoseconds(time.time_ns())

    uworker_output = uworker_msg_pb2.Output(
        uworker_input=uworker_msg_pb2.Input(
            fuzzer_name='fuzzer_test',
            job_type='foo-job',
            preprocess_start_time=preprocess_start_timestamp),)
    self.mock.download_and_deserialize_uworker_output.return_value = (
        uworker_output)

    module = mock.MagicMock(__name__='mock_task')
    self.mock.get_utask_module.return_value = module
    task_utils.FUZZER_BASED_TASKS.add('mock')

    module.utask_postprocess.side_effect = ValueError
    try:
      utasks.tworker_postprocess(download_url)
    except ValueError:
      pass

    self.mock.download_and_deserialize_uworker_output.assert_called_with(
        download_url)
    module.utask_postprocess.assert_called_with(uworker_output)
    # Asserts for task execution event.
    self.assertEqual(self.mock.emit.call_count, 2)
    task_finished_event = events.TaskExecutionEvent(
        testcase_id=None,
        task_fuzzer='fuzzer_test',
        task_stage=utasks._Subtask.POSTPROCESS.value,  # pylint: disable=protected-access
        task_status=events.TaskStatus.POST_STARTED,
        task_outcome=uworker_msg_pb2.ErrorType.Name(0),
        task_job='foo-job')
    task_post_event = events.TaskExecutionEvent(
        testcase_id=None,
        task_fuzzer='fuzzer_test',
        task_stage=utasks._Subtask.POSTPROCESS.value,  # pylint: disable=protected-access
        task_status=events.TaskStatus.EXCEPTION,
        task_outcome=events.TaskOutcome.UNHANDLED_EXCEPTION,
        task_job='foo-job')
    # Asserts task id/name fields were retrieved in base event.
    self.assertEqual(task_finished_event.task_name, 'mock_task')
    self.assertEqual(task_finished_event.task_id,
                     'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(task_post_event.task_name, 'mock_task')
    self.assertEqual(task_post_event.task_id,
                     'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')

    self.mock.emit.assert_any_call(task_finished_event)
    self.mock.emit.assert_any_call(task_post_event)

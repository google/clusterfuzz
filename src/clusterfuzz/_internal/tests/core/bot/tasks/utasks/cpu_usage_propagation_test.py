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
"""Tests for CPU usage propagation in utasks."""

import unittest
from unittest import mock

from clusterfuzz._internal.bot.tasks.utasks import tworker_postprocess
from clusterfuzz._internal.bot.tasks.utasks import uworker_main
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

@test_utils.with_cloud_emulators('datastore')
class CpuUsagePropagationTest(unittest.TestCase):
  """Tests for CPU usage propagation."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.download_and_deserialize_uworker_input',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.serialize_and_upload_uworker_output',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.download_and_deserialize_uworker_output',
        'clusterfuzz._internal.bot.tasks.utasks.get_utask_module',
        'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module',
        'clusterfuzz._internal.metrics.logs.error',
    ])

    self.job_name = 'test_job'
    self.job = data_types.Job(name=self.job_name, required_cpu=1.0)
    self.job.put()

    self.uworker_input = uworker_msg_pb2.Input(
        job_type=self.job_name,
        module_name='test_module',
    )
    self.mock.download_and_deserialize_uworker_input.return_value = self.uworker_input
    self.mock.get_command_from_module.return_value = 'fuzz'

    self.utask_module = mock.MagicMock()
    self.utask_module.__name__ = 'test_module'
    self.mock.get_utask_module.return_value = self.utask_module

  def test_uworker_main_propagation(self):
    """Test that uworker_main reads and propagates CPU usage."""
    environment.set_value('IS_K8S_ENV', 'True')

    with mock.patch('os.path.exists', return_value=True), \
         mock.patch('builtins.open', mock.mock_open(read_data='2.5')):

      uworker_output = uworker_msg_pb2.Output(error_type=uworker_msg_pb2.ErrorType.NO_ERROR)
      self.utask_module.utask_main.return_value = uworker_output

      uworker_main('http://input')

      # Check that serialize_and_upload_uworker_output was called with the right cpu_usage_max
      args, _ = self.mock.serialize_and_upload_uworker_output.call_args
      output = args[0]
      self.assertEqual(output.cpu_usage_max, '2.5')

  def test_tworker_postprocess_update(self):
    """Test that tworker_postprocess updates the Job entity."""
    uworker_output = uworker_msg_pb2.Output(
        cpu_usage_max='3.0',
        uworker_input=self.uworker_input,
    )
    self.mock.download_and_deserialize_uworker_output.return_value = uworker_output

    tworker_postprocess('http://output')

    updated_job = data_types.Job.query(data_types.Job.name == self.job_name).get()
    self.assertEqual(updated_job.required_cpu, 3.0)

  def test_tworker_postprocess_no_update_if_lower(self):
    """Test that tworker_postprocess does not update if new value is lower."""
    self.job.required_cpu = 5.0
    self.job.put()

    uworker_output = uworker_msg_pb2.Output(
        cpu_usage_max='3.0',
        uworker_input=self.uworker_input,
    )
    self.mock.download_and_deserialize_uworker_output.return_value = uworker_output

    tworker_postprocess('http://output')

    updated_job = data_types.Job.query(data_types.Job.name == self.job_name).get()
    self.assertEqual(updated_job.required_cpu, 5.0)

if __name__ == '__main__':
  unittest.main()

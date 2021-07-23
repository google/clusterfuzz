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
"""Tests for remote_process."""

import unittest

import mock

from clusterfuzz._internal.bot.untrusted_runner import remote_process
from clusterfuzz._internal.bot.untrusted_runner import remote_process_host
from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class RemoteProcessTest(unittest.TestCase):
  """RemoteProcess tests."""

  def setUp(self):
    test_helpers.patch(
        self, ['clusterfuzz._internal.system.process_handler.run_process'])

  @mock.patch.object(new_process.ProcessRunner, 'run_and_wait')
  def test_run_and_wait(self, mock_run_and_wait):
    """Test remote_process.run_and_wait()."""
    process_result = new_process.ProcessResult(['command', '123'], 0, b'output',
                                               60.0, False)

    mock_run_and_wait.return_value = process_result

    request = untrusted_runner_pb2.RunAndWaitRequest()
    request.executable_path = '/path'
    request.default_args.extend(['-default_arg'])
    request.additional_args.extend(['-additional_arg'])
    request.timeout = 100.0
    request.terminate_before_kill = True
    request.terminate_wait_time = 10.0
    request.input_data = b'input'
    request.max_stdout_len = 1337
    request.popen_args.shell = True
    request.popen_args.env.update({'VAR': 'VAL'})
    request.popen_args.env_is_set = True
    request.popen_args.cwd = '/'

    response = remote_process.run_and_wait(request, None)
    result = remote_process_host.process_result_from_proto(response.result)

    mock_run_and_wait.assert_called_with(
        additional_args=['-additional_arg'],
        timeout=100.0,
        terminate_before_kill=True,
        terminate_wait_time=10.0,
        input_data=b'input',
        max_stdout_len=1337,
        cwd='/',
        env={'VAR': 'VAL'},
        shell=True)

    self.assertEqual(result.command, process_result.command)
    self.assertEqual(result.return_code, process_result.return_code)
    self.assertEqual(result.output, process_result.output)
    self.assertEqual(result.time_executed, process_result.time_executed)
    self.assertEqual(result.timed_out, process_result.timed_out)

  @mock.patch.object(new_process.ProcessRunner, 'run_and_wait')
  def test_run_and_wait_none_env(self, mock_run_and_wait):
    """Test remote_process.run_and_wait() with a None env."""
    process_result = new_process.ProcessResult(['command', '123'], 0, b'output',
                                               60.0, False)

    mock_run_and_wait.return_value = process_result

    request = untrusted_runner_pb2.RunAndWaitRequest()
    request.executable_path = '/path'
    request.popen_args.env_is_set = False

    remote_process.run_and_wait(request, None)
    mock_run_and_wait.assert_called_with(additional_args=[], env=None)

  @mock.patch.object(new_process.ProcessRunner, 'run_and_wait')
  def test_run_and_wait_empty_env(self, mock_run_and_wait):
    """Test remote_process.run_and_wait() with an empty env."""
    process_result = new_process.ProcessResult(['command', '123'], 0, b'output',
                                               60.0, False)

    mock_run_and_wait.return_value = process_result

    request = untrusted_runner_pb2.RunAndWaitRequest()
    request.executable_path = '/path'
    request.popen_args.env_is_set = True

    remote_process.run_and_wait(request, None)
    mock_run_and_wait.assert_called_with(additional_args=[], env={})

  def test_run_process(self):
    """Test remote_process.run_process."""
    request = untrusted_runner_pb2.RunProcessRequest()
    request.cmdline = 'cmd arg'
    request.timeout = 20
    request.testcase_run = True
    request.gestures.extend(['gesture', 'gesture2'])
    request.env_copy.update({'VAR': 'VAL'})

    self.mock.run_process.return_value = (0, 10.0, 'output')

    response = remote_process.run_process(request, None)
    self.assertEqual(response.return_code, 0)
    self.assertEqual(response.execution_time, 10.0)
    self.assertEqual(response.output, 'output')

    self.mock.run_process.assert_called_with(
        cmdline='cmd arg',
        env_copy={'VAR': 'VAL'},
        gestures=['gesture', 'gesture2'],
        testcase_run=True,
        timeout=20)

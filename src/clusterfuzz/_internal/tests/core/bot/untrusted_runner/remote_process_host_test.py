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

from clusterfuzz._internal.bot.untrusted_runner import remote_process
from clusterfuzz._internal.bot.untrusted_runner import remote_process_host
from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class RemoteProcessHostTest(unittest.TestCase):
  """RemoteProcessHost tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.untrusted_runner.host.stub',
    ])

  def test_run_and_wait(self):
    """Test RemoteProcessRunner.run_and_wait()."""
    process_result = new_process.ProcessResult(['command', '123'], 0, b'output',
                                               60.0, False)

    self.mock.stub().RunAndWait.return_value = (
        untrusted_runner_pb2.RunAndWaitResponse(
            result=remote_process.process_result_to_proto(process_result)))

    runner = remote_process_host.RemoteProcessRunner('/executable',
                                                     ['-default_arg'])
    result = runner.run_and_wait(
        ['-additional_arg'],
        100.0,
        True,
        10.0,
        b'input',
        shell=True,
        env={'ASAN_OPTIONS': 'asan_options'},
        cwd='/',
        max_stdout_len=1337)
    result = remote_process_host.process_result_from_proto(result)

    request = self.mock.stub().RunAndWait.call_args[0][0]
    self.assertEqual('/executable', request.executable_path)
    self.assertEqual(['-default_arg'], request.default_args)
    self.assertEqual(['-additional_arg'], request.additional_args)
    self.assertEqual(100.0, request.timeout)
    self.assertTrue(request.terminate_before_kill)
    self.assertEqual(10.0, request.terminate_wait_time)
    self.assertEqual(b'input', request.input_data)
    self.assertFalse(request.popen_args.HasField('bufsize'))
    self.assertFalse(request.popen_args.HasField('executable'))
    self.assertTrue(request.popen_args.shell)
    self.assertEqual('/', request.popen_args.cwd)
    self.assertEqual({'ASAN_OPTIONS': 'asan_options'}, request.popen_args.env)
    self.assertTrue(request.popen_args.env_is_set)
    self.assertEqual(1337, request.max_stdout_len)

    self.assertEqual(result.command, process_result.command)
    self.assertEqual(result.return_code, process_result.return_code)
    self.assertEqual(result.output, process_result.output)
    self.assertEqual(result.time_executed, process_result.time_executed)
    self.assertEqual(result.timed_out, process_result.timed_out)

  def test_run_and_wait_none_env(self):
    """Test RemoteProcessRunner.run_and_wait() with a None env."""
    process_result = new_process.ProcessResult(['command', '123'], 0, b'output',
                                               60.0, False)

    self.mock.stub().RunAndWait.return_value = (
        untrusted_runner_pb2.RunAndWaitResponse(
            result=remote_process.process_result_to_proto(process_result)))

    runner = remote_process_host.RemoteProcessRunner('/executable',
                                                     ['-default_arg'])
    result = runner.run_and_wait()
    result = remote_process_host.process_result_from_proto(result)

    request = self.mock.stub().RunAndWait.call_args[0][0]
    self.assertEqual('/executable', request.executable_path)
    self.assertEqual(['-default_arg'], request.default_args)
    self.assertEqual([], request.additional_args)
    self.assertFalse(request.HasField('timeout'))
    self.assertFalse(request.terminate_before_kill)
    self.assertFalse(request.HasField('terminate_wait_time'))
    self.assertFalse(request.HasField('input_data'))
    self.assertFalse(request.popen_args.HasField('bufsize'))
    self.assertFalse(request.popen_args.HasField('executable'))
    self.assertFalse(request.popen_args.HasField('shell'))
    self.assertFalse(request.popen_args.HasField('cwd'))
    self.assertEqual({}, request.popen_args.env)
    self.assertFalse(request.popen_args.env_is_set)

    self.assertEqual(result.command, process_result.command)
    self.assertEqual(result.return_code, process_result.return_code)
    self.assertEqual(result.output, process_result.output)
    self.assertEqual(result.time_executed, process_result.time_executed)
    self.assertEqual(result.timed_out, process_result.timed_out)

  def test_run_and_wait_empty_env(self):
    """Test RemoteProcessRunner.run_and_wait() with an empty env."""
    process_result = new_process.ProcessResult(['command', '123'], 0, b'output',
                                               60.0, False)

    self.mock.stub().RunAndWait.return_value = (
        untrusted_runner_pb2.RunAndWaitResponse(
            result=remote_process.process_result_to_proto(process_result)))

    runner = remote_process_host.RemoteProcessRunner('/executable',
                                                     ['-default_arg'])
    result = runner.run_and_wait(env={})
    result = remote_process_host.process_result_from_proto(result)

    request = self.mock.stub().RunAndWait.call_args[0][0]
    self.assertEqual('/executable', request.executable_path)
    self.assertEqual(['-default_arg'], request.default_args)
    self.assertEqual([], request.additional_args)
    self.assertFalse(request.HasField('timeout'))
    self.assertFalse(request.terminate_before_kill)
    self.assertFalse(request.HasField('terminate_wait_time'))
    self.assertFalse(request.HasField('input_data'))
    self.assertFalse(request.popen_args.HasField('bufsize'))
    self.assertFalse(request.popen_args.HasField('executable'))
    self.assertFalse(request.popen_args.HasField('shell'))
    self.assertFalse(request.popen_args.HasField('cwd'))
    self.assertEqual({}, request.popen_args.env)
    self.assertTrue(request.popen_args.env_is_set)

    self.assertEqual(result.command, process_result.command)
    self.assertEqual(result.return_code, process_result.return_code)
    self.assertEqual(result.output, process_result.output)
    self.assertEqual(result.time_executed, process_result.time_executed)
    self.assertEqual(result.timed_out, process_result.timed_out)

  def test_run_process(self):
    """Test remote run_process."""
    self.mock.stub().RunProcess.return_value = (
        untrusted_runner_pb2.RunProcessResponse(
            return_code=0, execution_time=10.0, output='output'))

    return_code, execution_time, output = remote_process_host.run_process(
        '/executable',
        current_working_directory='/',
        need_shell=True,
        timeout=10,
        env_copy={'VAR': 'VAL'},
        gestures=['1', '2'])

    self.assertEqual(return_code, 0)
    self.assertEqual(execution_time, 10.0)
    self.assertEqual(output, 'output')

    return_code, execution_time, output = remote_process_host.run_process(
        '/executable',
        current_working_directory='/',
        need_shell=True,
        timeout=10.0,
        env_copy={'VAR': 'VAL'},
        gestures=['1', '2'])

    self.assertEqual(return_code, 0)
    self.assertEqual(execution_time, 10.0)
    self.assertEqual(output, 'output')

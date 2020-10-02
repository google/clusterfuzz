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
"""Remote process host (client)."""

import os
import subprocess

from . import environment
from . import host

from protos import untrusted_runner_pb2
from system import new_process
from system import process_handler


def process_result_from_proto(process_result_proto):
  """Convert ProcessResult proto to new_process.ProcessResult."""
  return new_process.ProcessResult(
      process_result_proto.command, process_result_proto.return_code,
      process_result_proto.output, process_result_proto.time_executed,
      process_result_proto.timed_out)


def run_process(cmdline,
                current_working_directory=None,
                timeout=process_handler.DEFAULT_TEST_TIMEOUT,
                need_shell=False,
                gestures=None,
                env_copy=None,
                testcase_run=True,
                ignore_children=True):
  """Remote version of process_handler.run_process."""
  request = untrusted_runner_pb2.RunProcessRequest(
      cmdline=cmdline,
      current_working_directory=current_working_directory,
      timeout=timeout,
      need_shell=need_shell,
      testcase_run=testcase_run,
      ignore_children=ignore_children)

  if gestures:
    request.gestures.extend(gestures)

  env = {}
  # run_process's local behaviour is to apply the passed |env_copy| on top of
  # the current environment instead of replacing it completely (like with
  # subprocess).
  environment.set_environment_vars(env, os.environ)
  environment.set_environment_vars(env, env_copy)
  request.env_copy.update(env)

  response = host.stub().RunProcess(request)
  return response.return_code, response.execution_time, response.output


class RemoteProcessRunner(new_process.ProcessRunner):
  """Remote child process."""

  def __init__(self, executable_path, default_args=None):
    super(RemoteProcessRunner, self).__init__(
        executable_path, default_args=default_args)

  def run(self, **kwargs):  # pylint: disable=arguments-differ
    # TODO(ochang): This can be implemented, but isn't necessary yet.
    raise NotImplementedError

  def run_and_wait(self,
                   additional_args=None,
                   timeout=None,
                   terminate_before_kill=False,
                   terminate_wait_time=None,
                   input_data=None,
                   max_stdout_len=None,
                   extra_env=None,
                   stdout=subprocess.PIPE,
                   stderr=subprocess.STDOUT,
                   **popen_args):
    # pylint: disable=unused-argument
    # pylint: disable=arguments-differ
    """Remote version of new_process.ProcessRunner.run_and_wait."""
    assert stdout == subprocess.PIPE
    assert stderr == subprocess.STDOUT

    request = untrusted_runner_pb2.RunAndWaitRequest(
        executable_path=self.executable_path,
        timeout=timeout,
        terminate_before_kill=terminate_before_kill,
        terminate_wait_time=terminate_wait_time,
        input_data=input_data,
        max_stdout_len=max_stdout_len)

    request.default_args.extend(self.default_args)
    request.additional_args.extend(additional_args)

    if 'bufsize' in popen_args:
      request.popen_args.bufsize = popen_args['bufsize']

    if 'executable' in popen_args:
      request.popen_args.executable = popen_args['executable']

    if 'shell' in popen_args:
      request.popen_args.shell = popen_args['shell']

    if 'cwd' in popen_args:
      request.popen_args.cwd = popen_args['cwd']

    passed_env = popen_args.get('env', None)
    if passed_env is not None:
      request.popen_args.env_is_set = True
      # Filter the passed environment to prevent leaking sensitive environment
      # variables if the caller passes e.g. os.environ.copy().
      environment.set_environment_vars(request.popen_args.env, passed_env)

    response = host.stub().RunAndWait(request)
    return process_result_from_proto(response.result)


def terminate_stale_application_instances():
  """Terminate stale application instances."""
  host.stub().TerminateStaleApplicationInstances(
      untrusted_runner_pb2.TerminateStaleApplicationInstancesRequest())

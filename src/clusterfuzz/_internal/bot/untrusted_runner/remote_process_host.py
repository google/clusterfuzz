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

from collections.abc import Mapping
from collections.abc import Sequence
import os
import subprocess
from typing import Any
from typing import cast

from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz._internal.protos import untrusted_runner_pb2_grpc
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import process_handler

from . import environment
from . import host

# pylint:disable=no-member


def process_result_from_proto(
    process_result_proto: untrusted_runner_pb2.ProcessResult,
) -> new_process.ProcessResult:
  """Convert ProcessResult proto to new_process.ProcessResult."""
  return new_process.ProcessResult(
      list(process_result_proto.command),
      process_result_proto.return_code,
      process_result_proto.output,
      process_result_proto.time_executed,
      process_result_proto.timed_out,
  )


def run_process(
    cmdline: str,
    current_working_directory: str | None = None,
    timeout: float = process_handler.DEFAULT_TEST_TIMEOUT,
    need_shell: bool = False,
    gestures: Sequence[str] | None = None,
    env_copy: Mapping[str, str] | None = None,
    testcase_run: bool = True,
    ignore_children: bool = True,
) -> tuple[int | None, float | None, str]:
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

  env: dict[str, str] = {}
  # run_process's local behaviour is to apply the passed |env_copy| on top of
  # the current environment instead of replacing it completely (like with
  # subprocess).
  environment.set_environment_vars(env, os.environ)
  environment.set_environment_vars(env, env_copy)
  request.env_copy.update(env)

  stub = cast(untrusted_runner_pb2_grpc.UntrustedRunnerStub, host.stub())
  response = stub.RunProcess(request)
  return response.return_code, response.execution_time, response.output


class RemoteProcessRunner(new_process.ProcessRunner):
  """Remote child process."""

  def __init__(
      self,
      executable_path: str,
      default_args: Sequence[str] | None = None,
  ) -> None:
    super().__init__(executable_path, default_args=default_args)

  def run(
      self,
      additional_args: Sequence[str] | None = None,
      max_stdout_len: int | None = None,
      extra_env: dict[str, str] | None = None,
      stdin: Any = subprocess.PIPE,
      stdout: Any = subprocess.PIPE,
      stderr: Any = subprocess.STDOUT,
      **popen_args: Any,
  ) -> new_process.ChildProcess:
    # TODO(ochang): This can be implemented, but isn't necessary yet.
    raise NotImplementedError

  def run_and_wait(
      self,
      additional_args: Sequence[str] | None = None,
      timeout: float | None = None,
      terminate_before_kill: bool = False,
      terminate_wait_time: float | None = None,
      input_data: str | bytes | None = None,
      max_stdout_len: int | None = None,
      extra_env: dict[str, str] | None = None,
      stdin: Any = subprocess.PIPE,
      stdout: Any = subprocess.PIPE,
      stderr: Any = subprocess.STDOUT,
      **popen_args: Any,
  ) -> new_process.ProcessResult:
    # pylint: disable=unused-argument
    """Remote version of new_process.ProcessRunner.run_and_wait."""
    assert stdout == subprocess.PIPE
    assert stderr == subprocess.STDOUT

    if isinstance(input_data, str):
      input_data = input_data.encode('utf-8')

    request = untrusted_runner_pb2.RunAndWaitRequest(
        executable_path=self.executable_path,
        timeout=timeout,
        terminate_before_kill=terminate_before_kill,
        terminate_wait_time=terminate_wait_time,
        input_data=input_data,
        max_stdout_len=max_stdout_len)

    request.default_args.extend(self.default_args)
    if additional_args is not None:
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

    stub = cast(untrusted_runner_pb2_grpc.UntrustedRunnerStub, host.stub())
    response = stub.RunAndWait(request)
    return process_result_from_proto(response.result)


def terminate_stale_application_instances() -> None:
  """Terminate stale application instances."""
  stub = cast(untrusted_runner_pb2_grpc.UntrustedRunnerStub, host.stub())
  stub.TerminateStaleApplicationInstances(
      untrusted_runner_pb2.TerminateStaleApplicationInstancesRequest())

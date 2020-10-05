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
"""Remote process implementation."""

from . import protobuf_utils

from metrics import logs
from protos import untrusted_runner_pb2
from system import new_process
from system import process_handler


def process_result_to_proto(process_result):
  """Convert new_process.ProcessResult to proto."""
  process_result_proto = untrusted_runner_pb2.ProcessResult(
      return_code=process_result.return_code,
      output=process_result.output,
      time_executed=process_result.time_executed,
      timed_out=process_result.timed_out)

  process_result_proto.command.extend(process_result.command)

  return process_result_proto


def run_and_wait(request, _):
  """Implementation of RunAndWait."""
  process_runner = new_process.ProcessRunner(request.executable_path,
                                             request.default_args)
  args = {}
  protobuf_utils.get_protobuf_field(args, request.popen_args, 'bufsize')
  protobuf_utils.get_protobuf_field(args, request.popen_args, 'executable')
  protobuf_utils.get_protobuf_field(args, request.popen_args, 'shell')
  protobuf_utils.get_protobuf_field(args, request.popen_args, 'cwd')

  if request.popen_args.env_is_set:
    args['env'] = request.popen_args.env
  else:
    args['env'] = None

  args['additional_args'] = request.additional_args
  protobuf_utils.get_protobuf_field(args, request, 'timeout')
  protobuf_utils.get_protobuf_field(args, request, 'terminate_before_kill')
  protobuf_utils.get_protobuf_field(args, request, 'terminate_wait_time')
  protobuf_utils.get_protobuf_field(args, request, 'input_data')
  protobuf_utils.get_protobuf_field(args, request, 'max_stdout_len')

  logs.log('Running command: %s' % process_runner.get_command())

  return untrusted_runner_pb2.RunAndWaitResponse(
      result=process_result_to_proto(process_runner.run_and_wait(**args)))


def run_process(request, _):
  """Implementation of RunProcess."""
  args = {}
  protobuf_utils.get_protobuf_field(args, request, 'cmdline')
  protobuf_utils.get_protobuf_field(args, request, 'current_working_directory')
  protobuf_utils.get_protobuf_field(args, request, 'timeout')
  protobuf_utils.get_protobuf_field(args, request, 'need_shell')

  if request.gestures:
    args['gestures'] = request.gestures

  if request.env_copy:
    args['env_copy'] = request.env_copy

  protobuf_utils.get_protobuf_field(args, request, 'testcase_run')
  protobuf_utils.get_protobuf_field(args, request, 'ignore_children')

  return_code, execution_time, output = process_handler.run_process(**args)
  response = untrusted_runner_pb2.RunProcessResponse(
      return_code=return_code, execution_time=execution_time, output=output)

  return response

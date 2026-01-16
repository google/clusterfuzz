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
"""Tasks RPC implementations."""

from google.protobuf import wrappers_pb2
from google.protobuf.any_pb2 import Any  # pylint: disable=no-name-in-module

from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks.utasks import fuzz_task
from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz.fuzz import engine

# pylint:disable=no-member


def _pack_values(values):
  """Pack protobuf values."""
  packed = {}
  if values is None:
    return packed

  for key, value in values.items():
    packed_value = Any()
    if isinstance(value, float):
      packed_value.Pack(wrappers_pb2.DoubleValue(value=value))
    elif isinstance(value, int):
      packed_value.Pack(wrappers_pb2.Int64Value(value=value))
    elif isinstance(value, str):
      packed_value.Pack(wrappers_pb2.StringValue(value=value))
    else:
      raise ValueError('Unknown stat type for ' + key)

    packed[key] = packed_value

  return packed


def engine_fuzz(request, _):
  """Run engine fuzzer."""
  engine_impl = engine.get(request.engine)
  result, fuzzer_metadata, strategies = fuzz_task.run_engine_fuzzer(
      engine_impl, request.target_name, request.sync_corpus_directory,
      request.testcase_directory)

  crashes = [
      untrusted_runner_pb2.EngineCrash(
          input_path=crash.input_path,
          stacktrace=crash.stacktrace,
          reproduce_args=crash.reproduce_args,
          crash_time=crash.crash_time) for crash in result.crashes
  ]

  packed_stats = _pack_values(result.stats)
  packed_strategies = _pack_values(strategies)

  return untrusted_runner_pb2.EngineFuzzResponse(
      logs=result.logs,
      command=result.command,
      crashes=crashes,
      stats=packed_stats,
      time_executed=result.time_executed,
      fuzzer_metadata=fuzzer_metadata,
      strategies=packed_strategies)


def engine_reproduce(request, _):
  """Run engine reproduce."""
  engine_impl = engine.get(request.engine)
  result = testcase_manager.engine_reproduce(engine_impl, request.target_name,
                                             request.testcase_path,
                                             request.arguments, request.timeout)
  return untrusted_runner_pb2.EngineReproduceResult(
      command=result.command,
      return_code=result.return_code,
      time_executed=result.time_executed,
      output=result.output)
